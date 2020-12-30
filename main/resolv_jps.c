/*

 * DNS host name to IP address resolver.
 * This file implements a DNS host name to IP address resolver.

 * Port to lwIP from uIP
 * by Jim Pettinato April 2007

 * uIP version Copyright (c) 2002-2003, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * RESOLV.C
 *
 * The lwIP DNS resolver functions are used to lookup a host name and
 * map it to a numerical IP address. It maintains a list of resolved
 * hostnames that can be queried with the resolv_lookup() function.
 * New hostnames can be resolved using the resolv_query() function.
 *
 * The lwIP version of the resolver also adds a non-blocking version of
 * gethostbyname() that will work with a raw API application. This function
 * checks for an IP address string first and converts it if it is valid.
 * gethostbyname() then does a resolv_lookup() to see if the name is
 * already in the table. If so, the IP is returned. If not, a query is
 * issued and the function returns with a QUERY_QUEUED status. The app
 * using the resolver must then go into a waiting state.
 *
 * Once a hostname has been resolved (or found to be non-existent),
 * the resolver code calls a specified callback function (which
 * must be implemented by the module that uses the resolver).

 */

#include <string.h>
#include <ctype.h>
#include "lwip/stats.h"
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"

// JPS addr include
#include "lwip/ip4_addr.h"

#include "lwip/netif.h"
#include "lwip/inet.h"
#include "netif/etharp.h"
#include "lwip/sys.h"
#include "lwip/opt.h"

#include "resolv_jps.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"

//added to get error checks
#include "esp_netif.h"
#include "esp_netif_ppp.h"

/* The maximum length of a host name supported in the name table. */
#define MAX_NAME_LENGTH 32
/* The maximum number of retries when asking for a name. */
#define MAX_RETRIES 8

/* The maximum number of table entries to maintain locally */
#ifndef LWIP_RESOLV_ENTRIES
#define LWIP_RESOLV_ENTRIES 4
#endif

#ifndef DNS_SERVER_PORT
#define DNS_SERVER_PORT 53
#endif

#if _BYTE_ORDER == _LITTLE_ENDIAN
#define JPS_FLAG 99
#endif

#if _BYTE_ORDER == _BIG_ENDIAN
#define JPS_FLAG 69
#endif

/* The DNS message header */
typedef struct s_dns_hdr {
  u16_t id;
  u8_t flags1, flags2;
#define DNS_FLAG1_RESPONSE        0x80
#define DNS_FLAG1_OPCODE_STATUS   0x10
#define DNS_FLAG1_OPCODE_INVERSE  0x08
#define DNS_FLAG1_OPCODE_STANDARD 0x00
#define DNS_FLAG1_AUTHORATIVE     0x04
#define DNS_FLAG1_TRUNC           0x02
#define DNS_FLAG1_RD              0x01
#define DNS_FLAG2_RA              0x80
#define DNS_FLAG2_ERR_MASK        0x0f
#define DNS_FLAG2_ERR_NONE        0x00
#define DNS_FLAG2_ERR_NAME        0x03
  u16_t numquestions;
  u16_t numanswers;
  u16_t numauthrr;
  u16_t numextrarr;
} DNS_HDR;

typedef struct a_real_hdr {
  u16_t id;
  //u8_t flags1, flags2;
  int qr_flag;
  int rd_flag;
  int ra_flag;
  int error_code;
  int error_name;
#define DNS_QR_MASK               0x80
#define DNS_RD_MASK               0x01
#define DNS_RA_MASK               0x80
#define DNS_ERR_MASK              0x0F
#define DNS_ERR_NAME_MASK         0x03
  u16_t numquestions; //QDCOUNT
  u16_t numanswers;   //ANCOUNT
  u16_t numauthrr;    //NSCOUNT
  u16_t numextrarr;   //ARCOUNT
} R_HDR;

/* The DNS answer message structure */
typedef struct r_dns_answer {
  /* DNS answer record starts with either a domain name or a pointer
     to a name already present somewhere in the packet. */
  char name_requested [MAX_NAME_LENGTH];
  u16_t q_type;
  u16_t q_class;
  u16_t type;
  u16_t class;
  u8_t ans_has_pointer;
  u8_t ans_pointer;
  u32_t validity_time;
  u16_t len;
  struct ip4_addr ipaddr;
} R_DNS_ANS;

/* The DNS answer message structure */
typedef struct s_dns_answer {
  /* DNS answer record starts with either a domain name or a pointer
     to a name already present somewhere in the packet. */
  u16_t type;
  u16_t class;
  u16_t ttl[2];
  u16_t len;
  //struct ip_addr ipaddr;
  char ipchars[4];
} DNS_ANSWER;

typedef struct namemap {
#define STATE_UNUSED 0
#define STATE_NEW    1
#define STATE_ASKING 2
#define STATE_DONE   3
#define STATE_ERROR  4
  u8_t state;
  u8_t tmr;
  u8_t retries;
  u8_t seqno;
  u8_t err;
  char name[MAX_NAME_LENGTH];
  struct ip4_addr ipaddr;
  void (* found)(char *name, struct ip4_addr *ipaddr); /* pointer to callback on DNS query done */
}DNS_TABLE_ENTRY;

static DNS_TABLE_ENTRY dns_table[LWIP_RESOLV_ENTRIES];

// JPS was here to modify initialization of seqno
static u8_t seqno = 0;
// this was original Line
//static u8_t seqno;

static struct udp_pcb *resolv_pcb = NULL; /* UDP connection to DNS server */
static struct ip4_addr serverIP; //the adress of the DNS server to use
static u8_t initFlag; // set to 1 if initialized

//JPS Test Line follows
struct ip_addr ipaddr1;

/*---------------------------------------------------------------------------
 * parse_name() - walk through a compact encoded DNS name and return the end
 * of the name.
 *---------------------------------------------------------------------------*/
static unsigned char *
parse_name(unsigned char *query)
{
  unsigned char n;

  do
  {
    n = *query++;

    while(n > 0)
    {
      /*      printf("%c", *query);*/
      ++query;
      --n;
    };
  } while(*query != 0);

  return query + 1;
}

/*---------------------------------------------------------------------------
 * parse_qname_length() - Walk through the encoded answer buffer and return
 * the length of the encoded name in chars.
 *---------------------------------------------------------------------------*/
int
parse_qname_length(char *jps_char_ptr){
  int subname_len;
  int encoded_name_len =0;

  while(*jps_char_ptr != 0 && encoded_name_len < MAX_NAME_LENGTH - 1){
    subname_len = (int) *jps_char_ptr; //first item is the length of the first subname
    encoded_name_len += (subname_len + 1);
    jps_char_ptr+= (subname_len + 1);
    }
  encoded_name_len++;
  return encoded_name_len;
}

/*---------------------------------------------------------------------------
 * parse_qname_name() - Walk through the encoded answer buffer and return
 * the name requested as a full domain name with "." separating the Subnames
 * and a trailing 0x00 to mark it as a string
 *---------------------------------------------------------------------------*/
int
parse_qname_name (char *jps_char_ptr, char *name_ptr){
  int subname_len;
  int encoded_name_len = 0;

  while(*jps_char_ptr != 0 && encoded_name_len < MAX_NAME_LENGTH - 1){
    subname_len = (int) *jps_char_ptr; //first item is the length of the first subname
    jps_char_ptr++;

    memcpy(name_ptr, jps_char_ptr, subname_len);
    jps_char_ptr += subname_len;
    name_ptr += subname_len;
    *name_ptr = 0x2e; //Add a decimal point between names
    name_ptr ++;
    encoded_name_len += (subname_len + 1);
    }

  if (encoded_name_len != 0){
    name_ptr--;
    *name_ptr = 0x00; // end with trailing 0 not a decial pt
  }
  encoded_name_len++;
  return encoded_name_len;
}


/* When receiving serial transmission of 16 bit information as
two 8 bit words from a Big Endian source, the order of bytes is
word 1 MS byte - word 1 LS byte
This routine stores these 2 8 bit bytes in a 16 bit word observing significance
 */
u16_t
two_char_to_u16_t(char *char_ptr){
  return (*(char_ptr)<<8) | *(char_ptr+1);
}

/* When receiving serial transmission of 32 bit information as
two 16 bit words from a Big Endian source, the order of bytes is
word 1 MS byte - word 1 LS byte - word 2 MS byte - word 2 LS byte 1
This routine stores these 4 8 bit bytes in a 32 bit word observing significance
 */
u32_t
four_char_to_u32_t(char *char_ptr){
  return (*(char_ptr)<<24) |
    (*(char_ptr+1)<<16) |
    (*(char_ptr+2)<<8) |
    *(char_ptr+3);
}

void
check_entries(void)
{
  static const char *TAG = "check_entries";
  ESP_LOGI(TAG, "...entered check entries" );

  register DNS_HDR *hdr;
  char *pHostname;
  //char *query, *pHostname; JPS removing query
  static u8_t i;
  //static u8_t n;
  register DNS_TABLE_ENTRY *pEntry;
  struct pbuf *p;
  for(i = 0; i < LWIP_RESOLV_ENTRIES; ++i)
  {
    pEntry = &dns_table[i];
    if(pEntry->state == STATE_NEW || pEntry->state == STATE_ASKING)
    {
      if(pEntry->state == STATE_ASKING)
      {
        if(--pEntry->tmr == 0)
        {
          if(++pEntry->retries == MAX_RETRIES)
          {
            pEntry->state = STATE_ERROR;
            if (pEntry->found) /* call specified callback function if provided */
              (*pEntry->found)(pEntry->name, NULL);
            continue;
          }
          pEntry->tmr = pEntry->retries;
        }
        else
        {
          /*  printf("Timer %d\n", pEntry->tmr);*/
          /* Its timer has not run out, so we move on to next
          entry. */
          continue;
        }
      }
      else
      {
        pEntry->state = STATE_ASKING;
        pEntry->tmr = 1;
        pEntry->retries = 0;
      }
      /* if here, we have either a new query or a retry on a previous query to process */
      //ESP_LOGI(TAG, "...new query to process");
      p = pbuf_alloc(PBUF_TRANSPORT, sizeof(DNS_HDR)+MAX_NAME_LENGTH+5, PBUF_RAM);
      //ESP_LOGI(TAG, "...pbuf pointer points to: %p", p);
      hdr = (DNS_HDR *)p->payload;
      //ESP_LOGI(TAG, "...hdr pointer points to: %p", hdr);
      void * jps_payload_ptr;
      jps_payload_ptr = p->payload;
      //ESP_LOGI(TAG, "...jps_payload_ptr points to: %p", jps_payload_ptr);

      //ESP_LOGI(TAG, "...hdr pointer points to : %p", hdr);
      //ESP_LOGI(TAG, "...DNS HDR size is       : %d", sizeof(DNS_HDR));
      memset(hdr, 0, sizeof(DNS_HDR));

      hdr->id = i;
      hdr->flags1 = DNS_FLAG1_RD;
      hdr->numquestions = 1;

      unsigned char jps_header[12];
      jps_header[0] = 0x00; /* ID of the request MSB*/
      jps_header[1] = 0x00; /* ID of the request LSB*/
      jps_header[2] = 0x01; /* Control word MSB */
      jps_header[3] = 0x00; /* Control word LSB */
      jps_header[4] = 0x00; /* QD Count MSB */
      jps_header[5] = 0x01; /* QD Count LSB */
      jps_header[6] = 0x00; /* ANCOUNT MSB*/
      jps_header[7] = 0x00; /* ANCOUNT LSB*/
      jps_header[8] = 0x00; /* NSCOUNT MSB */
      jps_header[9] = 0x00; /* NSCOUNT LSB */
      jps_header[10] = 0x00; /* ARCOUNT MSB */
      jps_header[11] = 0x00; /* ARCOUNT LSB */


      //unsigned char * jps_hdr_ptr;
      //jps_hdr_ptr = &jps_header[0];
      /*
      for (i = 0; i < sizeof(DNS_HDR); ++i){
        ESP_LOGI(TAG, "...JPS_Header item: %X %p ", *jps_hdr_ptr , jps_hdr_ptr);
        jps_hdr_ptr++;
      }  */

      unsigned char jps_question[MAX_NAME_LENGTH];
      unsigned char *jps_question_ptr;
      jps_question_ptr = &jps_question[0];

      memset(jps_question_ptr, 0, MAX_NAME_LENGTH);

      int label_len = 0;
      int loop_count = 0;

      pHostname = pEntry->name;
      unsigned char *jps_label_len_ptr, *jps_label_ptr;
      jps_label_len_ptr = jps_question_ptr;
      jps_label_ptr = jps_label_len_ptr + 1;

      while (*pHostname !=0 && loop_count < MAX_NAME_LENGTH){
        loop_count++;
        if (*pHostname != '.'){
          label_len++;
          *jps_label_len_ptr = label_len;
          *jps_label_ptr = *pHostname;
          jps_label_ptr++;
          pHostname++;
        }
        else{
          jps_label_len_ptr = jps_label_ptr;
          label_len = 0;
          *jps_label_len_ptr = label_len;
          jps_label_ptr++;
          pHostname++;
        }
      }
      // add the endqquerry instructions for type and class
      static unsigned char endquery[] = {0,0,1,0,1};
      memcpy(jps_label_ptr, endquery, 5);

      // loop_count has the total number of characters in the query
      loop_count = loop_count + 6;
      /*
      ESP_LOGI(TAG, "...no of Char in JPS Question Array: %d", loop_count);

      for (i=0; i < loop_count; ++i){
        if (*jps_question_ptr > 10){
          ESP_LOGI(TAG, "...Char in JPS Question Array: %c", *jps_question_ptr);
        }
        else{
          ESP_LOGI(TAG, "...Char in JPS Question Array: %X", *jps_question_ptr);
        }
        jps_question_ptr++;
      } */

      // now copy the header and query into the udp transports payload

      memcpy(jps_payload_ptr, jps_header, 12);

      jps_payload_ptr = jps_payload_ptr + 12;
      memcpy(jps_payload_ptr, jps_question, loop_count);

      //print our payload
      //jps_payload_ptr = p->payload;
      //char * jps_char_ptr;
      //jps_char_ptr = (char *) p->payload;

      /*
      for (i=0; i < loop_count + 12; ++i){
        if (*jps_char_ptr > 10){
          ESP_LOGI(TAG, "......Char in payload Array: %c", *jps_char_ptr);
        }
        else{
          ESP_LOGI(TAG, "......Hex  in payload Array: %X", *jps_char_ptr);
        }
        jps_char_ptr++;
      }
      */

      pbuf_realloc(p, loop_count + 12);

      udp_send(resolv_pcb, p);
      pbuf_free(p);
      break;
    }
  }
}

/*---------------------------------------------------------------------------*
 *
 * Callback for DNS responses
 *
 *---------------------------------------------------------------------------*/

/*
Lwip 2.0 documentation specifies the signature as
void udp_recv	(	struct udp_pcb * 	pcb,
udp_recv_fn 	recv,
void * 	recv_arg
)

further, udp_recv_fn should have the signature
typedef void(* udp_recv_fn) (void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)

*/

static void
resolv_recv(void *s, struct udp_pcb *pcb, struct pbuf *p,
                                  const ip_addr_t *addr, u16_t port)
{
  const char* TAG = "resolv_recv";
  ESP_LOGI(TAG, "... resolv_recv function called");


  char * jps_char_ptr;
  jps_char_ptr = (char *) p->payload;

  /*JPS check received buffer by printing out

  for (int i=0; i < 48; ++i){
    if ((*jps_char_ptr > 64 && *jps_char_ptr <91) ||
      (*jps_char_ptr > 96 && *jps_char_ptr <123)){
      ESP_LOGI(TAG, "......Letter in received buffer: %c", *jps_char_ptr);
    }
    else{
      ESP_LOGI(TAG, "......Hex in received buffer   : %X", *jps_char_ptr);
    }
    jps_char_ptr++;
  } // check printer buffer end */

  // When the DNS server sends a buffer, it contains a header and an answer
  // create structs to store this information
  R_HDR h;
  R_DNS_ANS r_ans;


  // Now Process the header section
  jps_char_ptr = (char *) p->payload; // points to start of header

  h.id = two_char_to_u16_t(jps_char_ptr); // ID is the first two x 8-bit bytes of buffer
  jps_char_ptr += 2; //2 characters processed. Point to next next field

  //h.flags1 = ; // Flags 1 contains flags QR, Opcode, AA, TC, and RD
  h.qr_flag = (int)((*jps_char_ptr & DNS_QR_MASK)>>7);
  h.rd_flag = (int)(*jps_char_ptr & DNS_RD_MASK);
  jps_char_ptr++; // 1 character processed. Point to next field

  //h.flags2 = *jps_char_ptr; // Flags 2 contains flags RA, Z, RCODE
  h.ra_flag = (int)((*jps_char_ptr & DNS_RA_MASK)>>7);
  h.error_code = (int)(*jps_char_ptr & DNS_ERR_MASK);
  h.error_name = (int)((*jps_char_ptr & DNS_ERR_NAME_MASK)>>1);
  jps_char_ptr++;

  h.numquestions = two_char_to_u16_t(jps_char_ptr); // called QDCOUNT in RFC1035
  jps_char_ptr += 2;

  h.numanswers = two_char_to_u16_t(jps_char_ptr); // called ANCOUNT in RFC1035
  jps_char_ptr += 2;

  h.numauthrr = two_char_to_u16_t(jps_char_ptr); // called NSCOUNT in RFC1035
  jps_char_ptr += 2;

  h.numextrarr = two_char_to_u16_t(jps_char_ptr); // called ARCOUNT in RFC1035
  jps_char_ptr += 2;

  ESP_LOGI(TAG, "\n");
  ESP_LOGI(TAG, ".DNS Answer header processed");
  ESP_LOGI(TAG, "...ID is                       : %d", h.id);
  ESP_LOGI(TAG, "...QR (0= querry, 1= answer)   : %d", h.qr_flag);
  ESP_LOGI(TAG, "...RD (1= recursion requested) : %d", h.rd_flag);
  ESP_LOGI(TAG, "...RA (1= recursion available) : %d", h.ra_flag);
  ESP_LOGI(TAG, "...Error Code (0= No errors)   : %d", h.error_code);
  ESP_LOGI(TAG, "...No. of questions            : %d", h.numquestions);
  ESP_LOGI(TAG, "...No. of answers              : %d", h.numanswers);
  ESP_LOGI(TAG, "...No. of name server records  : %d", h.numauthrr);
  ESP_LOGI(TAG, "...No. of additional records   : %d", h.numextrarr);


  // Now parse the DNS Questions section of the reply. This section
  // mirrors back the question the DNS Server was asked. The section consists of three fields
  // QNAME, QTYPE, QCLASS

  // Parse QNAME
  int encoded_name_len;
  encoded_name_len = parse_qname_name(jps_char_ptr, &r_ans.name_requested[0]);
  jps_char_ptr += encoded_name_len;

  // Parse QTYPE Requested Answer type. This a two octet - 16 bit field which specifies
  // the type of the query.  0x0001 represents "A" records (host addresses).
  r_ans.q_type = two_char_to_u16_t(jps_char_ptr);
  jps_char_ptr += 2;

  // Parse QCLASS requested Class - This is a two octet - 16 bits field which specifies
  // the class of the data in the RDATA field. Class 01 is IN for internet addr
  r_ans.q_class = two_char_to_u16_t(jps_char_ptr);
  jps_char_ptr += 2;

  //DNS Questions parse completed
  ESP_LOGI(TAG, "\n");
  ESP_LOGI(TAG, ".DNS Questions Asked section processed");
  ESP_LOGI(TAG, "...Name Requested length is    : %d", encoded_name_len);
  ESP_LOGI(TAG, "...Full Name Requested is      : %s", r_ans.name_requested);
  ESP_LOGI(TAG, "...Type Requested is           : %d", r_ans.q_type);
  ESP_LOGI(TAG, "...Class Requested is          : %d", r_ans.q_class);

  //DNS Question Section is now completed

  /*Now parse DNS Answers. The DNS Answers section has 6 fields. The fields are
  NAME The domain name that was queried, in the same format as the QNAME in the questions.
  TYPE Two octets specify the meaning of the data in the RDATA field. Type 0x0001 is an (A record) and type 0x0005 is (CNAME).
  CLASS Two octets specify the class of the data in the RDATA field. IN is 0x0001
  TTL Four octets specify the number of seconds the results can be cached.
  RDLENGTH The length of the RDATA field.
  RDATA The data of the response. The format is dependent on the TYPE field: if TYPE 1,
  for A records, then this is the IP address (4 octets).*/

  /* Start with the name field. The name field utilizes a compression scheme which can
  eliminate the repetition of domain names in the NAME, QNAME, and RDATA fields.

  Specifically, The compression scheme allows a domain name in a message to be represented as either:
    a sequence of labels ending in a zero octet
    a pointer (offest from the start of the message buffer in byte )
    a sequence of labels ending with a pointer

  Which compression method is used can be determined by the starting byte. Labels are limited
  to 63 bytes. This means that if the two MSB's are set to 1 at the start of this field
  the next 14 bits that follow are the offset. */

  //loop through the number of answers

  int num_answers = h.numanswers;
  while (num_answers > 0){
    /* check if answer has a name pointer */
    ESP_LOGI(TAG, "... Checking for name ptr: %X", *jps_char_ptr);
    if (*jps_char_ptr >= 0xC0){
      ESP_LOGI(TAG, "... Name is a pointer: %X", *jps_char_ptr);

    // record whether there is a pointer to address.
      r_ans.ans_has_pointer = 0x0001;
      ESP_LOGI(TAG, "... ans_has_ptr is: %d", r_ans.ans_has_pointer);

      r_ans.ans_pointer = (u16_t) *jps_char_ptr;

      jps_char_ptr += 2;
    }
    else{
      // read name as before, starting with length
    }

    // Parse Answer type -  two octet code (16 bit field) which specifies
    // the type of the query.  0x0001 represents "A" records (host addresses).
    // 0x000f for mail server (MX) records and 0x0002 for name servers (NS) records.
    r_ans.type = two_char_to_u16_t(jps_char_ptr);
    ESP_LOGI(TAG, "... r_ans.type is: %d", r_ans.type);
    jps_char_ptr += 2;

    // Parse Answer Class - Two octets (16 bits) which specify the class of data
    // in the RDATA field. Class 0x0001 is IN internet.
    r_ans.class = two_char_to_u16_t(jps_char_ptr);
    ESP_LOGI(TAG, "... r_ans.class is: %d", r_ans.class);
    jps_char_ptr += 2;

    // Parse TTL. TTL is the number of seconds the results can be considered valid.
    // total of 32 bits. These are stored in 4 consequtive 8 bit bytes in the buffer
    r_ans.validity_time = four_char_to_u32_t(jps_char_ptr);
    jps_char_ptr += 4;

    // Parse Len. Len is the length (in 8 bt chars) of RDATA. If an IP4_ADDR
    // is returned, the length is 4
    r_ans.len = two_char_to_u16_t(jps_char_ptr);
    jps_char_ptr += 2;

    // Parse ipaddr into struct. Note .addr is Big Endian by design so
    // no need to provide adjustment for Little Endian compilers as was done earlier
    memcpy(&r_ans.ipaddr.addr, jps_char_ptr, 4);

    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, ".DNS answer data processed");
    ESP_LOGI(TAG, "...DNS Name Requested          : %s", r_ans.name_requested);
    ESP_LOGI(TAG, "...Answer Type                 : %d", r_ans.type);
    ESP_LOGI(TAG, "...Answer Class                : %d", r_ans.class);
    ESP_LOGI(TAG, "...Validity Time 1             : %d", r_ans.validity_time);
    ESP_LOGI(TAG, "...Answer RD  length           : %d", r_ans.len);
    ESP_LOGI(TAG, "...Answer IP                   : "IPSTR"\n", IP2STR(&r_ans.ipaddr));
  num_answers --;
  }

  ESP_LOGI(TAG, ".struct approach to processing \n");

  char *pHostname;
  DNS_ANSWER *ans;
  DNS_HDR *hdr;
  static u8_t nanswers;
  static u8_t i;
  register DNS_TABLE_ENTRY *pEntry;

  hdr = (DNS_HDR *)p->payload;
  ESP_LOGI(TAG, "...ID %d", htons(hdr->id));
  ESP_LOGI(TAG, "...Query %d", hdr->flags1 & DNS_FLAG1_RESPONSE);
  ESP_LOGI(TAG, "...Error %d", hdr->flags2 & DNS_FLAG2_ERR_MASK);
  ESP_LOGI(TAG, "...Num questions %d, answers %d, authrr %d, extrarr %d\n",
    htons(hdr->numquestions),
    htons(hdr->numanswers),
    htons(hdr->numauthrr),
    htons(hdr->numextrarr));

  //
  /* The ID in the DNS header should be our entry into the name table. */
  i = htons(hdr->id);
  pEntry = &dns_table[i];
  ESP_LOGI(TAG, "...dns table entry id number is %d and the entry state is %d", i, pEntry->state);
  if( (i < LWIP_RESOLV_ENTRIES) && (pEntry->state == STATE_ASKING) )
  {
    /* This entry is now finished. */
    pEntry->state = STATE_DONE;
    pEntry->err = hdr->flags2 & DNS_FLAG2_ERR_MASK;

    /* Check for error. If so, call callback to inform. */
    if(pEntry->err != 0)
    {
      pEntry->state = STATE_ERROR;
      if (pEntry->found) /* call specified callback function if provided */
        (*pEntry->found)(pEntry->name, NULL);
      return;
    }

    /* We only care about the question(s) and the answers. The authrr
       and the extrarr are simply discarded. */

    nanswers = htons(hdr->numanswers);

    /* Skip the name in the question. XXX: This should really be
       checked agains the name in the question, to be sure that they
       match. */
    pHostname = (char *) parse_name((unsigned char *)p->payload + 12) + 4;

    while(nanswers > 0)
    {
      /* The first byte in the answer resource record determines if it
         is a compressed record or a normal one. */
      if(*pHostname & 0xc0)
      { /* Compressed name. */
        pHostname +=2;
        /*	printf("Compressed anwser\n");*/
      }
      else
      { /* Not compressed name. */
        pHostname = (char *) parse_name((unsigned char *)pHostname);
      }

      ans = (DNS_ANSWER *)pHostname;
      /*printf("Answer: type %x, class %x, ttl %x, length %x\n",
         htons(ans->type), htons(ans->class), (htons(ans->ttl[0])
           << 16) | htons(ans->ttl[1]), htons(ans->len));*/

      /* Check for IP address type and Internet class. Others are
       discarded.*/

      if((htons(ans->type) == 1) && (htons(ans->class) == 1) && (htons(ans->len) == 4) )
      { /* TODO: we should really check that this IP address is the one we want. */

        memcpy(&r_ans.ipaddr.addr, &ans->ipchars[0], 4);
        //r_ans.ipaddr.addr = ans->ipaddr;
        ESP_LOGI(TAG, "...Answer IP using memcpy             : "IPSTR"\n", IP2STR(&r_ans.ipaddr));

        // call specified callback function if provided
        if (pEntry->found)
          (*pEntry->found)(pEntry->name, &pEntry->ipaddr);
        return;
      }
      else
      {
        pHostname = pHostname + 10 + htons(ans->len);
      }
      --nanswers;
    }
  }
}
// Here is the full resolv_query signature I will ultimately have
// this was from strophe resolver. SRV request is 33
//    len = res_query(fulldomain, MESSAGE_C_IN, MESSAGE_T_SRV, buf,
//                    RESOLVER_BUF_MAX);

  void resolv_query(char *name, user_cb_fn jps_cb_ptr){
// Testing a function that makes a callback to the function
// pointed to by jps_cb_ptr

  static const char *TAG = "resolv_query";
  ESP_LOGI(TAG, "...entered resolv query. The name is %s", name );
  struct ip4_addr jps_addr;


// test the callback function passed as an argument
  (*jps_cb_ptr) (name, &jps_addr);
//  return;

// now build the table as envisioned by Adam Dunkels

static u8_t i;
static u8_t lseqi;
register DNS_TABLE_ENTRY *pEntry;

lseqi = 0;

ESP_LOGI(TAG, "...ready to build table The name is %s", name );

//JPS Code to enter info into the table
for (i = 0; i < LWIP_RESOLV_ENTRIES; ++i){
  pEntry = &dns_table[i];
  lseqi = i;
  if (pEntry->state == STATE_UNUSED){
    strcpy(pEntry->name, name);
    pEntry->found = jps_cb_ptr;
    pEntry->state = STATE_NEW;
    pEntry->seqno = lseqi;
    // enter dummy ip address for Testing
    IP4_ADDR(&jps_addr, 192, 168, 1, 10);
    //ESP_LOGI(TAG, "...dummy IP address: " IPSTR, IP2STR(&jps_addr));
    //pEntry->ipaddr = jps_addr;
    break;
  }
}
pEntry = &dns_table[lseqi];
ESP_LOGI(TAG, "...Created record at sequence number:  %d", lseqi );
ESP_LOGI(TAG, "...Record name is:                     %s", pEntry->name );
ESP_LOGI(TAG, "...Record state is:                    %d", (int) pEntry->state );
ESP_LOGI(TAG, "...Record callback pointer is:         %p", pEntry->found );
ESP_LOGI(TAG, "...Record IP address: " IPSTR, IP2STR(&pEntry->ipaddr));


seqno = lseqi + 1;

}

/*---------------------------------------------------------------------------*
 * Look up a hostname in the array of known hostnames.
 *
 * \note This function only looks in the internal array of known
 * hostnames, it does not send out a query for the hostname if none
 * was found. The function resolv_query() can be used to send a query
 * for a hostname.
 *
 * return A pointer to a 4-byte representation of the hostname's IP
 * address, or NULL if the hostname was not found in the array of
 * hostnames.
 *---------------------------------------------------------------------------*/
u32_t
resolv_lookup(char *name)
{
  static u8_t i;
  DNS_TABLE_ENTRY *pEntry;

  /* Walk through name list, return entry if found. If not, return NULL. */
  for(i=0; i<LWIP_RESOLV_ENTRIES; ++i)
  {
    pEntry = &dns_table[i];
    if ( (pEntry->state==STATE_DONE) && (strcmp(name, pEntry->name)==0) )
      return pEntry->ipaddr.addr;
  }
  return 0;
}


/*---------------------------------------------------------------------------*
 * Obtain the currently configured DNS server.
 * return unsigned long encoding of the IP address of
 * the currently configured DNS server or NULL if no DNS server has
 * been configured.
 *---------------------------------------------------------------------------*/
u32_t
resolv_getserver(void)
{
  if(resolv_pcb == NULL)
    return 0;
  return serverIP.addr;
}

err_t
resolv_init(ip_addr_t *dnsserver_ip_addr_ptr)
{
  // dnsserver_ip_addr is of type ip_addr_t which supports both IPv4 and IPPROTO_IPV6
  //
  static const char *TAG = "resolv init";
  ESP_LOGI(TAG, "...dnsserver passed to init is: " IPSTR, IP2STR(&dnsserver_ip_addr_ptr->u_addr.ip4));

  static u8_t i;

  serverIP.addr = dnsserver_ip_addr_ptr->u_addr.ip4.addr;

  for(i=0; i<LWIP_RESOLV_ENTRIES; ++i){
    //dns_table[i].state = STATE_DONE;
    dns_table[i].state = STATE_UNUSED;

    // jps added next Line
    dns_table[i].seqno = 0;
  }

  if(resolv_pcb != NULL){
    ESP_LOGI(TAG, "...resolv_pcb exists...delete it");
    udp_remove(resolv_pcb);
  }
  resolv_pcb = udp_new();
  udp_bind(resolv_pcb, IP_ADDR_ANY, 0);

  err_t ret;
  ret = udp_connect(resolv_pcb, dnsserver_ip_addr_ptr, DNS_SERVER_PORT);
  if (ret < 0 ){
    ESP_LOGI(TAG, "...udp connect failed resolver is: " IPSTR, IP2STR(&dnsserver_ip_addr_ptr->u_addr.ip4));
  }
  else{
    ESP_LOGI(TAG, "...udp connect succeeded resolver is: " IPSTR, IP2STR(&dnsserver_ip_addr_ptr->u_addr.ip4));
  }
  /*

  Now ready to call the udp_recv function which registers the function
  that should be called when packets are received. The following Information
  was gathered as I wanted to get the signatures correct.

  The original call to lwip used was:

      udp_recv(resolv_pcb, resolv_recv, NULL);

  But the Lwip 2.0 documentation specifies the signature of udp_recv as
  void udp_recv	(	struct udp_pcb * 	pcb,
                      udp_recv_fn 	recv,
                      void * 	recv_arg )

  Therefore I created a function pointer type for use in the call badk as follows:
  */

  typedef void(* udp_recv_fn) (void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
  udp_recv_fn udp_r = &resolv_recv;

  udp_recv (resolv_pcb, udp_r, NULL);

  initFlag = 1;


  return ERR_OK;
}
