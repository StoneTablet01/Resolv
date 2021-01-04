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
 *
 * Jim Sutton made the code work on the ESP32 chip. Big Problem
 * was how IP addresses were stored
 * Nest step continued cleanup



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

void
check_entries(void)
{
  static const char *TAG = "chck_entries";
  ESP_LOGI(TAG, "...begin check entries" );

  register DNS_HDR *hdr;
  char *query, *nptr, *pHostname;
  static u16_t i;
  static u8_t n;
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
      p = pbuf_alloc(PBUF_TRANSPORT, sizeof(DNS_HDR)+MAX_NAME_LENGTH+5, PBUF_RAM);
      hdr = (DNS_HDR *)p->payload;
      memset(hdr, 0, sizeof(DNS_HDR));

      /* Fill in header information observing Big Endian / Little Endian considerations*/
      hdr->id = htons(i);
      hdr->flags1 = DNS_FLAG1_RD; //This is 8bits so no need to worry about htons
      hdr->numquestions = htons(1);
      query = (char *)hdr + sizeof(DNS_HDR);
      pHostname = pEntry->name;
      --pHostname;
      /* Convert hostname into suitable query format. */

      int qname_len = 0;
      do
      {
        ++pHostname;
        nptr = query;
        ++query;
        for(n = 0; *pHostname != '.' && *pHostname != 0; ++pHostname)
        {
          *query = *pHostname;
          ++query;
          ++n;
          qname_len ++;
        }
        *nptr = n;
        qname_len ++;
      }
      while(*pHostname != 0);

      static unsigned char endquery[] = {0,0,1,0,1};
      // write a trailing 0 on qname and write q_type and q_class
      // order is MSB, LSB (network)
      memcpy(query, endquery, 5);

      pbuf_realloc(p, qname_len + 12 + 5);

      udp_send(resolv_pcb, p);
      ESP_LOGI(TAG, "...query sent to DNS server" );
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
static void
resolv_recv(void *s, struct udp_pcb *pcb, struct pbuf *p,
                                  const ip_addr_t *addr, u16_t port)
{
  const char* TAG = "resolv_recv ";
  ESP_LOGI(TAG, "...resolv_recv function called");

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
  ESP_LOGI(TAG, "...Num questions %d, answers %d, authrr %d, extrarr %d",
    htons(hdr->numquestions),
    htons(hdr->numanswers),
    htons(hdr->numauthrr),
    htons(hdr->numextrarr));

  /* The ID in the DNS header should be our entry into the name table. */
  i = htons(hdr->id);
  pEntry = &dns_table[i];

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
      /* printf("Answer: type %x, class %x, ttl %x, length %x\n",
         htons(ans->type), htons(ans->class), (htons(ans->ttl[0])
           << 16) | htons(ans->ttl[1]), htons(ans->len)); */

      /* Check for IP address type and Internet class. Others are
       discarded.*/

      if((htons(ans->type) == 1) && (htons(ans->class) == 1) && (htons(ans->len) == 4) )
      { /* TODO: we should really check that this IP address is the one we want. */
        memcpy(&pEntry->ipaddr.addr, &ans->ipchars[0], 4);
        ESP_LOGI(TAG, "...Answer IP using memcpy             : "IPSTR"\n", IP2STR(&pEntry->ipaddr));

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

void resolv_query(char *name, user_cb_fn jps_cb_ptr){

static const char *TAG = "resolv_query";
static u8_t i;
static u8_t lseqi;
register DNS_TABLE_ENTRY *pEntry;

ESP_LOGI(TAG, "...entered resolv query. The name is %s", name );

lseqi = 0;

ESP_LOGI(TAG, "...build entry for             : %s", name );

//JPS Code to enter info into the table
for (i = 0; i < LWIP_RESOLV_ENTRIES; ++i){
  pEntry = &dns_table[i];
  lseqi = i;
  if (pEntry->state == STATE_UNUSED){
    strcpy(pEntry->name, name);
    pEntry->found = jps_cb_ptr;
    pEntry->state = STATE_NEW;
    pEntry->seqno = lseqi;
    break;
  }
}
pEntry = &dns_table[lseqi];

ESP_LOGI(TAG, "...Created record at seq no    : %d", lseqi );
ESP_LOGI(TAG, "...Record name is              : %s", pEntry->name );
ESP_LOGI(TAG, "...Record state is             : %d", (int) pEntry->state );
//ESP_LOGI(TAG, "...Record callback pointer is:         %p", pEntry->found );
ESP_LOGI(TAG, "...Record IP address           : " IPSTR, IP2STR(&pEntry->ipaddr));

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
resolv_init(ip_addr_t *dnsserver_ip_addr_ptr) {
  static const char *TAG = "resolv init ";
  ESP_LOGI(TAG, "...dnsserver is                : " IPSTR, IP2STR(&dnsserver_ip_addr_ptr->u_addr.ip4));
  static u8_t i;

  serverIP.addr = dnsserver_ip_addr_ptr->u_addr.ip4.addr;

  for(i=0; i<LWIP_RESOLV_ENTRIES; ++i){
    dns_table[i].state = STATE_UNUSED;
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

    ESP_LOGI(TAG, "...udp connect failed to       : " IPSTR, IP2STR(&dnsserver_ip_addr_ptr->u_addr.ip4));
  }
  else{
    ESP_LOGI(TAG, "...udp connected to            : " IPSTR, IP2STR(&dnsserver_ip_addr_ptr->u_addr.ip4));
  }

  typedef void(* udp_recv_fn) (void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
  udp_recv_fn udp_r = &resolv_recv;
  udp_recv (resolv_pcb, udp_r, NULL);

  initFlag = 1;
  return ERR_OK;
}
