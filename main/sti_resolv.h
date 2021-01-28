/** @copyright
 * lwip DNS resolver header file.

 * Author: Jim Pettinato
 *   April 2007

 * ported from uIP resolv.c Copyright (c) 2002-2003, Adam Dunkels.
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
 */
#ifndef STI_RESOLV_H
#define STI_RESOLV_H

/* enumerated list of possible result values returned by gethostname() */
typedef enum e_resolv_result {
  RESOLV_QUERY_INVALID,
  RESOLV_QUERY_QUEUED,
  RESOLV_COMPLETE
} RESOLV_RESULT;

//typedef void(* user_cb_fn) (int i);
typedef void(* user_cb_fn) (char *name, struct ip4_addr *addr);
/* Functions. */

/** @brief Initialize this resolver
  *
  * Create a UDP connection with the DNS server so that DNS record queries can be made
  *
  * @note This function uses lwip directly. Other IP implementations will need to
  * provide there own IP stack implementations
  *
  * @param dnsserver_ip_addr_ptr  the IP address of the DNS Server.
  * @returns ERR_OK: UDP connection succeeded LWIP error code
  */
err_t
resolv_init(ip_addr_t *dnsserver_ip_addr_ptr); /* working to pass ip_addr_t*/


/** @brief Enter a request to get information for a hostname into the dns table
  *
  * @param name pointer to a character array containing the hostname
  * @param sti_cb_ptr optional user secified callback function when an IP address is received
  * @returns void
  **/
void resolv_query(char *name, user_cb_fn sti_cb_ptr);

/** @brief a full function resolv query
  * this function allows small computers to get a return
  * buffer from the dns server
  */
int
res_query_jps(const char *dname, int class, int type, unsigned char *answer, int anslen);


/** @brief Look up a hostname in the array of known hostnames
  *
  * Iterate through the table of DNS entries. If there are new entries, create and
  * send a query to the DNS Server to ask for "A" records. The structure of the
  * request is defined by RFC1035
  *
  * @note This function only looks in the internal array of known
  * hostnames, it does not send out a query for the hostname if none
  * was found. The function resolv_query() can be used to send a query
  * for a hostname.
  *
  * @param names pointer to a character array containing the full DNS name
  * @returns a unsigned long encoding of the IP address received from the DNS
  * Server "A" record for name or NULL if the hostname was not found in the array of
  * hostnames.
  */
u32_t
resolv_lookup(char *name);


/** @brief Obtain the currently configured DNS server
  *
  * @returns unsigned long encoding of the IP address of
  * the currently configured DNS server or NULL if no DNS server has
  * been configured.
  **/
u32_t
resolv_getserver(void);


/** @brief Update table of DNS entries
  *
  * Iterate through the table of DNS entries. If there are new entries, create and
  * send a query to the DNS Server to ask for "A" records. The structure of the
  * request is defined by RFC1035
  *
  * @param void
  *
  */
void
check_entries(void);

/** @brief get_qname_len() - Walk through the encoded answer buffer and return
 * the length of the encoded name in chars.
 *---------------------------------------------------------------------------*/
int
get_qname_len(struct pbuf *p, unsigned char *name_ptr);

#endif /* STI_RESOLV_H */
