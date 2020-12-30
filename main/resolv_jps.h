/**
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
#ifndef RESOLV_JPS_H
#define RESOLV_JPS_H

/* enumerated list of possible result values returned by gethostname() */
typedef enum e_resolv_result {
  RESOLV_QUERY_INVALID,
  RESOLV_QUERY_QUEUED,
  RESOLV_COMPLETE
} RESOLV_RESULT;

//typedef void(* user_cb_fn) (int i);
typedef void(* user_cb_fn) (char *name, struct ip4_addr *addr);
/* Functions. */

err_t resolv_init(ip_addr_t *dnsserver_ip_addr_ptr); /* working to pass ip_addr_t*/

void resolv_query(char *name, user_cb_fn jps_cb_ptr);
//void resolv_query(char *name, void (*found)(char *name, struct ip_addr *addr))
//void resolv_query(char *name);

u32_t
resolv_lookup(char *name);

u32_t
resolv_getserver(void);

void
check_entries(void);

#endif /* RESOLV_JPS_H */
