#ifndef RESOLVER_H
#define RESOLVER_H

#include <stddef.h>
#include <stdint.h>

#include "dns_msg.h"

/* Iterative resolution from the roots, with caching. Thread safe --
 * call it from as many workers as you like. */

/* Reads DNS_ROOT_HINTS. Call once at startup. */
void dns_resolver_init(void);

/* Returns 0 if resolution completed (an authoritative NXDOMAIN counts),
 * -1 if it failed outright, in which case *rcode is SERVFAIL. *nans may
 * include CNAMEs preceding the final A/AAAA. */
int dns_resolve(const char *name, uint16_t qtype,
		struct dns_answer *ans, size_t cap, size_t *nans, int *rcode);

void dns_resolver_stats(uint64_t *queries, uint64_t *timeouts);

#endif