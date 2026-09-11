#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stdint.h>
#include <stddef.h>

#include "dns_msg.h"

/* Thread safe LRU keyed on (name, qtype).
 *
 * TTLs come off the wire, clamped into a sane range, and lookup serves
 * the REMAINING ttl. A cache that pins every record for a flat 300s
 * serves stale data and visibly disagrees with dig. */

#define CACHE_CAPACITY	4096
#define CACHE_BUCKETS	2048	//power of two
#define CACHE_MIN_TTL	5
#define CACHE_MAX_TTL	86400
#define CACHE_NEG_TTL	60	//how long we remember an NXDOMAIN

int dns_cache_init(void);
void dns_cache_fini(void);

/* 1 on hit (out/n/rcode filled in), 0 on miss. A negative entry is a hit
 * with rcode NXDOMAIN and *n = 0. */
int dns_cache_get(const char *name, uint16_t qtype,
		  struct dns_answer *out, size_t cap, size_t *n, int *rcode);

/* n = 0 with rcode NXDOMAIN caches a negative result. */
void dns_cache_put(const char *name, uint16_t qtype,
		   const struct dns_answer *ans, size_t n, int rcode);

void dns_cache_stats(uint64_t *hits, uint64_t *misses, uint64_t *evictions,
		     uint64_t *expired, size_t *entries);

#endif
