#ifndef DNS_BLOOM_H
#define DNS_BLOOM_H

#include <stdint.h>
#include <stddef.h>

/* Counting Bloom filter in front of the cache hash map.
 *
 * The point is not to make a hit cheaper -- a hit still walks the
 * bucket. The point is that a MISS never has to take the cache mutex at
 * all: four relaxed byte loads out of a 64 KiB array answer "definitely
 * not cached" with no lock, no chain walk, and no cache-line ping-pong
 * between workers. Cold queries are the common case on a real resolver.
 *
 * Counting, not plain bits, because this cache deletes. LRU eviction
 * and TTL expiry both remove entries, and a plain filter cannot clear a
 * bit without risking a false negative for some other key that happens
 * to share it. Bits would only ever accumulate, the false positive rate
 * would climb toward 1, and the filter would decay into a branch that
 * always says "maybe". Counters make removal exact.
 *
 * One byte per slot rather than packed 4-bit nibbles: 64 KiB total,
 * which is nothing next to the cache itself, and a byte is the smallest
 * unit that can be updated without a read-modify-write straddling two
 * counters that share a word.
 *
 * m/n = 65536/4096 = 16 slots per entry at k = 4 gives a theoretical
 * false positive rate of (1 - e^(-kn/m))^k ~= 0.24%.
 *
 * Building with -DDNS_BLOOM_DISABLED compiles the filter out entirely,
 * leaving the original lock-then-look-up path. That is what the A/B
 * benchmark builds against; it is not a runtime switch, so neither
 * binary pays for a branch the other doesn't have.
 */

#define BLOOM_SLOTS	65536u	//power of two
#define BLOOM_HASHES	4u
#define BLOOM_MAX	255u	//counter saturation point

/* Shared key hash: FNV-1a 64, lowercasing as it goes, qtype mixed in.
 * The cache derives its bucket index from the low bits and the filter
 * derives its k slots from the whole word, so a lookup hashes the name
 * once, not twice. Defined even when the filter is compiled out. */
uint64_t dns_key_hash(const char *name, uint16_t qtype);

#ifndef DNS_BLOOM_DISABLED

void dns_bloom_reset(void);

/* Lock free. 0 = definitely absent, 1 = possibly present. */
int dns_bloom_maybe(uint64_t hash);

/* Callers must serialise these against each other; the cache mutex
 * already does, since every insertion and removal happens under it. */
void dns_bloom_add(uint64_t hash);
void dns_bloom_del(uint64_t hash);

/* saturated counts slots pinned at BLOOM_MAX. Those can no longer be
 * decremented, so they are a permanent source of false positives --
 * nonzero here means the filter is undersized for the load. */
void dns_bloom_stats(uint64_t *queries, uint64_t *rejected,
		     uint64_t *saturated, size_t *slots_used);

#else	/* filter compiled out */

static inline void dns_bloom_reset(void) { }
static inline int dns_bloom_maybe(uint64_t h) { (void)h; return 1; }
static inline void dns_bloom_add(uint64_t h) { (void)h; }
static inline void dns_bloom_del(uint64_t h) { (void)h; }
static inline void dns_bloom_stats(uint64_t *q, uint64_t *r, uint64_t *s,
				   size_t *u)
{
	if (q) *q = 0;
	if (r) *r = 0;
	if (s) *s = 0;
	if (u) *u = 0;
}

#endif	/* DNS_BLOOM_DISABLED */

#endif
