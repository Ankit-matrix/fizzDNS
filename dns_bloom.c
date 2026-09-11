#include <ctype.h>
#include <stdatomic.h>
#include <string.h>

#include "dns_bloom.h"

uint64_t dns_key_hash(const char *name, uint16_t qtype)
{
	uint64_t h = 14695981039346656037ULL;

	for (const char *p = name; *p; p++) {
		h ^= (uint8_t)tolower((unsigned char)*p);
		h *= 1099511628211ULL;
	}
	h ^= qtype;
	h *= 1099511628211ULL;
	return h;
}

#ifndef DNS_BLOOM_DISABLED

static _Atomic unsigned char slots[BLOOM_SLOTS];

/* Statistics are sharded per thread, one cache line each.
 *
 * They were three shared _Atomic counters, fetch_add'ed on every
 * lookup. That is a lock-prefixed read-modify-write on a line every
 * worker is writing, and it measured at ~10ns per lookup uncontended
 * and far worse with four threads -- more than the filter check it was
 * meant to be instrumenting. The filter existed to avoid exactly this
 * kind of shared write and its own bookkeeping was reintroducing it.
 *
 * Each thread now owns a shard and is the only writer to it, so the
 * relaxed load/store pair below compiles to plain movs with no lock
 * prefix. Readers sum the shards; they may catch a shard mid-update
 * and read a count one low, which is fine for a diagnostic. */
#define STAT_SHARDS	64

struct stat_shard {
	_Atomic uint64_t queries, rejected, saturated;
} __attribute__((aligned(64)));

static struct stat_shard shards[STAT_SHARDS];
static _Atomic unsigned int next_shard;
static _Thread_local struct stat_shard *my_shard;

static inline struct stat_shard *shard(void)
{
	if (__builtin_expect(my_shard == NULL, 0)) {
		unsigned int i = atomic_fetch_add_explicit(&next_shard, 1,
							   memory_order_relaxed);
		my_shard = &shards[i % STAT_SHARDS];
	}
	return my_shard;
}

/* Single writer per shard, so this need not be atomic as a unit. */
static inline void bump(_Atomic uint64_t *c)
{
	atomic_store_explicit(c,
			      atomic_load_explicit(c, memory_order_relaxed) + 1,
			      memory_order_relaxed);
}

/* Kirsch-Mitzenmacher: k slots from one 64 bit hash, g(i) = h1 + i*h2.
 * Forcing h2 odd keeps the k indices distinct -- (i - j) * h2 is only
 * 0 mod 2^16 when 2^16 divides (i - j), impossible for i, j < k. That
 * matters: if two of the k indices collided, add() would bump one slot
 * once where del() expects to decrement it twice. */
static inline void bloom_slots(uint64_t hash, uint32_t *idx)
{
	uint32_t h1 = (uint32_t)hash;
	uint32_t h2 = (uint32_t)(hash >> 32) | 1u;

	for (uint32_t i = 0; i < BLOOM_HASHES; i++)
		idx[i] = (h1 + i * h2) & (BLOOM_SLOTS - 1);
}

void dns_bloom_reset(void)
{
	for (uint32_t i = 0; i < BLOOM_SLOTS; i++)
		atomic_store_explicit(&slots[i], 0, memory_order_relaxed);

	for (unsigned int i = 0; i < STAT_SHARDS; i++) {
		atomic_store_explicit(&shards[i].queries, 0, memory_order_relaxed);
		atomic_store_explicit(&shards[i].rejected, 0, memory_order_relaxed);
		atomic_store_explicit(&shards[i].saturated, 0, memory_order_relaxed);
	}
}

/* No lock, relaxed loads. Both ways of racing an in-flight update are
 * harmless. Reading a zero that a concurrent add() is about to fill
 * reports "absent" for an entry inserted microseconds ago: a lost hit,
 * and the resolver just resolves it again. Reading a stale nonzero
 * after a del() reports "maybe", we take the lock, bucket_find() comes
 * back NULL, and it is an ordinary miss. What cannot happen is a
 * long-established entry reading as absent, because its counters were
 * raised before it was ever visible in the map. */
int dns_bloom_maybe(uint64_t hash)
{
	uint32_t idx[BLOOM_HASHES];

	struct stat_shard *st = shard();

	bloom_slots(hash, idx);
	bump(&st->queries);

	for (uint32_t i = 0; i < BLOOM_HASHES; i++) {
		if (atomic_load_explicit(&slots[idx[i]],
					 memory_order_relaxed) == 0) {
			bump(&st->rejected);
			return 0;
		}
	}
	return 1;
}

void dns_bloom_add(uint64_t hash)
{
	uint32_t idx[BLOOM_HASHES];

	bloom_slots(hash, idx);

	for (uint32_t i = 0; i < BLOOM_HASHES; i++) {
		unsigned char v = atomic_load_explicit(&slots[idx[i]],
						       memory_order_relaxed);

		if (v == BLOOM_MAX) {
			/* Pinned. Leave it: an over-count only ever costs
			 * false positives, an under-count would cost a
			 * false negative and a wrongly skipped lookup. */
			bump(&shard()->saturated);
			continue;
		}
		atomic_store_explicit(&slots[idx[i]], (unsigned char)(v + 1),
				      memory_order_relaxed);
	}
}

void dns_bloom_del(uint64_t hash)
{
	uint32_t idx[BLOOM_HASHES];

	bloom_slots(hash, idx);

	for (uint32_t i = 0; i < BLOOM_HASHES; i++) {
		unsigned char v = atomic_load_explicit(&slots[idx[i]],
						       memory_order_relaxed);

		/* v == 0 means a removal without a matching insertion, and
		 * v == BLOOM_MAX means the count was already lost to
		 * saturation. Decrementing either would let some unrelated
		 * key read as absent while it is still in the map. */
		if (v == 0 || v == BLOOM_MAX)
			continue;

		atomic_store_explicit(&slots[idx[i]], (unsigned char)(v - 1),
				      memory_order_relaxed);
	}
}

void dns_bloom_stats(uint64_t *q, uint64_t *r, uint64_t *s, size_t *used)
{
	uint64_t tq = 0, tr = 0, ts = 0;

	for (unsigned int i = 0; i < STAT_SHARDS; i++) {
		tq += atomic_load_explicit(&shards[i].queries, memory_order_relaxed);
		tr += atomic_load_explicit(&shards[i].rejected, memory_order_relaxed);
		ts += atomic_load_explicit(&shards[i].saturated, memory_order_relaxed);
	}
	if (q) *q = tq;
	if (r) *r = tr;
	if (s) *s = ts;

	if (used) {
		size_t n = 0;

		for (uint32_t i = 0; i < BLOOM_SLOTS; i++)
			if (atomic_load_explicit(&slots[i],
						 memory_order_relaxed))
				n++;
		*used = n;
	}
}

#endif	/* DNS_BLOOM_DISABLED */
