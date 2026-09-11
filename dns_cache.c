#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dns_bloom.h"
#include "dns_cache.h"

struct cache_node {
	char name[DNS_MAX_NAME + 1];
	uint16_t qtype;

	struct dns_answer ans[DNS_MAX_ANSWERS];
	size_t nans;
	int rcode;
	time_t expires;

	struct cache_node *hnext;		//bucket chain
	struct cache_node *prev, *next;		//lru list, MRU at head
};

static struct cache_node *buckets[CACHE_BUCKETS];
static struct cache_node *lru_head, *lru_tail;
static size_t entry_count;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
/* Atomic because the Bloom fast path bumps misses without taking
 * the lock -- that is the whole saving, so the counter has to be safe
 * on its own. */
static _Atomic uint64_t hits, misses, evictions, expirations;

/* Key hashing moved to dns_key_hash() (dns_bloom.c) so the map and the
 * filter cannot drift apart and a lookup only hashes the name once: the
 * bucket takes the low bits, the filter takes the whole word. Lowercase
 * as we go -- the hash and dns_name_equal() have to agree on case or
 * EXAMPLE.com lands in a different bucket from example.com and the
 * comparison never gets a chance to run. */
static inline uint32_t bucket_of(uint64_t hash)
{
	return (uint32_t)hash & (CACHE_BUCKETS - 1);
}

static uint32_t clamp_ttl(uint32_t ttl)
{
	if (ttl < CACHE_MIN_TTL)
		return CACHE_MIN_TTL;
	if (ttl > CACHE_MAX_TTL)
		return CACHE_MAX_TTL;
	return ttl;
}

/* ---- list helpers, caller holds the lock ---- */

static void lru_unlink(struct cache_node *n)
{
	if (n->prev)
		n->prev->next = n->next;
	else
		lru_head = n->next;

	if (n->next)
		n->next->prev = n->prev;
	else
		lru_tail = n->prev;

	n->prev = n->next = NULL;
}

static void lru_push_front(struct cache_node *n)
{
	n->prev = NULL;
	n->next = lru_head;
	if (lru_head)
		lru_head->prev = n;
	lru_head = n;
	if (!lru_tail)
		lru_tail = n;
}

static void bucket_unlink(struct cache_node *n)
{
	struct cache_node **pp = &buckets[bucket_of(dns_key_hash(n->name, n->qtype))];

	while (*pp) {
		if (*pp == n) {
			*pp = n->hnext;
			n->hnext = NULL;
			return;
		}
		pp = &(*pp)->hnext;
	}
}

/* The filter has to be told, or its counters would only ever go up and
 * it would decay into a branch that always says "maybe". */
static void node_destroy(struct cache_node *n)
{
	dns_bloom_del(dns_key_hash(n->name, n->qtype));
	bucket_unlink(n);
	lru_unlink(n);
	free(n);
	entry_count--;
}

static struct cache_node *bucket_find(uint64_t hash, const char *name,
				      uint16_t qtype)
{
	for (struct cache_node *n = buckets[bucket_of(hash)]; n; n = n->hnext)
		if (n->qtype == qtype && dns_name_equal(n->name, name))
			return n;
	return NULL;
}

/* Evict from the tail, but prefer an already dead entry if one is near
 * it -- reclaiming dead weight beats throwing away a live cold entry. */
static void evict_one(time_t now)
{
	struct cache_node *victim = lru_tail;
	int scanned = 0;

	for (struct cache_node *n = lru_tail; n && scanned < 8;
	     n = n->prev, scanned++) {
		if (n->expires <= now) {
			victim = n;
			break;
		}
	}

	if (victim) {
		node_destroy(victim);
		evictions++;
	}
}

/* ---- public ---- */

int dns_cache_init(void)
{
	pthread_mutex_lock(&lock);
	memset(buckets, 0, sizeof(buckets));
	lru_head = lru_tail = NULL;
	entry_count = 0;
	hits = misses = evictions = expirations = 0;
	dns_bloom_reset();
	pthread_mutex_unlock(&lock);
	return 0;
}

void dns_cache_fini(void)
{
	pthread_mutex_lock(&lock);

	struct cache_node *n = lru_head;

	while (n) {
		struct cache_node *next = n->next;

		free(n);
		n = next;
	}
	memset(buckets, 0, sizeof(buckets));
	lru_head = lru_tail = NULL;
	entry_count = 0;
	//nodes were freed directly above, never through node_destroy
	dns_bloom_reset();

	pthread_mutex_unlock(&lock);
}

int dns_cache_get(const char *name, uint16_t qtype,
		  struct dns_answer *out, size_t cap, size_t *n_out, int *rcode)
{
	time_t now = time(NULL);
	uint64_t h = dns_key_hash(name, qtype);
	int found = 0;

	/* The whole point of the filter: a cold query answers here, with
	 * four relaxed byte loads and no mutex. Everything below this
	 * line costs a lock acquisition the cold path now skips. */
	if (!dns_bloom_maybe(h)) {
		atomic_fetch_add_explicit(&misses, 1, memory_order_relaxed);
		return 0;
	}

	pthread_mutex_lock(&lock);

	struct cache_node *n = bucket_find(h, name, qtype);

	if (!n) {
		misses++;
	} else if (n->expires <= now) {
		node_destroy(n);
		expirations++;
		misses++;
	} else {
		size_t k = n->nans < cap ? n->nans : cap;
		uint32_t remaining = (uint32_t)(n->expires - now);

		for (size_t i = 0; i < k; i++) {
			out[i] = n->ans[i];
			out[i].ttl = remaining;	//what the client should see now
		}
		*n_out = k;
		*rcode = n->rcode;

		lru_unlink(n);
		lru_push_front(n);

		hits++;
		found = 1;
	}

	pthread_mutex_unlock(&lock);
	return found;
}

void dns_cache_put(const char *name, uint16_t qtype,
		   const struct dns_answer *ans, size_t n, int rcode)
{
	time_t now = time(NULL);
	uint32_t ttl;

	if (n > DNS_MAX_ANSWERS)
		n = DNS_MAX_ANSWERS;

	/* The set dies when its shortest lived member does. */
	if (n == 0) {
		ttl = CACHE_NEG_TTL;
	} else {
		ttl = CACHE_MAX_TTL;
		for (size_t i = 0; i < n; i++)
			if (ans[i].ttl < ttl)
				ttl = ans[i].ttl;
		ttl = clamp_ttl(ttl);
	}

	uint64_t h = dns_key_hash(name, qtype);

	pthread_mutex_lock(&lock);

	struct cache_node *node = bucket_find(h, name, qtype);

	if (!node) {
		while (entry_count >= CACHE_CAPACITY)
			evict_one(now);

		node = calloc(1, sizeof(*node));
		if (!node) {
			pthread_mutex_unlock(&lock);
			return;
		}

		snprintf(node->name, sizeof(node->name), "%s", name);
		node->qtype = qtype;

		uint32_t b = bucket_of(h);

		node->hnext = buckets[b];
		buckets[b] = node;
		entry_count++;

		/* Only for a genuinely new key. Re-putting an existing one
		 * would double-count its slots and leave them stuck high
		 * after the single matching del(). */
		dns_bloom_add(h);
	} else {
		lru_unlink(node);
	}

	/* memcpy from NULL is UB even with n == 0, and UBSan will say so. */
	if (n && ans)
		memcpy(node->ans, ans, n * sizeof(*ans));
	node->nans = n;
	node->rcode = rcode;
	node->expires = now + (time_t)ttl;

	lru_push_front(node);

	pthread_mutex_unlock(&lock);
}

void dns_cache_stats(uint64_t *h, uint64_t *m, uint64_t *e, uint64_t *x,
		     size_t *entries)
{
	pthread_mutex_lock(&lock);
	if (h) *h = atomic_load_explicit(&hits, memory_order_relaxed);
	if (m) *m = atomic_load_explicit(&misses, memory_order_relaxed);
	if (e) *e = atomic_load_explicit(&evictions, memory_order_relaxed);
	if (x) *x = atomic_load_explicit(&expirations, memory_order_relaxed);
	if (entries) *entries = entry_count;
	pthread_mutex_unlock(&lock);
}
