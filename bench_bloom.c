/* A/B benchmark for the Bloom fast path. Two binaries from this one
 * source: bench_bloom, and bench_nobloom built with -DDNS_BLOOM_DISABLED.
 * A compile-time switch rather than a runtime flag, so neither build
 * pays for a branch the other does not have.
 *
 * What is being measured is not "is a Bloom filter fast" -- it is
 * whether skipping the cache mutex on a cold query is worth four byte
 * loads. Expect the answer to depend almost entirely on two things:
 * the fraction of queries that miss, and the number of workers
 * contending for the lock. At one thread the mutex is uncontended and
 * the win is small; the interesting column is the multi-threaded one.
 *
 *   ./bench_bloom -t 4 -n 2000000 -c 90
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "dns_bloom.h"
#include "dns_cache.h"
#include "dns_msg.h"

#define LIVE_ENTRIES	(CACHE_CAPACITY / 2)
#define NAME_POOL	8192	//per thread, cycled through

static int nthreads = 4;
static long niters = 1000000;
static int cold_pct = 90;

struct worker {
	pthread_t tid;
	int id;
	long hits;
	double ns_per_op;
	char (*names)[64];	//built before the clock starts
};

static double now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* xorshift, per thread, so the name selection costs a few cycles and
 * not a trip through rand()'s internal lock. */
static inline uint32_t xrand(uint32_t *s)
{
	uint32_t x = *s;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return (*s = x);
}

/* Names are built up front, not inside the timed loop. snprintf costs
 * a few hundred nanoseconds -- more than the lookup it was meant to be
 * feeding -- and leaving it in the loop buries the effect being
 * measured under formatting overhead. */
static int build_names(struct worker *w)
{
	uint32_t seed = 0x9e3779b9u ^ (uint32_t)w->id;

	w->names = calloc(NAME_POOL, sizeof(*w->names));
	if (!w->names)
		return -1;

	for (int i = 0; i < NAME_POOL; i++) {
		uint32_t r = xrand(&seed);

		if ((int)(r % 100) < cold_pct)
			snprintf(w->names[i], 64, "cold%u.example.com",
				 r ^ 0x5bf03635u);
		else
			snprintf(w->names[i], 64, "live%u.example.com",
				 r % LIVE_ENTRIES);
	}
	return 0;
}

static void *run(void *arg)
{
	struct worker *w = arg;
	struct dns_answer out[DNS_MAX_ANSWERS];
	size_t n;
	int rcode;
	double t0, t1;

	t0 = now_ns();
	for (long i = 0; i < niters; i++) {
		const char *name = w->names[i & (NAME_POOL - 1)];

		if (dns_cache_get(name, DNS_TYPE_A, out, DNS_MAX_ANSWERS,
				  &n, &rcode))
			w->hits++;
	}
	t1 = now_ns();

	w->ns_per_op = (t1 - t0) / (double)niters;
	return NULL;
}

static void populate(void)
{
	struct dns_answer a;
	char name[64];

	memset(&a, 0, sizeof(a));
	a.type = DNS_TYPE_A;
	a.ttl = 86400;		//outlive the run
	inet_pton(AF_INET, "10.0.0.1", &a.rdata.a);

	for (int i = 0; i < LIVE_ENTRIES; i++) {
		snprintf(name, sizeof(name), "live%d.example.com", i);
		snprintf(a.owner, sizeof(a.owner), "%s", name);
		dns_cache_put(name, DNS_TYPE_A, &a, 1, DNS_RCODE_NOERROR);
	}
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "t:n:c:")) != -1) {
		switch (opt) {
		case 't': nthreads = atoi(optarg); break;
		case 'n': niters = atol(optarg); break;
		case 'c': cold_pct = atoi(optarg); break;
		default:
			fprintf(stderr,
				"usage: %s [-t threads] [-n iters] [-c cold%%]\n",
				argv[0]);
			return 2;
		}
	}
	if (nthreads < 1 || niters < 1 || cold_pct < 0 || cold_pct > 100) {
		fprintf(stderr, "bad arguments\n");
		return 2;
	}

#ifdef DNS_BLOOM_DISABLED
	const char *build = "bloom DISABLED (lock on every lookup)";
#else
	const char *build = "bloom ENABLED";
#endif

	dns_cache_init();
	populate();

	struct worker *w = calloc((size_t)nthreads, sizeof(*w));

	if (!w)
		return 1;

	for (int i = 0; i < nthreads; i++) {
		w[i].id = i;
		if (build_names(&w[i]))
			return 1;
	}

	double wall0 = now_ns();

	for (int i = 0; i < nthreads; i++)
		pthread_create(&w[i].tid, NULL, run, &w[i]);
	for (int i = 0; i < nthreads; i++)
		pthread_join(w[i].tid, NULL);

	double wall = now_ns() - wall0;

	double sum_ns = 0;
	long total_hits = 0;

	for (int i = 0; i < nthreads; i++) {
		sum_ns += w[i].ns_per_op;
		total_hits += w[i].hits;
	}

	long total_ops = niters * nthreads;
	uint64_t bq = 0, br = 0, bsat = 0;

	dns_bloom_stats(&bq, &br, &bsat, NULL);

	printf("%s\n", build);
	printf("  threads         %d\n", nthreads);
	printf("  lookups         %ld  (%d%% cold by construction)\n",
	       total_ops, cold_pct);
	printf("  mean ns/op      %.1f\n", sum_ns / nthreads);
	printf("  throughput      %.2f Mlookup/s\n",
	       (double)total_ops / (wall / 1e9) / 1e6);
	printf("  measured hits   %.1f%%\n",
	       100.0 * (double)total_hits / (double)total_ops);
	if (bq) {
		printf("  bloom rejects   %llu (%.1f%% of lookups took no lock)\n",
		       (unsigned long long)br, 100.0 * (double)br / (double)bq);
		/* Cold queries that the filter waved through anyway. This
		 * is the empirical false positive rate under load, and it
		 * is the number to watch: if it drifts up, the filter is
		 * undersized and the fast path stops paying for itself. */
		double cold = (double)total_ops - (double)total_hits;

		if (cold > 0)
			printf("  bloom fp rate   %.3f%%\n",
			       100.0 * (cold - (double)br) / cold);
		if (bsat)
			printf("  SATURATED       %llu slot updates lost -- "
			       "filter is undersized\n",
			       (unsigned long long)bsat);
	}

	dns_cache_fini();
	for (int i = 0; i < nthreads; i++)
		free(w[i].names);
	free(w);
	return 0;
}
