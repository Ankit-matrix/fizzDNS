#include <stdio.h>
#include <string.h>

#include "dns_bloom.h"
#include "dns_cache.h"
#include "dns_iface.h"
#include "dns_msg.h"
#include "resolver.h"

/* Both af_xdp_user and server link THIS object -- the same compiled
 * code, called through the same function. That is what reduces the
 * benchmark to one independent variable. If each transport carried its
 * own parsing and response building, a measured difference between them
 * would be a difference between two programs and you couldn't attribute
 * it to the transport at all. */

int dns_backend_init(int num_workers)
{
	if (dns_cache_init())
		return -1;

	dns_resolver_init();

	printf("dns backend: %d workers, cache %d entries / %d buckets\n",
	       num_workers, CACHE_CAPACITY, CACHE_BUCKETS);
	return 0;
}

int dns_resolve_query(const uint8_t *query, size_t query_len,
		      uint8_t *resp, size_t resp_cap, size_t *resp_len, bool is_udp)
{
	struct dns_query_info q;
	struct dns_answer ans[DNS_MAX_ANSWERS];
	size_t nans = 0;
	int rcode = DNS_RCODE_SERVFAIL;

	/* Something we can't parse gets no reply at all: we don't know its
	 * transaction id or its question, so there is nothing coherent to
	 * put in a FORMERR. */
	if (dns_parse_query(query, query_len, &q))
		return DNS_DROP;

	if (q.q.qclass != DNS_CLASS_IN)		//chaosnet and friends
		rcode = DNS_RCODE_NOTIMP;
	else
		dns_resolve(q.q.name, q.q.qtype, ans, DNS_MAX_ANSWERS,
			    &nans, &rcode);

	if (dns_build_response(query, query_len, &q, ans, nans, rcode, is_udp,
			       resp, resp_cap, resp_len))
		return DNS_DROP;

	return DNS_OK;
}

void dns_backend_fini(void)
{
	uint64_t hits = 0, misses = 0, evict = 0, expired = 0;
	uint64_t upq = 0, upto = 0;
	size_t entries = 0;

	dns_cache_stats(&hits, &misses, &evict, &expired, &entries);
	dns_resolver_stats(&upq, &upto);

	printf("--- dns backend ---\n");
	printf("  cache hits      %llu\n", (unsigned long long)hits);
	printf("  cache misses    %llu\n", (unsigned long long)misses);
	if (hits + misses)
		printf("  hit rate        %.1f%%\n",
		       100.0 * (double)hits / (double)(hits + misses));
	printf("  evictions       %llu\n", (unsigned long long)evict);
	printf("  expired         %llu\n", (unsigned long long)expired);
	printf("  live entries    %zu\n", entries);

	uint64_t bq = 0, br = 0, bsat = 0;
	size_t bused = 0;

	dns_bloom_stats(&bq, &br, &bsat, &bused);
	if (bq) {
		printf("  bloom lookups   %llu\n", (unsigned long long)bq);
		printf("  bloom rejects   %llu (%.1f%% skipped the lock)\n",
		       (unsigned long long)br,
		       100.0 * (double)br / (double)bq);
		printf("  bloom slots     %zu / %u\n", bused, BLOOM_SLOTS);
		if (bsat)
			printf("  bloom SATURATED %llu -- filter undersized\n",
			       (unsigned long long)bsat);
	}
	printf("  upstream sent   %llu\n", (unsigned long long)upq);
	printf("  upstream t/o    %llu\n", (unsigned long long)upto);

	dns_cache_fini();
}
