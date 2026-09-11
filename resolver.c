#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "dns_cache.h"
#include "dns_msg.h"
#include "resolver.h"

/* Ask a server; it either answers or hands back a referral one level
 * closer. Repeat until an answer, an NXDOMAIN, or we run out of budget.
 *
 *   www.example.com -> a.root-servers.net
 *     referral: com NS a.gtld-servers.net (+ glue)
 *   www.example.com -> a.gtld-servers.net
 *     referral: example.com NS ns1.example.com (+ glue)
 *   www.example.com -> ns1.example.com
 *     answer: A 93.184.216.34
 *
 * The things that are easy to get wrong: referrals with no glue (you
 * have to resolve the NS name itself, recursively), CNAME chains (you
 * follow them AND return every hop), truncation (TC means what you have
 * is incomplete, so don't parse a partial referral), and NODATA (the
 * name exists and the server answered authoritatively, it just has no
 * record of the type you asked for -- that's NOERROR with zero answers,
 * not a failure). NODATA was invisible as long as every name in the
 * test zone had exactly the one record type ever queried for it; it
 * became reachable the moment a name could have an A but no AAAA. */

#define UDP_TIMEOUT_SEC		2
#define MAX_REFERRALS		16	//delegation depth
#define MAX_CNAME_HOPS		8
#define MAX_NS_DEPTH		3	//nested resolves for missing glue
#define MAX_NS_CANDIDATES	8	//servers tried per level
#define MSG_BUF			1500

/* The only addresses in the system that can't be discovered by
 * resolution. https://www.iana.org/domains/root/servers */
static const char *const root_hints[] = {
	"198.41.0.4",		//a.root-servers.net
	"170.247.170.2",	//b
	"192.33.4.12",		//c
	"199.7.91.13",		//d
	"192.203.230.10",	//e
	"192.5.5.241",		//f
	"192.112.36.4",		//g
	"198.97.190.53",	//h
	"192.36.148.17",	//i
	"192.58.128.30",	//j
	"193.0.14.129",		//k
	"199.7.83.42",		//l
	"202.12.27.33",		//m
};
#define NUM_ROOTS ((int)(sizeof(root_hints) / sizeof(root_hints[0])))

/* Overridable via DNS_ROOT_HINTS so referral/glue/CNAME logic can be
 * exercised against a local fake hierarchy with no internet at all.
 * Twenty lines, and it turns the slowest, flakiest part of this file
 * into a two second test. */
static char active_roots[MAX_NS_CANDIDATES][INET_ADDRSTRLEN];
static const char *active_root_ptr[MAX_NS_CANDIDATES];
static const char *const *roots = root_hints;
static int nroots = NUM_ROOTS;

static uint64_t upstream_queries, upstream_timeouts;
static pthread_mutex_t stat_lock = PTHREAD_MUTEX_INITIALIZER;

static void stat_bump(uint64_t *counter)
{
	pthread_mutex_lock(&stat_lock);
	(*counter)++;
	pthread_mutex_unlock(&stat_lock);
}

/* The transaction id is the only unpredictable field an off-path
 * spoofer has to guess, so it comes from the kernel CSPRNG and nothing
 * else. rand_r() is a linear congruential generator, and seeding it
 * from time(NULL) ^ &seed leaves maybe a few dozen bits of real entropy
 * -- one observed query is enough to reconstruct the sequence and
 * predict every id this thread will ever use.
 *
 * Drawn 64 at a time so this is not a syscall per upstream query.
 * Returns -1 if the CSPRNG is unavailable; there is deliberately no
 * weak fallback, because a resolver that quietly degrades to guessable
 * ids is worse than one that refuses to resolve. */
static int next_txid(void)
{
	static __thread uint16_t pool[64];
	static __thread unsigned left;

	if (left == 0) {
		ssize_t n = getrandom(pool, sizeof(pool), 0);

		if (n != (ssize_t)sizeof(pool))
			return -1;
		left = sizeof(pool) / sizeof(pool[0]);
	}
	return pool[--left];
}

void dns_resolver_init(void)
{
	const char *env = getenv("DNS_ROOT_HINTS");
	char buf[512];
	int n = 0;

	if (!env || !*env)
		return;

	snprintf(buf, sizeof(buf), "%s", env);

	for (char *tok = strtok(buf, ","); tok && n < MAX_NS_CANDIDATES;
	     tok = strtok(NULL, ",")) {
		while (*tok == ' ')
			tok++;
		snprintf(active_roots[n], INET_ADDRSTRLEN, "%s", tok);
		active_root_ptr[n] = active_roots[n];
		n++;
	}

	if (n) {
		roots = active_root_ptr;
		nroots = n;
		fprintf(stderr, "resolver: using %d override root hint(s)\n", n);
	}
}

/* ---------------- one udp round trip ---------------- */

static int query_server(const char *server_ip, const char *name, uint16_t qtype,
			uint8_t *resp, size_t resp_cap)
{
	uint8_t qbuf[MSG_BUF];
	struct sockaddr_in dst;
	struct timeval tv = { .tv_sec = UDP_TIMEOUT_SEC, .tv_usec = 0 };
	int txid32 = next_txid();
	uint16_t txid;
	size_t qlen;
	int fd, ret = -1;

	if (txid32 < 0)
		return -1;
	txid = (uint16_t)txid32;

	if (dns_build_query(txid, name, qtype, false, DNS_EDNS_OUR_UDP_PAYLOAD,
			    qbuf, sizeof(qbuf), &qlen))
		return -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(53);
	if (inet_pton(AF_INET, server_ip, &dst.sin_addr) != 1)
		goto out;

	/* connect() on a UDP socket makes the kernel drop datagrams from
	 * anyone except this server. Free spoofing protection. */
	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		goto out;

	stat_bump(&upstream_queries);

	if (send(fd, qbuf, qlen, 0) < 0)
		goto out;

	for (;;) {
		struct dns_header h;
		ssize_t n = recv(fd, resp, resp_cap, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				stat_bump(&upstream_timeouts);
			goto out;
		}
		if (dns_parse_header(resp, (size_t)n, &h))
			goto out;

		/* Not our answer. Keep reading until the timeout rather
		 * than accepting it. */
		if (h.id != txid || !(h.flags & DNS_FLAG_QR))
			continue;

		/* And match the question back. A 16 bit id is 65536
		 * guesses; connect() narrows the source but does not
		 * authenticate the content, and an id match alone will
		 * happily accept an answer for a name we never asked
		 * about. The question section is the rest of what a
		 * datagram has to prove to be a reply to THIS query. */
		if (h.qdcount != 1)
			continue;

		char rname[DNS_MAX_NAME + 1];
		size_t qoff;

		if (dns_name_decode(resp, (size_t)n, DNS_HDR_LEN, rname,
				    sizeof(rname), &qoff))
			continue;
		if (qoff + 4 > (size_t)n)
			continue;
		if (((uint16_t)resp[qoff] << 8 | resp[qoff + 1]) != qtype)
			continue;
		if (((uint16_t)resp[qoff + 2] << 8 | resp[qoff + 3]) !=
		    DNS_CLASS_IN)
			continue;
		if (!dns_name_equal(rname, name))
			continue;

		ret = (int)n;
		break;
	}
out:
	close(fd);
	return ret;
}

/* ---------------- pulling a response apart ---------------- */

struct referral {
	char zone[DNS_MAX_NAME + 1];	//the delegated zone, all NS share it
	char ns_name[MAX_NS_CANDIDATES][DNS_MAX_NAME + 1];
	char ns_addr[MAX_NS_CANDIDATES][INET_ADDRSTRLEN];
	bool has_addr[MAX_NS_CANDIDATES];
	int count;
};

/* Every accepted record is gated on dns_name_in_bailiwick() (dns_msg.c):
 * a server may only speak about names at or below the zone we are
 * currently asking it about. Without it a .com nameserver can hand back
 * a delegation for bank.co.uk, or an A record in someone else's zone,
 * and we cache it. */

static int dissect(const uint8_t *msg, size_t len, const char *qname,
		   const char *zone,
		   struct dns_answer *ans, size_t ans_cap, size_t *nans,
		   char *cname_out, size_t cname_cap,
		   struct referral *ref, int *rcode)
{
	struct dns_header h;
	size_t off, ans_start;

	*nans = 0;
	*rcode = DNS_RCODE_SERVFAIL;
	if (cname_out)
		cname_out[0] = '\0';
	ref->count = 0;
	ref->zone[0] = '\0';

	if (dns_parse_header(msg, len, &h))
		return -1;

	*rcode = h.flags & DNS_RCODE_MASK;

	/* TC means what came back is incomplete. Don't act on half a
	 * referral -- try the next server instead. (Proper TCP fallback
	 * is genuinely not implemented; it's in the report as such.) */
	if (h.flags & DNS_FLAG_TC)
		return -1;

	off = DNS_HDR_LEN;
	for (int i = 0; i < h.qdcount; i++)
		if (dns_skip_question(msg, len, off, &off))
			return -1;

	/* Answers are only accepted for names on the CNAME chain that
	 * starts at the name we asked for, AND only if this server is
	 * allowed to speak for them. Without the chain check a server
	 * can staple an A record for any name onto any reply; without
	 * the bailiwick check it can staple one for any name in anyone
	 * else\'s zone. Both end up in the cache.
	 *
	 * The chain grows as CNAMEs are accepted, so the section is
	 * rescanned until it stops growing -- records are not required
	 * to arrive in chain order, and a single forward pass would drop
	 * legitimate records and turn them into a spurious SERVFAIL.
	 * Each pass rebuilds the answer set from scratch, so it is
	 * idempotent and cannot double-count. */
	ans_start = off;

	char chain[MAX_CNAME_HOPS + 1][DNS_MAX_NAME + 1];
	int nchain = 1;

	snprintf(chain[0], sizeof(chain[0]), "%s", qname);

	for (int pass = 0; pass <= MAX_CNAME_HOPS; pass++) {
		int grown = nchain;
		size_t o = ans_start;

		*nans = 0;
		if (cname_out)
			cname_out[0] = '\0';

		for (int i = 0; i < h.ancount; i++) {
			struct dns_rr rr;

			if (dns_parse_rr(msg, len, o, &rr, &o))
				return -1;
			if (rr.rclass != DNS_CLASS_IN)
				continue;

			if (!dns_name_in_bailiwick(rr.name, zone))
				continue;

			bool on_chain = false;

			for (int c = 0; c < nchain && !on_chain; c++)
				on_chain = dns_name_equal(rr.name, chain[c]);
			if (!on_chain)
				continue;

			if (rr.type == DNS_TYPE_A && rr.rdlength == 4) {
				if (*nans < ans_cap) {
					struct dns_answer *a = &ans[(*nans)++];

					a->type = DNS_TYPE_A;
					a->ttl = rr.ttl;
					memcpy(&a->rdata.a, rr.rdata, 4);
					snprintf(a->owner, sizeof(a->owner), "%s", rr.name);
				}
			} else if (rr.type == DNS_TYPE_AAAA && rr.rdlength == 16) {
				if (*nans < ans_cap) {
					struct dns_answer *a = &ans[(*nans)++];

					a->type = DNS_TYPE_AAAA;
					a->ttl = rr.ttl;
					memcpy(a->rdata.aaaa, rr.rdata, 16);
					snprintf(a->owner, sizeof(a->owner), "%s", rr.name);
				}
			} else if (rr.type == DNS_TYPE_CNAME) {
				char target[DNS_MAX_NAME + 1];

				if (dns_name_decode(msg, len, (size_t)(rr.rdata - msg),
						    target, sizeof(target), NULL))
					continue;

				if (*nans < ans_cap) {
					struct dns_answer *a = &ans[(*nans)++];

					a->type = DNS_TYPE_CNAME;
					a->ttl = rr.ttl;
					snprintf(a->rdata.cname, sizeof(a->rdata.cname),
						 "%s", target);
					snprintf(a->owner, sizeof(a->owner), "%s", rr.name);
				}

				/* only chase a CNAME owned by the name we asked for */
				if (cname_out && dns_name_equal(rr.name, qname))
					snprintf(cname_out, cname_cap, "%s", target);

				bool known = false;

				for (int c = 0; c < nchain && !known; c++)
					known = dns_name_equal(target, chain[c]);
				if (!known && nchain <= MAX_CNAME_HOPS)
					snprintf(chain[nchain++], DNS_MAX_NAME + 1,
						 "%s", target);
			}
		}

		if (nchain == grown)		//converged
			break;
	}

	/* Step over the answer section for real, so the authority parse
	 * below starts where it should. */
	off = ans_start;
	for (int i = 0; i < h.ancount; i++) {
		struct dns_rr rr;

		if (dns_parse_rr(msg, len, off, &rr, &off))
			return -1;
	}

	/* Authority: NS referrals. Three conditions, and a referral that
	 * fails any of them is not a referral, it is an attempt to take
	 * over a zone this server has no business answering for:
	 *
	 *   - the delegated zone must be at or below the zone we asked
	 *     this server about (.com may delegate example.com, not
	 *     bank.co.uk);
	 *   - it must be strictly below, not equal, or a server can point
	 *     at itself forever and we burn the whole referral budget;
	 *   - the name we are chasing must actually live under it, or the
	 *     delegation is not on the path to anything we asked for.
	 *
	 * All NS records in one referral describe the same zone, so the
	 * first accepted owner fixes it and the rest must match. */
	for (int i = 0; i < h.nscount; i++) {
		struct dns_rr rr;
		char nsname[DNS_MAX_NAME + 1];

		if (dns_parse_rr(msg, len, off, &rr, &off))
			return -1;
		if (rr.type != DNS_TYPE_NS || ref->count >= MAX_NS_CANDIDATES)
			continue;

		if (!dns_name_in_bailiwick(rr.name, zone))
			continue;
		if (zone && *zone && dns_name_equal(rr.name, zone))
			continue;
		if (!dns_name_in_bailiwick(qname, rr.name))
			continue;

		if (ref->zone[0]) {
			if (!dns_name_equal(rr.name, ref->zone))
				continue;
		} else {
			snprintf(ref->zone, sizeof(ref->zone), "%s", rr.name);
		}

		if (dns_name_decode(msg, len, (size_t)(rr.rdata - msg),
				    nsname, sizeof(nsname), NULL))
			continue;

		snprintf(ref->ns_name[ref->count], DNS_MAX_NAME + 1, "%s", nsname);
		ref->has_addr[ref->count] = false;
		ref->count++;
	}

	/* Additional: glue. Same rule -- a server may only supply
	 * addresses for names inside the zone it speaks for. Glue for
	 * ns1.example.com from a .com server is fine; glue for
	 * ns1.attacker.net is not, and that one has to be resolved
	 * independently by resolve_ns_addr() instead of being taken on
	 * this server\'s word. */
	for (int i = 0; i < h.arcount; i++) {
		struct dns_rr rr;

		if (dns_parse_rr(msg, len, off, &rr, &off))
			break;		//OPT pseudo-RRs etc, stop, don't fail
		if (rr.type != DNS_TYPE_A || rr.rdlength != 4)
			continue;
		if (!dns_name_in_bailiwick(rr.name, zone))
			continue;

		for (int j = 0; j < ref->count; j++) {
			if (ref->has_addr[j])
				continue;
			if (!dns_name_equal(ref->ns_name[j], rr.name))
				continue;

			inet_ntop(AF_INET, rr.rdata, ref->ns_addr[j],
				  INET_ADDRSTRLEN);
			ref->has_addr[j] = true;
			break;
		}
	}

	return 0;
}

/* ---------------- the loop ---------------- */

static int resolve_from(const char *name, uint16_t qtype,
			const char *const servers[], int nservers,
			struct dns_answer *ans, size_t ans_cap, size_t *nans,
			int *rcode, int ns_depth, int cname_hops);

/* A referral can name servers without giving their addresses. Then we
 * have to resolve the NS name itself, which is a nested resolution with
 * its own depth budget so mutually delegating zones can't spin.
 *
 * Always A: our upstream transport is IPv4 sockets regardless of what
 * the client originally asked for, so an NS hostname is always looked
 * up as an A record here. */
static int resolve_ns_addr(const char *ns_name, char *out, size_t out_cap,
			   int ns_depth)
{
	struct dns_answer ans[DNS_MAX_ANSWERS];
	size_t nans = 0;
	int rcode = 0;

	if (ns_depth >= MAX_NS_DEPTH)
		return -1;

	if (resolve_from(ns_name, DNS_TYPE_A, roots, nroots, ans,
			 DNS_MAX_ANSWERS, &nans, &rcode, ns_depth + 1, 0))
		return -1;

	for (size_t i = 0; i < nans; i++) {
		if (ans[i].type == DNS_TYPE_A) {
			inet_ntop(AF_INET, &ans[i].rdata.a, out,
				  (socklen_t)out_cap);
			return 0;
		}
	}
	return -1;
}

static int resolve_from(const char *name, uint16_t qtype,
			const char *const servers[], int nservers,
			struct dns_answer *ans, size_t ans_cap, size_t *nans,
			int *rcode, int ns_depth, int cname_hops)
{
	char current[MAX_NS_CANDIDATES][INET_ADDRSTRLEN];
	int ncurrent = nservers < MAX_NS_CANDIDATES
		     ? nservers : MAX_NS_CANDIDATES;

	for (int i = 0; i < ncurrent; i++)
		snprintf(current[i], INET_ADDRSTRLEN, "%s", servers[i]);

	/* The zone the current servers are authoritative for. Starts at
	 * the root, which is the empty string, and can only ever move
	 * downward -- dissect() enforces that. This is the state the
	 * bailiwick checks are made against. */
	char zone[DNS_MAX_NAME + 1] = "";

	*nans = 0;
	*rcode = DNS_RCODE_SERVFAIL;

	for (int level = 0; level < MAX_REFERRALS; level++) {
		uint8_t resp[MSG_BUF];
		struct referral ref;
		char cname[DNS_MAX_NAME + 1];
		bool answered = false;

		/* try each server at this level until one talks to us */
		for (int s = 0; s < ncurrent; s++) {
			int n = query_server(current[s], name, qtype,
					     resp, sizeof(resp));

			if (n < 0)
				continue;
			if (dissect(resp, (size_t)n, name, zone, ans, ans_cap,
				    nans, cname, sizeof(cname), &ref, rcode))
				continue;

			answered = true;
			break;
		}

		if (!answered)
			return -1;

		if (*rcode == DNS_RCODE_NXDOMAIN)	//authoritative "no"
			return 0;

		/* did we get what we asked for? */
		for (size_t i = 0; i < *nans; i++) {
			if (ans[i].type == qtype &&
			    dns_name_equal(ans[i].owner, name)) {
				*rcode = DNS_RCODE_NOERROR;
				return 0;
			}
		}

		/* a CNAME instead. Follow it, keeping the hops we already
		 * collected so the client sees the whole chain. */
		if (cname[0] && cname_hops < MAX_CNAME_HOPS) {
			struct dns_answer tail[DNS_MAX_ANSWERS];
			size_t carried = *nans, more = 0;
			int sub_rcode = 0;

			if (resolve_from(cname, qtype, roots, nroots, tail,
					 DNS_MAX_ANSWERS, &more, &sub_rcode,
					 ns_depth, cname_hops + 1))
				return -1;

			for (size_t i = 0; i < more && carried < ans_cap; i++)
				ans[carried++] = tail[i];
			*nans = carried;
			*rcode = sub_rcode;
			return 0;
		}

		/* otherwise it's a referral: go down a level */
		if (ref.count == 0) {
			/* No delegation, no CNAME, no matching record, but a
			 * server DID answer with NOERROR. That's not a
			 * failure -- it's NODATA: the name exists and the
			 * zone is authoritative for it, it just has nothing
			 * of the type we asked for (e.g. an A-only host
			 * queried for AAAA). Returning -1 here turned every
			 * NODATA case into a wrong SERVFAIL. */
			if (*rcode == DNS_RCODE_NOERROR)
				return 0;
			return -1;
		}

		int next_n = 0;

		for (int i = 0; i < ref.count && next_n < MAX_NS_CANDIDATES; i++)
			if (ref.has_addr[i])		//glue first, it's free
				snprintf(current[next_n++], INET_ADDRSTRLEN,
					 "%s", ref.ns_addr[i]);

		/* No glue at all. Resolve one NS name out of band -- one is
		 * enough to make progress and keeps the fan-out bounded. */
		if (next_n == 0) {
			for (int i = 0; i < ref.count; i++) {
				char addr[INET_ADDRSTRLEN];

				if (resolve_ns_addr(ref.ns_name[i], addr,
						    sizeof(addr), ns_depth))
					continue;

				snprintf(current[0], INET_ADDRSTRLEN, "%s", addr);
				next_n = 1;
				break;
			}
		}

		if (next_n == 0)
			return -1;

		ncurrent = next_n;
		snprintf(zone, sizeof(zone), "%s", ref.zone);
	}

	return -1;	//out of delegation budget
}

/* ---------------- entry point ---------------- */

int dns_resolve(const char *name, uint16_t qtype,
		struct dns_answer *ans, size_t cap, size_t *nans, int *rcode)
{
	/* Only A/AAAA under IN is implemented. Anything else gets a clean
	 * NOTIMP rather than a confusing empty NOERROR. */
	if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
		*nans = 0;
		*rcode = DNS_RCODE_NOTIMP;
		return 0;
	}

	if (dns_cache_get(name, qtype, ans, cap, nans, rcode))
		return 0;

	if (resolve_from(name, qtype, roots, nroots, ans, cap, nans, rcode,
			 0, 0)) {
		*nans = 0;
		*rcode = DNS_RCODE_SERVFAIL;
		return -1;
	}

	/* Cache successes and authoritative negatives. Never SERVFAIL --
	 * that's our failure, not a fact about the zone. NODATA (NOERROR
	 * with zero answers) is deliberately not cached here, same as
	 * before this change: it shares the negative-caching gap that
	 * already existed for other empty-but-not-NXDOMAIN cases. */
	if (*rcode == DNS_RCODE_NOERROR && *nans > 0)
		dns_cache_put(name, qtype, ans, *nans, *rcode);
	else if (*rcode == DNS_RCODE_NXDOMAIN)
		dns_cache_put(name, qtype, NULL, 0, *rcode);

	return 0;
}

void dns_resolver_stats(uint64_t *queries, uint64_t *timeouts)
{
	pthread_mutex_lock(&stat_lock);
	if (queries) *queries = upstream_queries;
	if (timeouts) *timeouts = upstream_timeouts;
	pthread_mutex_unlock(&stat_lock);
}