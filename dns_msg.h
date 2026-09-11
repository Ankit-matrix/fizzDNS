#ifndef DNS_MSG_H
#define DNS_MSG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RFC 1035 s3 and s4. Everything here is pure -- no sockets, no globals,
 * no allocation -- so it can be unit tested with no network at all.
 *
 * Every walker takes the message base AND its length and checks against
 * both. Compression means an offset can point back anywhere in the
 * message, so "I already checked this one" is never true for the next. */

#define DNS_MAX_NAME	255
#define DNS_MAX_LABEL	63
#define DNS_HDR_LEN	12
#define DNS_MAX_ANSWERS	8	//cap on the answer set we build

#define DNS_TYPE_A	1
#define DNS_TYPE_NS	2
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_AAAA	28

#define DNS_CLASS_IN	1

#define DNS_RCODE_NOERROR	0
#define DNS_RCODE_FORMERR	1
#define DNS_RCODE_SERVFAIL	2
#define DNS_RCODE_NXDOMAIN	3
#define DNS_RCODE_NOTIMP	4
#define DNS_RCODE_REFUSED	5

/* header flags, host order */
#define DNS_FLAG_QR	0x8000
#define DNS_FLAG_AA	0x0400
#define DNS_FLAG_TC	0x0200
#define DNS_FLAG_RD	0x0100
#define DNS_FLAG_RA	0x0080
#define DNS_OPCODE_MASK	0x7800
#define DNS_RCODE_MASK	0x000F

#define DNS_TYPE_OPT             41	/* EDNS0 pseudo-RR, RFC 6891 */

#define DNS_EDNS_VERSION           0	/* the only version we understand */
#define DNS_EDNS_MIN_PAYLOAD      512	/* RFC 6891 floor -- a requestor
					 * asking for less is clamped up */
#define DNS_EDNS_OUR_UDP_PAYLOAD 1232	/* what we advertise, and the
					 * ceiling we hold OURSELVES to
					 * even if a client claims to
					 * accept more -- the 2020 DNS
					 * flag day value, chosen to stay
					 * clear of IP fragmentation */
#define DNS_CLASSIC_UDP_LIMIT     512	/* RFC 1035 ceiling, used
					 * verbatim when the query carries
					 * no OPT record at all */
#define DNS_OPT_RR_LEN             11	/* root name(1)+type(2)+class(2)
					 * +ttl(4)+rdlength(2), no options */

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

/* raw_off/raw_len point back at the original bytes so the builder can
 * echo the question verbatim instead of re-encoding it. Re-encoding
 * normalises the case and breaks clients doing DNS-0x20. */
struct dns_question {
	char name[DNS_MAX_NAME + 1];	//lowercased, no trailing dot
	uint16_t qtype;
	uint16_t qclass;
	size_t raw_off;
	size_t raw_len;			//QNAME + QTYPE + QCLASS
};

struct dns_query_info {
	struct dns_header hdr;
	struct dns_question q;
	bool recursion_desired;

	/* EDNS0 (RFC 6891), parsed from an OPT RR in the additional
	 * section if the query carried one. */
	bool has_edns;
	uint16_t edns_udp_payload;	/* the OPT RR's "class" field */
	uint8_t  edns_version;		/* top byte of the "ttl" field */
	bool     edns_do;		/* DNSSEC-OK bit; accepted, ignored --
					 * we don't do DNSSEC validation */
};

/* rdata points INTO the caller's buffer, it is not copied */
struct dns_rr {
	char name[DNS_MAX_NAME + 1];
	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	uint16_t rdlength;
	const uint8_t *rdata;
};

/* an RR we intend to emit -- owns its data */
struct dns_answer {
	uint16_t type;				//A, AAAA, or CNAME
	uint32_t ttl;
	union {
		uint32_t a;			//be32
		uint8_t aaaa[16];		//be128, network byte order
		char cname[DNS_MAX_NAME + 1];
	} rdata;
	char owner[DNS_MAX_NAME + 1];
};

/* ---- parsing ---- */

/* Decode a possibly compressed name at off. out gets the dotted
 * lowercase form, root is the empty string. *next_off is the offset
 * past the name in the ORIGINAL stream, i.e. past the two pointer
 * bytes, not past the target. Jump count is bounded. */
int dns_name_decode(const uint8_t *msg, size_t len, size_t off,
		    char *out, size_t out_cap, size_t *next_off);

int dns_parse_header(const uint8_t *msg, size_t len, struct dns_header *out);
int dns_parse_query(const uint8_t *msg, size_t len, struct dns_query_info *out);
int dns_skip_question(const uint8_t *msg, size_t len, size_t off, size_t *next);
int dns_parse_rr(const uint8_t *msg, size_t len, size_t off,
		 struct dns_rr *rr, size_t *next);

/* ---- building ---- */

int dns_name_encode(const char *name, uint8_t *out, size_t cap, size_t *written);

/* Echoes the question from `query`, appends nans answers, sets QR/RA
 * and rcode. nans=0 with a non-zero rcode gives NXDOMAIN/SERVFAIL. */
int dns_build_response(const uint8_t *query, size_t query_len,
		       const struct dns_query_info *q,
		       const struct dns_answer *ans, size_t nans, int rcode,
		       bool is_udp,
		       uint8_t *out, size_t cap, size_t *out_len);

/* edns_udp_payload == 0 means "don't attach an OPT record at all". */
int dns_build_query(uint16_t id, const char *name, uint16_t qtype, bool rd,
		    uint16_t edns_udp_payload,
		    uint8_t *out, size_t cap, size_t *out_len);

bool dns_name_equal(const char *a, const char *b);	//case insensitive, RFC 4343

/* True if `name` is `zone` itself or a subdomain of it; the root zone
 * is the empty string and contains everything. This is the predicate
 * the resolver gates every accepted record on -- see resolver.c. */
bool dns_name_in_bailiwick(const char *name, const char *zone);

#endif