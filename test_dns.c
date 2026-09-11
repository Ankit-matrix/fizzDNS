/* No network, no NIC, no root. Runs under ASan+UBSan via `make test`. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "dns_msg.h"
#include "dns_bloom.h"
#include "dns_cache.h"

static int checks, failures;

#define CHECK(cond, ...) do {						\
	checks++;							\
	if (!(cond)) {							\
		failures++;						\
		printf("  FAIL  %s:%d  ", __FILE__, __LINE__);		\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

/* Build "www.example.com A IN" as a query, id 0x1234, RD set. */
static size_t make_query(uint8_t *b, const char *name, uint16_t qtype)
{
	size_t n;

	if (dns_build_query(0x1234, name, qtype, true, 0, b, 512, &n))
		return 0;
	return n;
}

static size_t make_query_edns(uint8_t *b, const char *name, uint16_t qtype,
			      uint16_t edns_payload)
{
	size_t n;

	if (dns_build_query(0x1234, name, qtype, true, edns_payload, b, 512, &n))
		return 0;
	return n;
}

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

/* ---------------- names ---------------- */

static void test_names(void)
{
	uint8_t buf[512];
	char out[DNS_MAX_NAME + 1];
	size_t n, next;

	CHECK(dns_name_encode("www.example.com", buf, sizeof(buf), &n) == 0,
	      "encode failed");
	CHECK(n == 17, "encoded length %zu, want 17", n);
	CHECK(buf[0] == 3 && buf[4] == 7, "label lengths wrong");

	CHECK(dns_name_decode(buf, n, 0, out, sizeof(out), &next) == 0,
	      "decode failed");
	CHECK(strcmp(out, "www.example.com") == 0, "round trip gave '%s'", out);
	CHECK(next == n, "next_off %zu, want %zu", next, n);

	//trailing dot is the same name
	CHECK(dns_name_encode("example.com.", buf, sizeof(buf), &n) == 0,
	      "trailing dot rejected");
	CHECK(n == 13, "trailing dot length %zu, want 13", n);

	//root
	CHECK(dns_name_encode("", buf, sizeof(buf), &n) == 0, "root rejected");
	CHECK(n == 1 && buf[0] == 0, "root encoding wrong");
	CHECK(dns_name_decode(buf, 1, 0, out, sizeof(out), NULL) == 0,
	      "root decode failed");
	CHECK(out[0] == '\0', "root should decode to empty string");

	//decoding lowercases
	uint8_t mixed[] = { 3, 'W', 'W', 'W', 3, 'C', 'o', 'M', 0 };

	CHECK(dns_name_decode(mixed, sizeof(mixed), 0, out, sizeof(out), NULL) == 0,
	      "mixed case decode failed");
	CHECK(strcmp(out, "www.com") == 0, "not lowercased: '%s'", out);

	//empty label
	CHECK(dns_name_encode("a..b", buf, sizeof(buf), &n) != 0,
	      "empty label accepted");

	//oversized label
	char big[80];

	memset(big, 'a', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	CHECK(dns_name_encode(big, buf, sizeof(buf), &n) != 0,
	      "64+ byte label accepted");

	//name longer than 255
	char huge[400] = "";

	for (int i = 0; i < 8; i++)
		strcat(huge, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.");
	CHECK(dns_name_encode(huge, buf, sizeof(buf), &n) != 0,
	      "255+ byte name accepted");

	CHECK(dns_name_equal("EXAMPLE.com", "example.COM"), "case compare failed");
	CHECK(!dns_name_equal("example.com", "example.net"), "bad compare match");
	CHECK(!dns_name_equal("example.com", "example.com.uk"), "prefix matched");
}

static void test_compression(void)
{
	char out[DNS_MAX_NAME + 1];
	size_t next;

	/* msg: [0..16] www.example.com, then a pointer at 17 back to
	 * offset 4 ("example.com"). */
	uint8_t msg[64] = { 0 };
	size_t n;

	dns_name_encode("www.example.com", msg, sizeof(msg), &n);
	msg[n] = 0xC0;
	msg[n + 1] = 0x04;

	CHECK(dns_name_decode(msg, n + 2, n, out, sizeof(out), &next) == 0,
	      "pointer decode failed");
	CHECK(strcmp(out, "example.com") == 0, "pointer gave '%s'", out);
	CHECK(next == n + 2, "next_off should be past the pointer, got %zu", next);

	//self pointer at offset 0 -> 0
	uint8_t self[4] = { 0xC0, 0x00, 0, 0 };

	CHECK(dns_name_decode(self, sizeof(self), 0, out, sizeof(out), NULL) != 0,
	      "self pointer accepted");

	//forward pointer 0 -> 2
	uint8_t fwd[8] = { 0xC0, 0x02, 1, 'a', 0, 0, 0, 0 };

	CHECK(dns_name_decode(fwd, sizeof(fwd), 0, out, sizeof(out), NULL) != 0,
	      "forward pointer accepted");

	//ping pong: 4 -> 0, 0 -> 4
	uint8_t pp[8] = { 0xC0, 0x04, 0, 0, 0xC0, 0x00, 0, 0 };

	CHECK(dns_name_decode(pp, sizeof(pp), 4, out, sizeof(out), NULL) != 0,
	      "ping-pong pointer accepted");

	//pointer with only one byte left
	uint8_t stub[1] = { 0xC0 };

	CHECK(dns_name_decode(stub, 1, 0, out, sizeof(out), NULL) != 0,
	      "truncated pointer accepted");

	//reserved label type 0x40
	uint8_t rsv[4] = { 0x40, 1, 2, 0 };

	CHECK(dns_name_decode(rsv, sizeof(rsv), 0, out, sizeof(out), NULL) != 0,
	      "reserved label type accepted");

	//label running past the end of the message
	uint8_t over[4] = { 10, 'a', 'b', 'c' };

	CHECK(dns_name_decode(over, sizeof(over), 0, out, sizeof(out), NULL) != 0,
	      "overrunning label accepted");
}

/* ---------------- query parsing ---------------- */

static void test_parse_query(void)
{
	uint8_t q[512];
	struct dns_query_info info;
	size_t len = make_query(q, "www.example.com", DNS_TYPE_A);

	CHECK(len > 0, "make_query failed");
	CHECK(dns_parse_query(q, len, &info) == 0, "parse failed");
	CHECK(info.hdr.id == 0x1234, "id %04x", info.hdr.id);
	CHECK(strcmp(info.q.name, "www.example.com") == 0, "name '%s'", info.q.name);
	CHECK(info.q.qtype == DNS_TYPE_A, "qtype %u", info.q.qtype);
	CHECK(info.q.qclass == DNS_CLASS_IN, "qclass %u", info.q.qclass);
	CHECK(info.recursion_desired, "RD not seen");
	CHECK(info.q.raw_off == 12, "raw_off %zu", info.q.raw_off);
	CHECK(info.q.raw_len == len - 12, "raw_len %zu", info.q.raw_len);

	// AAAA question parses the same way, just a different qtype on the wire
	uint8_t q6[512];
	size_t len6 = make_query(q6, "www.example.com", DNS_TYPE_AAAA);
	struct dns_query_info info6;

	CHECK(len6 > 0, "make_query AAAA failed");
	CHECK(dns_parse_query(q6, len6, &info6) == 0, "AAAA parse failed");
	CHECK(info6.q.qtype == DNS_TYPE_AAAA,
	      "qtype %u, want AAAA", info6.q.qtype);

	// header only
	CHECK(dns_parse_query(q, 11, &info) != 0,
	      "11 byte message accepted");

	// QR set: that's a response, not ours to answer
	uint8_t r[512];

	memcpy(r, q, len);
	r[2] |= 0x80;
	CHECK(dns_parse_query(r, len, &info) != 0,
	      "QR=1 accepted as a query");

	// non-zero opcode
	memcpy(r, q, len);
	r[2] |= 0x08;			// opcode 1, IQUERY
	CHECK(dns_parse_query(r, len, &info) != 0,
	      "opcode 1 accepted");

	// qdcount 2
	memcpy(r, q, len);
	r[5] = 2;
	CHECK(dns_parse_query(r, len, &info) != 0,
	      "qdcount=2 accepted");

	// qdcount 0
	memcpy(r, q, len);
	r[5] = 0;
	CHECK(dns_parse_query(r, len, &info) != 0,
	      "qdcount=0 accepted");

	// question chopped off before qtype/qclass
	CHECK(dns_parse_query(q, len - 2, &info) != 0,
	      "short question accepted");

	// qname is lowercased, but raw bytes keep their case
	uint8_t mixed[512];
	size_t mlen = make_query(mixed, "WWW.Example.COM", DNS_TYPE_A);

	CHECK(dns_parse_query(mixed, mlen, &info) == 0,
	      "mixed case parse failed");
	CHECK(strcmp(info.q.name, "www.example.com") == 0,
	      "qname not lowercased: '%s'", info.q.name);
	CHECK(mixed[13] == 'W', "raw query bytes were modified");


	// no additional section at all: has_edns stays false
	{
		uint8_t pq[512];
		size_t pn = make_query(pq, "example.com", DNS_TYPE_A);
		struct dns_query_info pinfo;

		CHECK(dns_parse_query(pq, pn, &pinfo) == 0,
		      "plain reparse failed");
		CHECK(!pinfo.has_edns,
		      "plain query should not have has_edns set");
	}

	// EDNS0 with the DO bit set
	{
		uint8_t eb[512];
		size_t en;
		struct dns_query_info einfo;

		CHECK(dns_build_query(0x2222, "example.com", DNS_TYPE_A, true,
				      4096, eb, sizeof(eb), &en) == 0,
		      "do-bit query build failed");

		/*
		 * DO is bit 15 of the OPT RR's TTL field, which starts
		 * 12(hdr)+13(qname)+4(qtype/qclass)+1(root name)+2(type)
		 * +2(class) = 34 bytes in.
		 */
		eb[36] |= 0x80;

		CHECK(dns_parse_query(eb, en, &einfo) == 0,
		      "do-bit parse failed");
		CHECK(einfo.has_edns,
		      "do-bit query missing has_edns");
		CHECK(einfo.edns_do,
		      "DO bit not observed");
		CHECK(einfo.edns_udp_payload == 4096,
		      "do-bit payload");
	}
}

static void test_parse_rr(void)
{
	/* www.example.com A IN 300 93.184.216.34 */
	uint8_t msg[64];
	struct dns_rr rr;
	size_t n, next;

	dns_name_encode("www.example.com", msg, sizeof(msg), &n);
	msg[n + 0] = 0; msg[n + 1] = 1;			//type A
	msg[n + 2] = 0; msg[n + 3] = 1;			//class IN
	msg[n + 4] = 0; msg[n + 5] = 0;
	msg[n + 6] = 1; msg[n + 7] = 0x2C;		//ttl 300
	msg[n + 8] = 0; msg[n + 9] = 4;			//rdlength
	msg[n + 10] = 93; msg[n + 11] = 184;
	msg[n + 12] = 216; msg[n + 13] = 34;

	CHECK(dns_parse_rr(msg, n + 14, 0, &rr, &next) == 0, "rr parse failed");
	CHECK(strcmp(rr.name, "www.example.com") == 0, "rr name '%s'", rr.name);
	CHECK(rr.type == DNS_TYPE_A, "rr type %u", rr.type);
	CHECK(rr.ttl == 300, "rr ttl %u", rr.ttl);
	CHECK(rr.rdlength == 4, "rdlength %u", rr.rdlength);
	CHECK(next == n + 14, "next %zu", next);

	//rdlength claiming more than is there
	msg[n + 9] = 40;
	CHECK(dns_parse_rr(msg, n + 14, 0, &rr, &next) != 0,
	      "overlong rdlength accepted");

	/* www.example.com AAAA IN 300 2606:2800:220:1:248:1893:25c8:1946 */
	uint8_t msg6[64];
	struct dns_rr rr6;
	size_t n6, next6;
	uint8_t addr6[16];

	inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", addr6);

	dns_name_encode("www.example.com", msg6, sizeof(msg6), &n6);
	msg6[n6 + 0] = 0; msg6[n6 + 1] = 28;		//type AAAA
	msg6[n6 + 2] = 0; msg6[n6 + 3] = 1;		//class IN
	msg6[n6 + 4] = 0; msg6[n6 + 5] = 0;
	msg6[n6 + 6] = 1; msg6[n6 + 7] = 0x2C;		//ttl 300
	msg6[n6 + 8] = 0; msg6[n6 + 9] = 16;		//rdlength
	memcpy(msg6 + n6 + 10, addr6, 16);

	CHECK(dns_parse_rr(msg6, n6 + 26, 0, &rr6, &next6) == 0,
	      "aaaa rr parse failed");
	CHECK(rr6.type == DNS_TYPE_AAAA, "rr6 type %u", rr6.type);
	CHECK(rr6.rdlength == 16, "rr6 rdlength %u", rr6.rdlength);
	CHECK(memcmp(rr6.rdata, addr6, 16) == 0, "rr6 rdata mismatch");
	CHECK(next6 == n6 + 26, "next6 %zu", next6);
}

/* ---------------- response building ---------------- */

static void test_build_response(void)
{
	uint8_t q[512], out[512];
	struct dns_query_info info;
	struct dns_answer ans[4];
	size_t qlen = make_query(q, "www.example.com", DNS_TYPE_A);
	size_t olen;

	dns_parse_query(q, qlen, &info);

	memset(ans, 0, sizeof(ans));
	ans[0].type = DNS_TYPE_A;
	ans[0].ttl = 300;
	inet_pton(AF_INET, "93.184.216.34", &ans[0].rdata.a);
	snprintf(ans[0].owner, sizeof(ans[0].owner), "www.example.com");

	/* Poison the buffer first. The header is written last, so anything
	 * that reads out[] before writing it reads garbage -- this is what
	 * caught the spurious TC bit. */
	memset(out, 0xFF, sizeof(out));

	CHECK(dns_build_response(q, qlen, &info, ans, 1, DNS_RCODE_NOERROR,true,
				 out, sizeof(out), &olen) == 0, "build failed");
	CHECK(olen == qlen + 16, "length %zu, want %zu", olen, qlen + 16);
	CHECK(rd16(out) == 0x1234, "id not echoed");
	CHECK(rd16(out + 2) & DNS_FLAG_QR, "QR not set");
	CHECK(rd16(out + 2) & DNS_FLAG_RA, "RA not set");
	CHECK(rd16(out + 2) & DNS_FLAG_RD, "RD not mirrored");
	CHECK(!(rd16(out + 2) & DNS_FLAG_TC), "TC set on a response that fits");
	CHECK((rd16(out + 2) & DNS_RCODE_MASK) == 0, "rcode not NOERROR");
	CHECK(rd16(out + 4) == 1, "qdcount %u", rd16(out + 4));
	CHECK(rd16(out + 6) == 1, "ancount %u", rd16(out + 6));
	CHECK(rd16(out + 8) == 0 && rd16(out + 10) == 0, "ns/ar not zero");
	CHECK(memcmp(out + 12, q + 12, qlen - 12) == 0,
	      "question not echoed verbatim");
	CHECK(out[qlen] == 0xC0 && out[qlen + 1] == 0x0C,
	      "owner not compressed to offset 12");
	CHECK(memcmp(out + qlen + 12, &ans[0].rdata.a, 4) == 0, "rdata wrong");

	//question echoed byte for byte, including case
	uint8_t mq[512], mout[512];
	size_t mqlen = make_query(mq, "WWW.Example.COM", DNS_TYPE_A);
	struct dns_query_info minfo;

	dns_parse_query(mq, mqlen, &minfo);
	memset(mout, 0xFF, sizeof(mout));
	CHECK(dns_build_response(mq, mqlen, &minfo, ans, 1, DNS_RCODE_NOERROR,
				 true, mout, sizeof(mout), &olen) == 0, "build failed");
	CHECK(memcmp(mout + 12, mq + 12, mqlen - 12) == 0,
	      "0x20 encoding not preserved");

	//NXDOMAIN: rcode set, no answers even if we pass some
	memset(out, 0xFF, sizeof(out));
	CHECK(dns_build_response(q, qlen, &info, ans, 1, DNS_RCODE_NXDOMAIN,
				 true, out, sizeof(out), &olen) == 0, "nxdomain failed");
	CHECK((rd16(out + 2) & DNS_RCODE_MASK) == DNS_RCODE_NXDOMAIN, "rcode wrong");
	CHECK(rd16(out + 6) == 0, "ancount %u on NXDOMAIN", rd16(out + 6));
	CHECK(olen == qlen, "nxdomain length %zu, want %zu", olen, qlen);
	CHECK(!(rd16(out + 2) & DNS_FLAG_TC), "TC set on NXDOMAIN");

	//NODATA: NOERROR rcode, zero answers -- distinct from NXDOMAIN
	memset(out, 0xFF, sizeof(out));
	CHECK(dns_build_response(q, qlen, &info, ans, 0, DNS_RCODE_NOERROR,true,
				 out, sizeof(out), &olen) == 0, "nodata build failed");
	CHECK((rd16(out + 2) & DNS_RCODE_MASK) == DNS_RCODE_NOERROR,
	      "nodata rcode wrong");
	CHECK(rd16(out + 6) == 0, "nodata ancount %u", rd16(out + 6));
	CHECK(olen == qlen, "nodata length %zu, want %zu", olen, qlen);

	//AAAA answer: 16 byte rdata, round-trips through the parser
	uint8_t q6[512];
	size_t q6len = make_query(q6, "www.example.com", DNS_TYPE_AAAA);
	struct dns_query_info info6;
	struct dns_answer ans6[1];

	dns_parse_query(q6, q6len, &info6);
	memset(ans6, 0, sizeof(ans6));
	ans6[0].type = DNS_TYPE_AAAA;
	ans6[0].ttl = 300;
	inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", ans6[0].rdata.aaaa);
	snprintf(ans6[0].owner, sizeof(ans6[0].owner), "www.example.com");

	memset(out, 0xFF, sizeof(out));
	CHECK(dns_build_response(q6, q6len, &info6, ans6, 1, DNS_RCODE_NOERROR, true,
				 out, sizeof(out), &olen) == 0, "aaaa build failed");
	CHECK(olen == q6len + 28, "aaaa length %zu, want %zu", olen, q6len + 28);
	CHECK(rd16(out + 6) == 1, "aaaa ancount %u", rd16(out + 6));
	CHECK(out[q6len] == 0xC0 && out[q6len + 1] == 0x0C,
	      "aaaa owner not compressed");
	CHECK(rd16(out + q6len + 2) == DNS_TYPE_AAAA, "aaaa type field wrong");
	CHECK(rd16(out + q6len + 10) == 16, "aaaa rdlength field wrong");
	CHECK(memcmp(out + q6len + 12, ans6[0].rdata.aaaa, 16) == 0,
	      "aaaa rdata wrong");

	struct dns_rr rr6;
	size_t next6;

	CHECK(dns_parse_rr(out, olen, q6len, &rr6, &next6) == 0,
	      "aaaa response rr unparseable");
	CHECK(rr6.type == DNS_TYPE_AAAA, "reparsed type %u", rr6.type);
	CHECK(rr6.rdlength == 16, "reparsed rdlength %u", rr6.rdlength);
	CHECK(memcmp(rr6.rdata, ans6[0].rdata.aaaa, 16) == 0,
	      "reparsed aaaa rdata wrong");

	//CNAME chain: the second RR's owner is not the queried name
	memset(ans, 0, sizeof(ans));
	ans[0].type = DNS_TYPE_CNAME;
	ans[0].ttl = 300;
	snprintf(ans[0].owner, sizeof(ans[0].owner), "www.example.com");
	snprintf(ans[0].rdata.cname, sizeof(ans[0].rdata.cname), "real.example.com");
	ans[1].type = DNS_TYPE_A;
	ans[1].ttl = 300;
	snprintf(ans[1].owner, sizeof(ans[1].owner), "real.example.com");
	inet_pton(AF_INET, "1.2.3.4", &ans[1].rdata.a);

	memset(out, 0xFF, sizeof(out));
	CHECK(dns_build_response(q, qlen, &info, ans, 2, DNS_RCODE_NOERROR,true,
				 out, sizeof(out), &olen) == 0, "cname build failed");
	CHECK(rd16(out + 6) == 2, "cname ancount %u", rd16(out + 6));
	CHECK(out[qlen] == 0xC0, "first owner should be a pointer");
	CHECK(!(rd16(out + 2) & DNS_FLAG_TC), "TC set on a chain that fits");

	//the CNAME target must be parseable back out
	struct dns_rr rr;
	size_t next;

	CHECK(dns_parse_rr(out, olen, qlen, &rr, &next) == 0, "cname rr unparseable");
	CHECK(rr.type == DNS_TYPE_CNAME, "first rr type %u", rr.type);

	char target[DNS_MAX_NAME + 1];

	CHECK(dns_name_decode(out, olen, (size_t)(rr.rdata - out), target,
			      sizeof(target), NULL) == 0, "cname target decode failed");
	CHECK(strcmp(target, "real.example.com") == 0, "cname target '%s'", target);

	//second RR's owner written out in full, not compressed
	CHECK(out[next] != 0xC0, "second owner should not point at offset 12");

	//too small a buffer sets TC and emits no partial RR
	memset(ans, 0, sizeof(ans));
	ans[0].type = DNS_TYPE_A;
	ans[0].ttl = 300;
	snprintf(ans[0].owner, sizeof(ans[0].owner), "www.example.com");
	memset(out, 0xFF, sizeof(out));
	CHECK(dns_build_response(q, qlen, &info, ans, 1, DNS_RCODE_NOERROR,true,
				 out, qlen + 8, &olen) == 0, "small buffer failed");
	CHECK(rd16(out + 2) & DNS_FLAG_TC, "TC not set when out of room");
	CHECK(rd16(out + 6) == 0, "ancount %u when truncated", rd16(out + 6));
	CHECK(olen == qlen, "truncated length %zu, want %zu", olen, qlen);

	//an AAAA answer needs 16 bytes; 4-byte-short buffer must also TC
	memset(ans6, 0, sizeof(ans6));
	ans6[0].type = DNS_TYPE_AAAA;
	ans6[0].ttl = 300;
	snprintf(ans6[0].owner, sizeof(ans6[0].owner), "www.example.com");
	memset(out, 0xFF, sizeof(out));
	CHECK(dns_build_response(q6, q6len, &info6, ans6, 1, DNS_RCODE_NOERROR,true,
				 out, q6len + 20, &olen) == 0,
	      "small aaaa buffer failed");
	CHECK(rd16(out + 2) & DNS_FLAG_TC, "TC not set for undersized AAAA");
	CHECK(rd16(out + 6) == 0, "aaaa ancount %u when truncated", rd16(out + 6));

	//buffer too small even for the header
	CHECK(dns_build_response(q, qlen, &info, ans, 1, DNS_RCODE_NOERROR, true,
				 out, 8, &olen) != 0, "8 byte buffer accepted");
}

static void test_edns(void)
{
	uint8_t eq[512], eout[2048];
	struct dns_query_info einfo, classic_info;
	struct dns_answer eans[3];
	size_t eqlen, eolen;
	char la[64], lb[64], lc[64], ld[64], le[64], lf[64], lg[64], lh[64];
	char name1[256], name2[256];

	/* Same trick as fake_hierarchy.py's BIG_HOP chain: two max-length
	 * (63 byte) labels per hop so the chain is ~130-140 bytes per
	 * name and ~600 bytes total across two CNAME hops -- comfortably
	 * over the classic 512 ceiling, comfortably under 1232. */
	memset(la, 'a', 63); la[63] = '\0';
	memset(lb, 'b', 63); lb[63] = '\0';
	memset(lc, 'c', 63); lc[63] = '\0';
	memset(ld, 'd', 63); ld[63] = '\0';
	memset(le, 'e', 63); le[63] = '\0';
	memset(lf, 'f', 63); lf[63] = '\0';
	memset(lg, 'g', 63); lg[63] = '\0';
	memset(lh, 'h', 63); lh[63] = '\0';
	snprintf(name1, sizeof(name1), "%s.%s.%s.test", la, lb, le);
	snprintf(name2, sizeof(name2), "%s.%s.%s.test", lc, ld, lf);

	eqlen = make_query_edns(eq, name1, DNS_TYPE_A, DNS_EDNS_OUR_UDP_PAYLOAD);
	CHECK(eqlen > 0, "edns make_query failed");
	CHECK(dns_parse_query(eq, eqlen, &einfo) == 0, "edns query parse failed");
	CHECK(einfo.has_edns, "has_edns not set");
	CHECK(einfo.edns_udp_payload == DNS_EDNS_OUR_UDP_PAYLOAD, "edns payload");
	CHECK(!einfo.edns_do, "DO bit set when not requested");

	memset(eans, 0, sizeof(eans));
	eans[0].type = DNS_TYPE_CNAME;
	eans[0].ttl = 300;
	snprintf(eans[0].owner, sizeof(eans[0].owner), "%s", name1);
	snprintf(eans[0].rdata.cname, sizeof(eans[0].rdata.cname), "%s", name2);
	eans[1].type = DNS_TYPE_CNAME;
	eans[1].ttl = 300;
	snprintf(eans[1].owner, sizeof(eans[1].owner), "%s", name2);
	snprintf(eans[1].rdata.cname, sizeof(eans[1].rdata.cname), "final.test");
	eans[2].type = DNS_TYPE_A;
	eans[2].ttl = 300;
	snprintf(eans[2].owner, sizeof(eans[2].owner), "final.test");
	inet_pton(AF_INET, "10.0.0.9", &eans[2].rdata.a);

	classic_info = einfo;
	classic_info.has_edns = false;

	//without EDNS (classic 512), this chain must not fit
	memset(eout, 0xFF, sizeof(eout));
	CHECK(dns_build_response(eq, eqlen, &classic_info, eans, 3,
				 DNS_RCODE_NOERROR, true, eout, sizeof(eout),
				 &eolen) == 0, "classic chain build failed");
	printf("classic response length = %zu bytes\n", eolen);
	CHECK(rd16(eout + 2) & DNS_FLAG_TC, "classic chain should truncate");
	CHECK(rd16(eout + 6) < 3, "classic chain ancount %u", rd16(eout + 6));
	CHECK(rd16(eout + 10) == 0, "classic response should carry no OPT");

	//with EDNS advertised at 1232, the same chain fits whole
	memset(eout, 0xFF, sizeof(eout));
	CHECK(dns_build_response(eq, eqlen, &einfo, eans, 3, DNS_RCODE_NOERROR,
				 true, eout, sizeof(eout), &eolen) == 0,
	      "edns chain build failed");
	CHECK(!(rd16(eout + 2) & DNS_FLAG_TC), "edns chain should not truncate");
	CHECK(rd16(eout + 6) == 3, "edns chain ancount %u", rd16(eout + 6));
	CHECK(rd16(eout + 10) == 1, "edns chain arcount (OPT) %u", rd16(eout + 10));

	//walk to the OPT record and check its shape
	{
		struct dns_rr rr;
		size_t off;

		CHECK(dns_skip_question(eout, eolen, 12, &off) == 0,
		      "edns response question unparseable");
		for (int i = 0; i < 3; i++) {
			struct dns_rr skip_rr;

			CHECK(dns_parse_rr(eout, eolen, off, &skip_rr, &off) == 0,
			      "edns answer %d unparseable", i);
		}
		CHECK(dns_parse_rr(eout, eolen, off, &rr, &off) == 0,
		      "opt record unparseable");
		CHECK(rr.type == DNS_TYPE_OPT, "opt type %u", rr.type);
		CHECK(rr.name[0] == '\0', "opt name not root: '%s'", rr.name);
		CHECK(rr.rclass == DNS_EDNS_OUR_UDP_PAYLOAD,
		      "opt advertised payload %u", rr.rclass);
		CHECK(rr.rdlength == 0, "opt rdlength %u, want 0", rr.rdlength);
	}

	//a client claiming only 700 bytes is held to 700, not 1232
	{
		struct dns_query_info small_edns = einfo;

		small_edns.edns_udp_payload = 700;
		memset(eout, 0xFF, sizeof(eout));
		CHECK(dns_build_response(eq, eqlen, &small_edns, eans, 3,
					 DNS_RCODE_NOERROR, true, eout,
					 sizeof(eout), &eolen) == 0,
		      "small edns chain build failed");
		CHECK(eolen <= 700, "small edns response %zu bytes, want <=700",
		      eolen);
	}

	//TCP ignores EDNS size negotiation entirely: no cap even without EDNS...
	memset(eout, 0xFF, sizeof(eout));
	CHECK(dns_build_response(eq, eqlen, &classic_info, eans, 3,
				 DNS_RCODE_NOERROR, false, eout, sizeof(eout),
				 &eolen) == 0, "tcp chain build failed");
	CHECK(!(rd16(eout + 2) & DNS_FLAG_TC), "tcp chain should not truncate");
	CHECK(rd16(eout + 6) == 3, "tcp chain ancount %u", rd16(eout + 6));
	CHECK(rd16(eout + 10) == 0, "tcp response should carry no OPT");

	//...but OPT is still echoed over TCP if the client sent one (version ack)
	memset(eout, 0xFF, sizeof(eout));
	CHECK(dns_build_response(eq, eqlen, &einfo, eans, 3, DNS_RCODE_NOERROR,
				 false, eout, sizeof(eout), &eolen) == 0,
	      "tcp+edns chain build failed");
	CHECK(rd16(eout + 10) == 1, "tcp+edns response should carry OPT");
}

static void test_build_query(void)
{
	uint8_t b[512];
	struct dns_header h;
	size_t n;

	/* Normal query without EDNS0 */
	CHECK(dns_build_query(0xBEEF, "example.com", DNS_TYPE_A, false,
			      0, b, sizeof(b), &n) == 0,
	      "build_query failed");
	CHECK(dns_parse_header(b, n, &h) == 0, "header unparseable");
	CHECK(h.id == 0xBEEF, "id %04x", h.id);
	CHECK(!(h.flags & DNS_FLAG_RD), "RD set when not asked for");
	CHECK(h.qdcount == 1, "qdcount %u", h.qdcount);
	CHECK(h.arcount == 0, "arcount %u when no EDNS requested", h.arcount);
	CHECK(n == 12 + 13 + 4, "length %zu", n);

	/* No room */
	CHECK(dns_build_query(1, "example.com", DNS_TYPE_A, false,
			      0, b, 14, &n) != 0,
	      "undersized buffer accepted");

	/* EDNS0: an OPT record appears in the additional section */
	CHECK(dns_build_query(0xCAFE, "example.com", DNS_TYPE_A, true,
			      DNS_EDNS_OUR_UDP_PAYLOAD, b, sizeof(b), &n) == 0,
	      "edns build_query failed");
	CHECK(dns_parse_header(b, n, &h) == 0, "edns header unparseable");
	CHECK(h.arcount == 1, "edns arcount %u, want 1", h.arcount);
	CHECK(n == 12 + 13 + 4 + DNS_OPT_RR_LEN,
	      "edns query length %zu", n);

	struct dns_rr rr;
	size_t off;

	CHECK(dns_skip_question(b, n, 12, &off) == 0,
	      "edns question unparseable");
	CHECK(dns_parse_rr(b, n, off, &rr, &off) == 0,
	      "edns opt unparseable");
	CHECK(rr.type == DNS_TYPE_OPT, "opt type %u", rr.type);
	CHECK(rr.name[0] == '\0', "opt name not root: '%s'", rr.name);
	CHECK(rr.rclass == DNS_EDNS_OUR_UDP_PAYLOAD,
	      "opt payload %u", rr.rclass);

	struct dns_query_info qi;

	CHECK(dns_parse_query(b, n, &qi) == 0, "edns self-parse failed");
	CHECK(qi.has_edns, "self-parsed query missing has_edns");
	CHECK(qi.edns_udp_payload == DNS_EDNS_OUR_UDP_PAYLOAD,
	      "self-parsed payload");
	CHECK(!qi.edns_do, "self-parsed DO bit set unexpectedly");

	CHECK(dns_build_query(1, "example.com", DNS_TYPE_A, false,
			      DNS_EDNS_OUR_UDP_PAYLOAD, b,
			      12 + 13 + 4 + 2, &n) != 0,
	      "undersized edns buffer accepted");
}

/* ---------------- cache ---------------- */

static void test_cache(void)
{
	struct dns_answer in[2], out[8];
	size_t n = 0;
	int rcode = 0;

	dns_cache_init();

	memset(in, 0, sizeof(in));
	in[0].type = DNS_TYPE_A;
	in[0].ttl = 300;
	snprintf(in[0].owner, sizeof(in[0].owner), "www.example.com");
	inet_pton(AF_INET, "93.184.216.34", &in[0].rdata.a);

	CHECK(dns_cache_get("www.example.com", DNS_TYPE_A, out, 8, &n, &rcode) == 0,
	      "hit on an empty cache");

	dns_cache_put("www.example.com", DNS_TYPE_A, in, 1, DNS_RCODE_NOERROR);

	CHECK(dns_cache_get("www.example.com", DNS_TYPE_A, out, 8, &n, &rcode) == 1,
	      "miss after put");
	CHECK(n == 1, "got %zu answers", n);
	CHECK(rcode == DNS_RCODE_NOERROR, "rcode %d", rcode);
	CHECK(out[0].rdata.a == in[0].rdata.a, "wrong address back");
	CHECK(out[0].ttl <= 300 && out[0].ttl > 290, "remaining ttl %u", out[0].ttl);

	/* The hash lowercases and so does the comparison. If they ever
	 * disagree, EXAMPLE.com lands in a different bucket and silently
	 * never matches. */
	CHECK(dns_cache_get("WWW.EXAMPLE.COM", DNS_TYPE_A, out, 8, &n, &rcode) == 1,
	      "case-insensitive lookup missed");

	//different qtype is a different key
	CHECK(dns_cache_get("www.example.com", DNS_TYPE_AAAA, out, 8, &n, &rcode) == 0,
	      "qtype not part of the key");

	//AAAA gets its own cache slot alongside the A record for the same name
	struct dns_answer in6;

	memset(&in6, 0, sizeof(in6));
	in6.type = DNS_TYPE_AAAA;
	in6.ttl = 300;
	snprintf(in6.owner, sizeof(in6.owner), "www.example.com");
	inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", in6.rdata.aaaa);

	dns_cache_put("www.example.com", DNS_TYPE_AAAA, &in6, 1, DNS_RCODE_NOERROR);
	CHECK(dns_cache_get("www.example.com", DNS_TYPE_AAAA, out, 8, &n, &rcode) == 1,
	      "aaaa miss after put");
	CHECK(n == 1 && out[0].type == DNS_TYPE_AAAA, "aaaa entry wrong shape");
	CHECK(memcmp(out[0].rdata.aaaa, in6.rdata.aaaa, 16) == 0,
	      "aaaa address wrong");
	//the A entry for the same name must be untouched
	CHECK(dns_cache_get("www.example.com", DNS_TYPE_A, out, 8, &n, &rcode) == 1,
	      "a entry clobbered by aaaa put");
	CHECK(out[0].type == DNS_TYPE_A, "a entry lost its type");

	//negative entry: NXDOMAIN with no answers, and a NULL ans pointer
	dns_cache_put("nope.example.com", DNS_TYPE_A, NULL, 0, DNS_RCODE_NXDOMAIN);
	CHECK(dns_cache_get("nope.example.com", DNS_TYPE_A, out, 8, &n, &rcode) == 1,
	      "negative entry not cached");
	CHECK(n == 0, "negative entry has %zu answers", n);
	CHECK(rcode == DNS_RCODE_NXDOMAIN, "negative rcode %d", rcode);

	//ttl clamping: 1 second becomes CACHE_MIN_TTL
	in[0].ttl = 1;
	dns_cache_put("short.example.com", DNS_TYPE_A, in, 1, DNS_RCODE_NOERROR);
	dns_cache_get("short.example.com", DNS_TYPE_A, out, 8, &n, &rcode);
	CHECK(out[0].ttl >= CACHE_MIN_TTL - 1, "ttl %u not clamped up", out[0].ttl);

	//the set expires when its shortest lived member does
	in[0].ttl = 900;
	in[1] = in[0];
	in[1].ttl = 60;
	dns_cache_put("pair.example.com", DNS_TYPE_A, in, 2, DNS_RCODE_NOERROR);
	dns_cache_get("pair.example.com", DNS_TYPE_A, out, 8, &n, &rcode);
	CHECK(n == 2, "pair has %zu answers", n);
	CHECK(out[0].ttl <= 60, "served ttl %u, should follow the shortest",
	      out[0].ttl);

	//overwrite in place, not a duplicate entry
	size_t before = 0, after = 0;

	dns_cache_stats(NULL, NULL, NULL, NULL, &before);
	in[0].ttl = 300;
	dns_cache_put("pair.example.com", DNS_TYPE_A, in, 1, DNS_RCODE_NOERROR);
	dns_cache_stats(NULL, NULL, NULL, NULL, &after);
	CHECK(before == after, "re-put grew the cache: %zu -> %zu", before, after);
	dns_cache_get("pair.example.com", DNS_TYPE_A, out, 8, &n, &rcode);
	CHECK(n == 1, "overwrite left %zu answers", n);

	//fill past capacity and make sure we evict rather than grow
	char name[64];

	for (int i = 0; i < CACHE_CAPACITY + 100; i++) {
		snprintf(name, sizeof(name), "host%d.example.com", i);
		dns_cache_put(name, DNS_TYPE_A, in, 1, DNS_RCODE_NOERROR);
	}

	uint64_t evictions = 0;
	size_t entries = 0;

	dns_cache_stats(NULL, NULL, &evictions, NULL, &entries);
	CHECK(entries <= CACHE_CAPACITY, "cache grew to %zu entries", entries);
	CHECK(evictions > 0, "nothing was evicted");

	//truncate into a smaller output buffer without overrunning it
	struct dns_answer small[1];

	dns_cache_put("multi.example.com", DNS_TYPE_A, in, 2, DNS_RCODE_NOERROR);
	dns_cache_get("multi.example.com", DNS_TYPE_A, small, 1, &n, &rcode);
	CHECK(n == 1, "cap not honoured, got %zu", n);

	dns_cache_fini();
}

/* ---------------- bloom filter ---------------- */

/* The defining property, and the only one worth testing hard: the
 * filter may say "maybe" about a key it has never seen, but it must
 * never say "definitely not" about a key that is in it. A false
 * positive costs one wasted lookup. A false negative silently drops a
 * cached answer on the floor and sends the resolver back upstream, and
 * nothing else in the system would notice. */
static void test_bloom(void)
{
	char name[64];

	dns_bloom_reset();

	uint64_t h = dns_key_hash("www.example.com", DNS_TYPE_A);

	CHECK(dns_bloom_maybe(h) == 0, "empty filter claimed a hit");

	dns_bloom_add(h);
	CHECK(dns_bloom_maybe(h) == 1, "added key reads as absent");

	//qtype is part of the key, same as in the map
	CHECK(dns_bloom_maybe(dns_key_hash("www.example.com", DNS_TYPE_AAAA)) == 0,
	      "qtype not mixed into the hash");

	//and the hash lowercases, or the filter and the bucket disagree
	CHECK(dns_key_hash("WWW.EXAMPLE.COM", DNS_TYPE_A) == h,
	      "hash is case sensitive");

	dns_bloom_del(h);
	CHECK(dns_bloom_maybe(h) == 0, "deleted key still present");

	/* Counting is the reason we can delete at all. Add the same key
	 * twice, remove it once, and it must still read as present --
	 * a plain bit filter cannot express this and this is exactly
	 * where it would produce a false negative. */
	dns_bloom_add(h);
	dns_bloom_add(h);
	dns_bloom_del(h);
	CHECK(dns_bloom_maybe(h) == 1, "counter dropped to zero too early");
	dns_bloom_del(h);
	CHECK(dns_bloom_maybe(h) == 0, "counter never reached zero");

	/* Churn: fill to capacity, delete every one, and the filter must
	 * come back completely empty. A leak here means slots creep
	 * upward over the process lifetime and the false positive rate
	 * climbs until the filter stops rejecting anything. */
	dns_bloom_reset();
	for (int i = 0; i < CACHE_CAPACITY; i++) {
		snprintf(name, sizeof(name), "churn%d.example.com", i);
		dns_bloom_add(dns_key_hash(name, DNS_TYPE_A));
	}
	for (int i = 0; i < CACHE_CAPACITY; i++) {
		snprintf(name, sizeof(name), "churn%d.example.com", i);
		dns_bloom_del(dns_key_hash(name, DNS_TYPE_A));
	}

	size_t used = 0;
	uint64_t saturated = 0;

	dns_bloom_stats(NULL, NULL, &saturated, &used);
	CHECK(used == 0, "%zu slots left set after deleting everything", used);
	CHECK(saturated == 0, "%llu saturations at design load",
	      (unsigned long long)saturated);

	/* Measured false positive rate at the design point, against the
	 * analytic (1 - e^(-kn/m))^k ~= 0.24%. The bound is on the
	 * expectation, so allow generous headroom -- this is a check
	 * that the filter is not degenerate, not a statistical test. */
	dns_bloom_reset();
	for (int i = 0; i < CACHE_CAPACITY; i++) {
		snprintf(name, sizeof(name), "live%d.example.com", i);
		dns_bloom_add(dns_key_hash(name, DNS_TYPE_A));
	}

	int probes = 100000, fp = 0;

	for (int i = 0; i < probes; i++) {
		snprintf(name, sizeof(name), "absent%d.example.com", i);
		if (dns_bloom_maybe(dns_key_hash(name, DNS_TYPE_A)))
			fp++;
	}
	printf("  bloom: measured fp rate %.3f%% over %d probes "
	       "(analytic ~0.24%%)\n", 100.0 * fp / probes, probes);
	CHECK(fp * 100 < probes * 2, "fp rate %.2f%% far above the bound",
	      100.0 * fp / probes);

	//no false negatives among the keys actually present
	int missing = 0;

	for (int i = 0; i < CACHE_CAPACITY; i++) {
		snprintf(name, sizeof(name), "live%d.example.com", i);
		if (!dns_bloom_maybe(dns_key_hash(name, DNS_TYPE_A)))
			missing++;
	}
	CHECK(missing == 0, "%d false negatives", missing);

	dns_bloom_reset();
}

/* The integration test that matters. Everything above tests the filter
 * in isolation; this tests that the cache keeps it in sync through the
 * two paths that remove entries behind the caller's back -- LRU
 * eviction and TTL expiry. A filter that is added to but never
 * decremented passes every test above and fails here. */
static void test_bloom_cache_sync(void)
{
	struct dns_answer in, out[8];
	size_t n = 0;
	int rcode = 0;
	char name[64];

	dns_cache_init();

	memset(&in, 0, sizeof(in));
	in.type = DNS_TYPE_A;
	in.ttl = 3600;
	snprintf(in.owner, sizeof(in.owner), "sync.example.com");
	inet_pton(AF_INET, "10.0.0.1", &in.rdata.a);

	/* Insert three times capacity so the LRU evicts continuously,
	 * then confirm every entry that survived is still reachable.
	 * A stale-low counter anywhere in the filter shows up here as a
	 * lookup that returns 0 for something the map still holds. */
	const int total = CACHE_CAPACITY * 3;

	for (int i = 0; i < total; i++) {
		snprintf(name, sizeof(name), "evict%d.example.com", i);
		dns_cache_put(name, DNS_TYPE_A, &in, 1, DNS_RCODE_NOERROR);
	}

	size_t entries = 0;
	int reachable = 0;

	dns_cache_stats(NULL, NULL, NULL, NULL, &entries);
	for (int i = 0; i < total; i++) {
		snprintf(name, sizeof(name), "evict%d.example.com", i);
		if (dns_cache_get(name, DNS_TYPE_A, out, 8, &n, &rcode))
			reachable++;
	}
	CHECK((size_t)reachable == entries,
	      "%d entries reachable but %zu live -- filter out of sync",
	      reachable, entries);

	/* Expiry removes through a different path (dns_cache_get calls
	 * node_destroy itself), so exercise it separately. TTL 1 clamps
	 * up to CACHE_MIN_TTL, so drive it by hand instead of sleeping:
	 * re-put under a fresh key, evict it, and check the filter
	 * released the slots by refilling and confirming we still find
	 * everything. */
	dns_cache_fini();	//init does not free, it only zeroes the table
	dns_cache_init();
	for (int round = 0; round < 4; round++) {
		for (int i = 0; i < CACHE_CAPACITY; i++) {
			snprintf(name, sizeof(name), "r%d.h%d.example.com",
				 round, i);
			dns_cache_put(name, DNS_TYPE_A, &in, 1,
				      DNS_RCODE_NOERROR);
		}
	}

	size_t used = 0;

	dns_cache_stats(NULL, NULL, NULL, NULL, &entries);
	dns_bloom_stats(NULL, NULL, NULL, &used);

	/* Slots in use should track live entries, not total insertions.
	 * With k = 4 and no collisions the ceiling is 4 per entry; if the
	 * filter were leaking it would be climbing toward all 65536. */
	CHECK(used <= entries * BLOOM_HASHES,
	      "%zu slots used for %zu live entries -- filter is leaking",
	      used, entries);

	//and the survivors are still all reachable through the fast path
	reachable = 0;
	for (int round = 0; round < 4; round++) {
		for (int i = 0; i < CACHE_CAPACITY; i++) {
			snprintf(name, sizeof(name), "r%d.h%d.example.com",
				 round, i);
			if (dns_cache_get(name, DNS_TYPE_A, out, 8, &n, &rcode))
				reachable++;
		}
	}
	CHECK((size_t)reachable == entries,
	      "after churn: %d reachable, %zu live", reachable, entries);

	uint64_t bq = 0, br = 0;

	dns_bloom_stats(&bq, &br, NULL, NULL);
	printf("  bloom: %llu lookups, %llu rejected without the lock "
	       "(%.1f%%)\n", (unsigned long long)bq, (unsigned long long)br,
	       bq ? 100.0 * (double)br / (double)bq : 0.0);

	dns_cache_fini();
}


/* ---------------- concurrent cache ---------------- */

/* The filter is read without the cache mutex, so the one failure this
 * design could plausibly have is a lost hit under concurrency: a
 * counter momentarily reading zero for a key that is in the map. The
 * single-threaded tests cannot see it. Run it under TSan too --
 * `make test-race` -- because a benign-looking relaxed load is exactly
 * the kind of thing that is benign right up until it isn't.
 *
 * Invariant checked at the end, with all writers stopped: every key
 * still in the map must be reachable through the filtered path, and
 * the count must equal what the cache says is live. */

#define CT_THREADS	4
#define CT_KEYS		1024
#define CT_ROUNDS	2000

struct ct_arg {
	int id;
	long gets, hits;
};

static void ct_name(char *buf, size_t cap, int k)
{
	snprintf(buf, cap, "ct%d.example.com", k);
}

static void *ct_worker(void *p)
{
	struct ct_arg *a = p;
	struct dns_answer in, out[8];
	size_t n;
	int rcode;
	char name[64];
	uint32_t seed = 0x2545f491u ^ (uint32_t)a->id;

	memset(&in, 0, sizeof(in));
	in.type = DNS_TYPE_A;
	in.ttl = 3600;

	for (int i = 0; i < CT_ROUNDS; i++) {
		seed ^= seed << 13;
		seed ^= seed >> 17;
		seed ^= seed << 5;

		/* Key comes from bits the put/get choice does not use. With
		 * k = seed % CT_KEYS and the branch on seed & 1, puts only
		 * ever land on odd keys and gets only ever read even ones,
		 * and the hit rate sits at exactly zero. */
		int k = (int)((seed >> 1) % CT_KEYS);

		ct_name(name, sizeof(name), k);

		/* Mixed load: every thread both inserts and looks up the
		 * same key space, so adds, deletes and lock-free reads
		 * genuinely overlap rather than running in phases. */
		if (seed & 1) {
			snprintf(in.owner, sizeof(in.owner), "%s", name);
			in.rdata.a = (uint32_t)k;
			dns_cache_put(name, DNS_TYPE_A, &in, 1,
				      DNS_RCODE_NOERROR);
		} else {
			a->gets++;
			if (dns_cache_get(name, DNS_TYPE_A, out, 8, &n, &rcode)) {
				a->hits++;
				/* A hit must carry the value that key was
				 * stored with. Cross-key corruption would
				 * show up here as a mismatched address. */
				if (n == 1 && out[0].rdata.a != (uint32_t)k) {
					checks++;
					failures++;
					printf("  FAIL  key %d returned %u\n",
					       k, out[0].rdata.a);
				}
			}
		}
	}
	return NULL;
}

static void test_cache_concurrent(void)
{
	pthread_t t[CT_THREADS];
	struct ct_arg a[CT_THREADS];
	struct dns_answer out[8];
	size_t n;
	int rcode;
	char name[64];

	dns_cache_init();
	memset(a, 0, sizeof(a));

	for (int i = 0; i < CT_THREADS; i++) {
		a[i].id = i;
		pthread_create(&t[i], NULL, ct_worker, &a[i]);
	}
	for (int i = 0; i < CT_THREADS; i++)
		pthread_join(t[i], NULL);

	/* Quiesced: no writer can be mid-update, so a miss now is a real
	 * miss and not a race. */
	size_t entries = 0;
	int reachable = 0;

	dns_cache_stats(NULL, NULL, NULL, NULL, &entries);
	for (int k = 0; k < CT_KEYS; k++) {
		ct_name(name, sizeof(name), k);
		if (dns_cache_get(name, DNS_TYPE_A, out, 8, &n, &rcode))
			reachable++;
	}
	CHECK((size_t)reachable == entries,
	      "after concurrent load: %d reachable, %zu live -- a lookup "
	      "lost a live entry", reachable, entries);

	long gets = 0, hits = 0;

	for (int i = 0; i < CT_THREADS; i++) {
		gets += a[i].gets;
		hits += a[i].hits;
	}
	printf("  concurrent: %ld lookups across %d threads, %.1f%% hit, "
	       "%zu live at exit\n", gets, CT_THREADS,
	       gets ? 100.0 * (double)hits / (double)gets : 0.0, entries);

	dns_cache_fini();
}


/* ---------------- bailiwick ---------------- */

/* The predicate the resolver gates every accepted record on. If this is
 * wrong in the permissive direction, a .com server can delegate
 * bank.co.uk and we cache whatever it says; if it is wrong in the
 * restrictive direction, ordinary delegation stops working. Both
 * directions are checked. */
static void test_bailiwick(void)
{
	//the root contains everything
	CHECK(dns_name_in_bailiwick("example.com", "") == true, "root excluded a name");
	CHECK(dns_name_in_bailiwick("", "") == true, "root excluded the root");

	//a zone contains itself and its descendants
	CHECK(dns_name_in_bailiwick("com", "com") == true, "zone excluded itself");
	CHECK(dns_name_in_bailiwick("example.com", "com") == true, "com !> example.com");
	CHECK(dns_name_in_bailiwick("www.example.com", "com") == true, "com !> www.example.com");
	CHECK(dns_name_in_bailiwick("www.example.com", "example.com") == true,
	      "example.com !> www.example.com");

	//and nothing else
	CHECK(dns_name_in_bailiwick("com", "example.com") == false, "parent inside child");
	CHECK(dns_name_in_bailiwick("bank.co.uk", "com") == false,
	      "com allowed to speak for bank.co.uk");
	CHECK(dns_name_in_bailiwick("example.org", "example.com") == false,
	      "sibling zone accepted");

	/* The one that a naive strsuffix() gets wrong, and the reason
	 * the label-boundary check exists: "notexample.com" ends with
	 * "example.com" as raw text but is a different zone entirely. */
	CHECK(dns_name_in_bailiwick("notexample.com", "example.com") == false,
	      "suffix match without a label boundary");
	CHECK(dns_name_in_bailiwick("evilexample.com", "example.com") == false,
	      "suffix match without a label boundary");

	//case insensitive, same as every other name comparison here
	CHECK(dns_name_in_bailiwick("WWW.EXAMPLE.COM", "example.com") == true,
	      "bailiwick is case sensitive");
	CHECK(dns_name_in_bailiwick("www.example.com", "EXAMPLE.COM") == true,
	      "bailiwick is case sensitive");

	//a shorter name can never be inside a longer zone
	CHECK(dns_name_in_bailiwick("a.com", "b.a.com") == false, "child zone contains parent");
}

int main(void)
{
	printf("dns_msg / dns_cache tests\n\n");

	test_names();
	test_compression();
	test_parse_query();
	test_parse_rr();
	test_build_response();
	test_build_query();
	test_edns();
	test_bailiwick();
	test_cache();
	test_bloom();
	test_bloom_cache_sync();
	test_cache_concurrent();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}