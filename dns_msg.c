#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>

#include "dns_msg.h"

/* Pointers can chain. A crafted message can point at itself, so bound
 * the jumps instead of trusting the data. A legal name has at most 128
 * labels so 32 is already generous. */
#define MAX_PTR_JUMPS 32

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xFF);
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* ---------------- names ---------------- */

int dns_name_decode(const uint8_t *msg, size_t len, size_t off,
		    char *out, size_t out_cap, size_t *next_off)
{
	size_t written = 0, after = 0;
	int jumps = 0;
	bool jumped = false;

	if (!out || out_cap == 0)
		return -1;
	out[0] = '\0';

	for (;;) {
		if (off >= len)
			return -1;

		uint8_t l = msg[off];

		if (l == 0) {			//end of name
			if (!jumped)
				after = off + 1;
			break;
		}

		if ((l & 0xC0) == 0xC0) {	//compression pointer
			if (off + 1 >= len)
				return -1;
			if (++jumps > MAX_PTR_JUMPS)
				return -1;

			size_t target = ((size_t)(l & 0x3F) << 8) | msg[off + 1];

			if (!jumped) {
				after = off + 2;
				jumped = true;
			}
			/* Must point strictly backwards. Forward and self
			 * pointers are the classic decompression loop;
			 * refusing them is cheaper than cycle detection. */
			if (target >= off)
				return -1;
			off = target;
			continue;
		}

		if (l & 0xC0)			//0x40/0x80 are reserved
			return -1;
		if (l > DNS_MAX_LABEL)
			return -1;
		if (off + 1 + l > len)
			return -1;

		if (written + (written ? 1 : 0) + l + 1 > out_cap)
			return -1;
		if (written + l > DNS_MAX_NAME)
			return -1;

		if (written)
			out[written++] = '.';
		for (uint8_t i = 0; i < l; i++)
			out[written++] = (char)tolower(msg[off + 1 + i]);

		off += 1 + l;
	}

	out[written] = '\0';
	if (next_off)
		*next_off = after;
	return 0;
}

int dns_name_encode(const char *name, uint8_t *out, size_t cap, size_t *written)
{
	const char *p = name;
	size_t o = 0;

	/* root, or a bare trailing dot */
	if (!name || !*name || (name[0] == '.' && name[1] == '\0')) {
		if (cap < 1)
			return -1;
		out[0] = 0;
		*written = 1;
		return 0;
	}

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		if (l == 0 || l > DNS_MAX_LABEL)
			return -1;
		if (o + 1 + l + 1 > cap)
			return -1;

		out[o++] = (uint8_t)l;
		for (size_t i = 0; i < l; i++)
			out[o++] = (uint8_t)p[i];

		if (!dot)
			break;
		p = dot + 1;
		if (!*p)		//"example.com."
			break;
	}

	if (o + 1 > cap)
		return -1;
	out[o++] = 0;

	if (o > DNS_MAX_NAME + 1)
		return -1;

	*written = o;
	return 0;
}

bool dns_name_equal(const char *a, const char *b)
{
	while (*a && *b) {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return false;
		a++;
		b++;
	}
	return *a == *b;
}

/* ---------------- parsing ---------------- */

int dns_parse_header(const uint8_t *msg, size_t len, struct dns_header *h)
{
	if (len < DNS_HDR_LEN)
		return -1;

	h->id      = rd16(msg + 0);
	h->flags   = rd16(msg + 2);
	h->qdcount = rd16(msg + 4);
	h->ancount = rd16(msg + 6);
	h->nscount = rd16(msg + 8);
	h->arcount = rd16(msg + 10);
	return 0;
}

int dns_skip_question(const uint8_t *msg, size_t len, size_t off, size_t *next)
{
	char scratch[DNS_MAX_NAME + 1];
	size_t after;

	if (dns_name_decode(msg, len, off, scratch, sizeof(scratch), &after))
		return -1;
	if (after + 4 > len)
		return -1;

	*next = after + 4;
	return 0;
}

int dns_parse_query(const uint8_t *msg, size_t len, struct dns_query_info *out)
{
	size_t after;

	memset(out, 0, sizeof(*out));

	if (dns_parse_header(msg, len, &out->hdr))
		return -1;
	if (out->hdr.flags & DNS_FLAG_QR)	//a response is not ours to answer
		return -1;
	if (out->hdr.flags & DNS_OPCODE_MASK)	//standard QUERY only
		return -1;
	if (out->hdr.qdcount != 1)
		return -1;

	if (dns_name_decode(msg, len, DNS_HDR_LEN, out->q.name,
			    sizeof(out->q.name), &after))
		return -1;
	if (after + 4 > len)
		return -1;

	out->q.qtype   = rd16(msg + after);
	out->q.qclass  = rd16(msg + after + 2);
	out->q.raw_off = DNS_HDR_LEN;
	out->q.raw_len = (after + 4) - DNS_HDR_LEN;

	out->recursion_desired = (out->hdr.flags & DNS_FLAG_RD) != 0;
	/* EDNS0 (RFC 6891): an OPT pseudo-RR in the additional section.
	 * This resolver only ever supports one question per message, so
	 * we only look at the first additional record. A malformed or
	 * absent one just means "no EDNS" -- it does not fail the whole
	 * query, since EDNS is optional by definition. */
	if (out->hdr.arcount >= 1) {
		struct dns_rr opt;
		size_t opt_next;
		size_t arr_off = after + 4;

		if (dns_parse_rr(msg, len, arr_off, &opt, &opt_next) == 0 &&
		    opt.type == DNS_TYPE_OPT && opt.name[0] == '\0') {
			out->has_edns = true;
			out->edns_udp_payload = opt.rclass;
			out->edns_version = (uint8_t)((opt.ttl >> 16) & 0xFF);
			out->edns_do = (opt.ttl & 0x8000) != 0;
		}
	}

	out->recursion_desired = (out->hdr.flags & DNS_FLAG_RD) != 0;
	return 0;
}

int dns_parse_rr(const uint8_t *msg, size_t len, size_t off,
		 struct dns_rr *rr, size_t *next)
{
	size_t after;

	if (dns_name_decode(msg, len, off, rr->name, sizeof(rr->name), &after))
		return -1;
	if (after + 10 > len)
		return -1;

	rr->type     = rd16(msg + after);
	rr->rclass   = rd16(msg + after + 2);
	rr->ttl      = rd32(msg + after + 4);
	rr->rdlength = rd16(msg + after + 8);

	if (after + 10 + rr->rdlength > len)
		return -1;

	rr->rdata = msg + after + 10;
	*next = after + 10 + rr->rdlength;
	return 0;
}

/* ---------------- building ---------------- */

int dns_build_response(const uint8_t *query, size_t query_len,
		       const struct dns_query_info *q,
		       const struct dns_answer *ans, size_t nans, int rcode,
		       bool is_udp,
		       uint8_t *out, size_t cap, size_t *out_len)
{
	size_t o = DNS_HDR_LEN, emitted = 0;
	bool truncated = false;
	uint16_t flags;
	uint16_t arcount = 0;

	if (cap < DNS_HDR_LEN)
		return -1;
	if (q->q.raw_off + q->q.raw_len > query_len)
		return -1;
	if (o + q->q.raw_len > cap)
		return -1;

	memcpy(out + o, query + q->q.raw_off, q->q.raw_len);
	o += q->q.raw_len;

	/* EDNS0 (RFC 6891). No OPT from the client -> stay at the
	 * classic 512 byte ceiling; that limit predates EDNS and a
	 * client that never asked for more can't be assumed to handle
	 * more. A client that DOES send OPT gets up to
	 * DNS_EDNS_OUR_UDP_PAYLOAD, clamped down further if it asked for
	 * less -- but never further UP than our own advertised figure,
	 * regardless of how large the client claims to accept, so we
	 * never risk IP fragmentation on our own reply. TCP has no such
	 * ceiling at all: its own 2 byte length prefix is the only
	 * limit, so is_udp short-circuits every bit of this. */
	size_t effective_cap = cap;

	if (is_udp) {
		effective_cap = DNS_CLASSIC_UDP_LIMIT;

		if (q->has_edns) {
			uint16_t theirs = q->edns_udp_payload;

			if (theirs < DNS_EDNS_MIN_PAYLOAD)
				theirs = DNS_EDNS_MIN_PAYLOAD;
			effective_cap = theirs < DNS_EDNS_OUR_UDP_PAYLOAD
				       ? theirs : DNS_EDNS_OUR_UDP_PAYLOAD;
		}
		if (effective_cap > cap)
			effective_cap = cap;
	}

	/* Reserve room for our own OPT record up front so the answer
	 * loop below never eats the space it needs. */
	size_t ans_cap = effective_cap;

	if (q->has_edns) {
		ans_cap = effective_cap > DNS_OPT_RR_LEN
			? effective_cap - DNS_OPT_RR_LEN : o;
	}

	for (size_t i = 0; i < nans && rcode == DNS_RCODE_NOERROR; i++) {
		size_t start = o, rdlen_at, n;

		if (dns_name_equal(ans[i].owner, q->q.name)) {
			if (o + 2 > ans_cap)
				goto full;
			out[o++] = 0xC0;
			out[o++] = 0x0C;
		} else {
			if (dns_name_encode(ans[i].owner, out + o, ans_cap - o, &n))
				goto full;
			o += n;
		}

		if (o + 10 > ans_cap)
			goto full;

		wr16(out + o, ans[i].type);	o += 2;
		wr16(out + o, DNS_CLASS_IN);	o += 2;
		wr32(out + o, ans[i].ttl);	o += 4;
		rdlen_at = o;			o += 2;

		if (ans[i].type == DNS_TYPE_A) {
			if (o + 4 > ans_cap)
				goto full;
			memcpy(out + o, &ans[i].rdata.a, 4);
			o += 4;
			wr16(out + rdlen_at, 4);
		} else if (ans[i].type == DNS_TYPE_AAAA) {
			if (o + 16 > ans_cap)
				goto full;
			memcpy(out + o, ans[i].rdata.aaaa, 16);
			o += 16;
			wr16(out + rdlen_at, 16);
		} else if (ans[i].type == DNS_TYPE_CNAME) {
			if (dns_name_encode(ans[i].rdata.cname, out + o,
					    ans_cap - o, &n))
				goto full;
			o += n;
			wr16(out + rdlen_at, (uint16_t)n);
		} else {
			o = start;
			continue;
		}

		emitted++;
		continue;
full:
		o = start;
		truncated = true;
		break;
	}

	/* Echo an OPT record back whenever the query carried one --
	 * over UDP AND over TCP (a TCP client can send EDNS purely for
	 * version negotiation; the size field just isn't meaningful
	 * there). Space for it was already reserved above for the UDP
	 * case, and for TCP effective_cap == cap so there's essentially
	 * always room. */
	if (q->has_edns && o + DNS_OPT_RR_LEN <= effective_cap) {
		out[o++] = 0x00;			//root name
		wr16(out + o, DNS_TYPE_OPT);	o += 2;
		wr16(out + o, DNS_EDNS_OUR_UDP_PAYLOAD); o += 2;
		uint32_t opt_ttl = q->edns_do ? 0x00008000U : 0;
		wr32(out + o, opt_ttl);	//ext-rcode=0, version=0, flags=0 (no DO)
		o += 4;
		wr16(out + o, 0);	//rdlength: we carry no options
		o += 2;
		arcount = 1;
	}

	flags = DNS_FLAG_QR | DNS_FLAG_RA;
	if (q->recursion_desired)
		flags |= DNS_FLAG_RD;
	if (truncated)
		flags |= DNS_FLAG_TC;
	flags |= (uint16_t)(rcode & DNS_RCODE_MASK);

	wr16(out + 0, q->hdr.id);
	wr16(out + 2, flags);
	wr16(out + 4, 1);
	wr16(out + 6, (uint16_t)emitted);
	wr16(out + 8, 0);
	wr16(out + 10, arcount);

	*out_len = o;
	return 0;
}

int dns_build_query(uint16_t id, const char *name, uint16_t qtype, bool rd,
		    uint16_t edns_udp_payload, uint8_t *out, size_t cap,
		    size_t *out_len)
{
	size_t n, o;

	if (cap < DNS_HDR_LEN)
		return -1;

	wr16(out + 0, id);
	wr16(out + 2, rd ? DNS_FLAG_RD : 0);
	wr16(out + 4, 1);
	wr16(out + 6, 0);
	wr16(out + 8, 0);
	wr16(out + 10, edns_udp_payload ? 1 : 0);

	if (dns_name_encode(name, out + DNS_HDR_LEN, cap - DNS_HDR_LEN, &n))
		return -1;

	o = DNS_HDR_LEN + n;
	if (o + 4 > cap)
		return -1;

	wr16(out + o, qtype);		o += 2;
	wr16(out + o, DNS_CLASS_IN);	o += 2;

	if (edns_udp_payload) {
		if (o + DNS_OPT_RR_LEN > cap)
			return -1;
		out[o++] = 0x00;			//root name
		wr16(out + o, DNS_TYPE_OPT);	o += 2;
		wr16(out + o, edns_udp_payload); o += 2;
		wr32(out + o, 0);			//ext-rcode/version/flags = 0
		o += 4;
		wr16(out + o, 0);			//rdlength: no options
		o += 2;
	}

	*out_len = o;

	// for (size_t i = 0; i < en; i++) {
	// 	printf("%02x%s", eb[i], (i + 1) % 16 == 0 ? "\n" : " ");
	// }
	// printf("\n");
	return 0;
}

bool dns_name_in_bailiwick(const char *name, const char *zone)
{
	if (!name || !zone)
		return false;
	if (!*zone)			//root contains everything
		return true;

	size_t nl = strlen(name), zl = strlen(zone);

	if (nl == zl)
		return dns_name_equal(name, zone);
	if (nl < zl + 2)		//needs at least one label plus a dot
		return false;

	/* Compare against a label boundary, not a raw suffix: without the
	 * dot check, "notexample.com" would test as being inside
	 * "example.com". */
	return name[nl - zl - 1] == '.' && dns_name_equal(name + nl - zl, zone);
}
