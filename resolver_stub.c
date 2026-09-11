#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "dns_iface.h"

/* dns_iface.h with zero upstream I/O: every query gets an immediate A
 * record pointing at a fixed address.
 *
 * Two reasons it exists. One, A can build and debug the whole XDP path
 * before B has written a line. Two -- and this is the important one --
 * it is the only configuration in which the AF_XDP vs UDP comparison
 * actually measures the transport. With a real iterative resolver in
 * the loop, per-query latency is ~1s of upstream network time and the
 * tens of microseconds the packet path contributes vanish into the
 * noise; you end up measuring root server variance and calling it a
 * kernel bypass result.
 *
 * STUB_DELAY_US injects synthetic latency, so you can sweep for the
 * crossover where resolution cost starts to dominate transport cost.
 * That curve is a better result than either single number. */

#define DNS_HDR_LEN	12
#define STUB_ANSWER_IP	"10.0.0.1"
#define STUB_TTL	300

static uint32_t stub_addr;
static long stub_delay_us;

int dns_backend_init(int num_workers)
{
	const char *ip = getenv("STUB_ANSWER_IP");
	const char *delay = getenv("STUB_DELAY_US");

	if (!ip)
		ip = STUB_ANSWER_IP;
	if (inet_pton(AF_INET, ip, &stub_addr) != 1) {
		fprintf(stderr, "stub: bad STUB_ANSWER_IP '%s'\n", ip);
		return -1;
	}

	stub_delay_us = delay ? strtol(delay, NULL, 10) : 0;

	printf("stub resolver: %d workers, answering %s", num_workers, ip);
	if (stub_delay_us)
		printf(", %ld us synthetic delay", stub_delay_us);
	printf("\n");
	return 0;
}

/* Walk the QNAME and return the offset past QTYPE/QCLASS, i.e. the
 * length of header + question. 0 means malformed. */
static size_t question_end(const uint8_t *msg, size_t len)
{
	size_t off = DNS_HDR_LEN;

	while (off < len) {
		uint8_t l = msg[off];

		if (l == 0) {
			off += 1;
			if (off + 4 > len)	//QTYPE + QCLASS
				return 0;
			return off + 4;
		}
		if (l & 0xC0)		//pointers are illegal in a question
			return 0;
		off += 1 + l;
	}
	return 0;
}

int dns_resolve_query(const uint8_t *query, size_t query_len,
		      uint8_t *resp, size_t resp_cap, size_t *resp_len,
		      bool is_udp)
{
	(void) is_udp;/* the stub answers identically either way -- it
			 * isolates the transport layer, it doesn't
			 * exercise EDNS/TCP size negotiation. */
	size_t qend, need;
	uint16_t flags;
	uint8_t *a;

	if (query_len < DNS_HDR_LEN)
		return DNS_DROP;

	qend = question_end(query, query_len);
	if (!qend)
		return DNS_DROP;

	/* header + question + ptr 2 + type 2 + class 2 + ttl 4 +
	 * rdlength 2 + rdata 4 */
	need = qend + 16;
	if (need > resp_cap)
		return DNS_DROP;

	if (stub_delay_us) {
		struct timespec ts = {
			.tv_sec  = stub_delay_us / 1000000,
			.tv_nsec = (stub_delay_us % 1000000) * 1000,
		};
		nanosleep(&ts, NULL);
	}

	memcpy(resp, query, qend);

	flags = (uint16_t)((resp[2] << 8) | resp[3]);
	flags |= 0x8000;		//QR
	flags |= 0x0080;		//RA
	flags &= (uint16_t)~0x7800;	//opcode = QUERY
	flags &= (uint16_t)~0x000F;	//rcode = NOERROR
	resp[2] = (uint8_t)(flags >> 8);
	resp[3] = (uint8_t)flags;

	resp[6] = 0; resp[7] = 1;	//ancount
	resp[8] = 0; resp[9] = 0;	//nscount
	resp[10] = 0; resp[11] = 0;	//arcount

	a = resp + qend;
	a[0] = 0xC0; a[1] = 0x0C;	//name -> offset 12
	a[2] = 0x00; a[3] = 0x01;	//A
	a[4] = 0x00; a[5] = 0x01;	//IN
	a[6] = (uint8_t)(STUB_TTL >> 24); a[7] = (uint8_t)(STUB_TTL >> 16);
	a[8] = (uint8_t)(STUB_TTL >> 8);  a[9] = (uint8_t)STUB_TTL;
	a[10] = 0x00; a[11] = 0x04;	//rdlength
	memcpy(a + 12, &stub_addr, 4);

	*resp_len = need;
	return DNS_OK;
}

void dns_backend_fini(void)
{
}
