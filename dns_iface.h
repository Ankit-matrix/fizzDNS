#ifndef DNS_IFACE_H
#define DNS_IFACE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* The only header both halves share. A never includes B's internals,
 * B never includes xsk_setup.h. Freeze this and both sides can build. */

/* 512 = classic UDP DNS ceiling without EDNS0. With EDNS0 negotiated,
 * UDP responses can run up to DNS_EDNS_OUR_UDP_PAYLOAD (1232, see
 * dns_msg.h) instead -- this is sized for that plus header/OPT
 * headroom, and stays comfortably inside one UMEM frame (4096) once
 * L2/L3/L4 headers are added. */
#define DNS_MAX_MSG_LEN 1500

/* TCP has no realistic size limit of what this resolver ever builds --
 * DNS_MAX_ANSWERS bounds the record count, not the bytes -- but the
 * wire format caps a whole length-prefixed TCP message at 65535 (the
 * 2-byte length field), so that's the buffer size the TCP listener
 * uses for both the incoming query and the outgoing response. */
#define DNS_MAX_TCP_MSG_LEN 65535

enum dns_result{
	DNS_OK = 0,	//resp/resp_len hold something to send
	DNS_DROP = -1	//unanswerable, send nothing
};

/* Called once, from main, before any worker exists. */
int dns_backend_init(int num_workers);

/* Called from N worker threads at once, so it must be thread safe.
 * May block for as long as it likes; it is never on the packet path.
 * NXDOMAIN/SERVFAIL are normal DNS_OK returns with the rcode set --
 * DNS_DROP is only for input we can't answer at all.
 *
 * resp_cap is passed explicitly on purpose. Letting the callee assume
 * the frame size is how you get a UMEM overrun that shows up as
 * corruption in some unrelated frame three packets later. */

 /* Called from N worker threads at once, so it must be thread safe.
 * ...
 * is_udp tells the builder whether to apply any UDP size ceiling at
 * all (classic 512, or the EDNS-negotiated figure) -- TCP has no such
 * ceiling, its own length prefix is the only limit. */
int dns_resolve_query(const uint8_t *query, size_t query_len,
		      uint8_t *resp, size_t resp_cap, size_t *resp_len,
		      bool is_udp);

/* Called once, after every worker has joined. */
void dns_backend_fini(void);

#endif
