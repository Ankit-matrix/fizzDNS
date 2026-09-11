#ifndef DNS_TCP_H
#define DNS_TCP_H

#include <stdint.h>

/* DNS-over-TCP listener, shared by both transports (server.c and
 * af_xdp_user.c).
 *
 * The AF_XDP kernel filter (af_xdp_kern.c) only ever redirects IPv4/
 * UDP/dport-53 packets into the xsk -- a TCP SYN on port 53 takes
 * XDP_PASS and lands on the ordinary kernel network stack, exactly as
 * it would on a box running no XDP program at all. So this listener
 * is a completely normal blocking TCP server: it doesn't touch
 * AF_XDP, UMEM, or any ring, and doesn't need anything from
 * xsk_setup.h. Bind it once and it works unmodified whichever binary
 * links it in.
 *
 * One thread accepts; each accepted connection gets its own thread,
 * bounded by DNS_TCP_MAX_CONNS. A resolve can block for ~1s of
 * upstream walk, and RFC 7766 lets a client pipeline more than one
 * query per connection, so serialising every TCP client through a
 * small fixed worker pool would let one slow resolve head-of-line
 * block every other TCP client behind it. Thread-per-connection avoids
 * that at the cost of a bounded number of threads, which is fine at
 * the connection volumes TCP fallback actually sees: TCP is the
 * exception path for oversized answers, not the bulk transport. */

#define DNS_TCP_MAX_CONNS 128

struct dns_tcp_server;

/* Starts the accept thread and returns immediately; NULL on failure
 * (bind/listen/thread-create failures are logged to stderr with the
 * reason). dns_backend_init() must already have been called --
 * connections are served as soon as they arrive, from the calling
 * process's shared resolver/cache state. */
struct dns_tcp_server *dns_tcp_server_start(int port);

/* Signals every open connection to unblock (via shutdown(), not a
 * forceful close, so a reply already queued still gets a chance to go
 * out) and joins the accept thread. Safe to call once; *srv is invalid
 * afterwards. Read stats before calling this, not after. */
void dns_tcp_server_stop(struct dns_tcp_server *srv);

void dns_tcp_server_stats(const struct dns_tcp_server *srv,
			  uint64_t *accepted, uint64_t *rejected,
			  uint64_t *queries, uint64_t *answered);

#endif