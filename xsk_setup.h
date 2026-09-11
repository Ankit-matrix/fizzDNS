#ifndef XSK_SETUP_H
#define XSK_SETUP_H

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <net/if.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

/* Everything to do with bringing an AF_XDP socket into existence: UMEM,
 * the four rings, the frame allocator, and attaching the XDP program.
 * af_xdp_user.c includes this and never calls libxdp directly. */

#define NUM_FRAMES		4096
#define FRAME_SIZE		XSK_UMEM__DEFAULT_FRAME_SIZE	//4096
#define INVALID_UMEM_FRAME	UINT64_MAX

/* Frames handed to the kernel up front for RX; the rest stay in the
 * free list as the TX pool. This split only works because we copy the
 * query out and recycle the frame immediately -- holding a frame for
 * the ~1s an iterative resolve takes would starve the fill ring at a
 * few hundred concurrent queries and the NIC would start dropping. */
#define FILL_RING_FRAMES	(NUM_FRAMES / 2)

#define RX_BATCH_SIZE		64
#define TX_BATCH_SIZE		64

/* Mirror of enum xdp_dns_stat in af_xdp_kern.c. Keep in sync. */
enum xdp_dns_stat{
	STAT_TOTAL = 0,
	STAT_NOT_IPV4,
	STAT_NOT_UDP,
	STAT_NOT_DNS_PORT,
	STAT_MALFORMED,
	STAT_NOT_QUERY,
	STAT_REDIRECTED,
	STAT__MAX,
};

extern const char *const xdp_dns_stat_names[STAT__MAX];

struct xsk_stats{
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_dropped;	//parsed but unusable
	uint64_t tx_no_slot;	//tx ring full
	uint64_t tx_no_frame;	//umem exhausted
	uint64_t queue_full;	//resolver backlog
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;	/* FILL: userspace -> kernel        */
	struct xsk_ring_cons cq;	/* COMPLETION: kernel -> userspace  */
	struct xsk_umem *umem;
	void *buffer;
	uint64_t size;
};

struct xsk_socket_info{
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	/* Free frame stack. NOT thread safe, deliberately. Exactly one
	 * thread may touch this, the four rings, or outstanding_tx. The
	 * rings are single producer/single consumer by contract; letting
	 * resolver workers in here is a data race that surfaces as
	 * descriptor corruption and phantom packet loss under load. */
	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;
	bool need_wakeup;	//did we negotiate XDP_USE_NEED_WAKEUP

	struct xsk_stats stats;
};

struct xsk_env{
	char ifname[IF_NAMESIZE];
	int ifindex;
	int queue_id;

	struct xdp_program *prog;
	enum xdp_attach_mode attach_mode;
	int xsk_map_fd;
	int stats_map_fd;
	bool custom_prog;

	void *packet_buffer;
	uint64_t packet_buffer_size;

	/* Per socket, not global: with several sockets one driver could
	 * in principle give zero-copy to one and not another, and a
	 * benchmark that reports a single flag for all of them is
	 * reporting whichever happened to be created last. */
	bool zerocopy;

	/* Only the env that actually attached the program detaches it.
	 * Clones share the attachment and must not tear it down. */
	bool owns_prog;

	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk;
};

/* Load af_xdp_kern.o and attach it, then resolve the fds for xsks_map
 * and xdp_dns_stats. bpf_obj == NULL uses libxsk's built-in program. */
int xsk_env_load_program(struct xsk_env *env, const char *ifname,
			 const char *bpf_obj, const char *progname,
			 enum xdp_attach_mode mode);

/* Share one already-attached XDP program with another env, so a second
 * (third, ...) socket can be created on a different rx queue without
 * attaching the program again. The XDP program is per-INTERFACE, but an
 * AF_XDP socket is per-QUEUE -- src keeps ownership of the attachment,
 * dst borrows the interface and map fds and brings up its own UMEM,
 * rings and frame pool.
 *
 * The kernel side needs nothing extra for this: af_xdp_kern.c already
 * redirects with ctx->rx_queue_index as the XSKMAP key, so a socket
 * registered at index N automatically receives queue N's traffic. */
void xsk_env_clone_program(struct xsk_env *dst, const struct xsk_env *src);

/* Allocate the UMEM, create the socket, register it in the xskmap and
 * prime the fill ring. After xsk_env_load_program(). */
int xsk_env_setup_socket(struct xsk_env *env, int queue_id,
			 bool want_zerocopy, bool want_need_wakeup);

void xsk_env_teardown(struct xsk_env *env);

/* Per-cpu counters from the XDP program, summed. out needs STAT__MAX. */
int xsk_env_read_kern_stats(struct xsk_env *env, uint64_t *out);

bool xsk_env_is_zerocopy(const struct xsk_env *env);

/* ---- frame allocator, loop thread only ---- */

static inline uint64_t xsk_alloc_frame(struct xsk_socket_info *xsk)
{
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	uint64_t frame = xsk->umem_frame_addr[--xsk->umem_frame_free];

	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static inline void xsk_free_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);
	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static inline uint32_t xsk_free_frame_count(const struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

/* An RX descriptor address is frame base + headroom, and in unaligned
 * mode the offset lives in the top 16 bits. The allocator only ever
 * deals in frame bases, so normalise before freeing -- handing back an
 * unaligned address makes frames drift and eventually overlap. */
static inline uint64_t xsk_frame_base(uint64_t addr)
{
	return xsk_umem__extract_addr(addr) & ~((uint64_t)FRAME_SIZE - 1);
}

#endif
