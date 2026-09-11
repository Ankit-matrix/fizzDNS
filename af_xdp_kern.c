#include <linux/bpf.h>
#include <linux/if_ether.h>	//For working with ethernet
#include <linux/ip.h>		//For working with Internet Protocol
#include <linux/udp.h>		//Same thing but UDP
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT	53
#define MAX_RX_QUEUES	64
#define MAX_IHL_BYTES	60	//ihl is 4 bits, so 15*4

/* Keep in sync with enum xdp_dns_stat in xsk_setup.h */
enum xdp_dns_stat{
	STAT_TOTAL = 0,		//every packet
	STAT_NOT_IPV4,
	STAT_NOT_UDP,
	STAT_NOT_DNS_PORT,	//port != 53
	STAT_MALFORMED,		//random nonsense or truncated headers
	STAT_NOT_QUERY,		//qr=1 or qdcount!=1
	STAT_REDIRECTED,	//handed to the xsk
	STAT__MAX
};

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_RX_QUEUES);
	__type(key, __u32);
	__type(value, __u32);
} xsks_map SEC(".maps");

/* PERCPU_ARRAY, not bpf_printk. Every trace_printk is a formatted write
 * into a per-cpu ring plus a global lock, per packet, and it dominates
 * the cost of the whole program. There is no printk on this path. */
struct{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT__MAX);
	__type(key, __u32);
	__type(value, __u64);
} xdp_dns_stats SEC(".maps");

struct dnshdr {
	__be16 id;
	__be16 flags;
	__be16 qdcount;
	__be16 ancount;
	__be16 nscount;
	__be16 arcount;
};

static __always_inline void stat_bump(__u32 slot)
{
	__u64 *val = bpf_map_lookup_elem(&xdp_dns_stats, &slot);

	if (val) (*val)++;
}

static __always_inline int stat_verdict(__u32 slot, int verdict)
{
	stat_bump(slot);
	return verdict;
}

/* A packet only reaches the xsk if it is IPv4, unfragmented, UDP, dport
 * 53, has a full 12 byte DNS header, QR=0 and QDCOUNT=1. Everything else
 * takes XDP_PASS and goes up the normal stack, so userspace never wakes
 * for stray responses, and the box degrades to an ordinary host if the
 * resolver dies instead of blackholing port 53. */
SEC("xdp")
int xdp_dns_redirect(struct xdp_md *ctx)	//struct xdp_md - packet
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 qidx = ctx->rx_queue_index;	//__u32 ~ uint32_t

	stat_bump(STAT_TOTAL);

	//ethernet
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end) return stat_verdict(STAT_MALFORMED, XDP_PASS);
	if (eth->h_proto != bpf_htons(ETH_P_IP)) return stat_verdict(STAT_NOT_IPV4, XDP_PASS);

	//ipv4
	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > data_end) return stat_verdict(STAT_MALFORMED, XDP_PASS);
	if (ip->version != 4 || ip->ihl < 5) return stat_verdict(STAT_MALFORMED, XDP_PASS);
	if (ip->protocol != IPPROTO_UDP) return stat_verdict(STAT_NOT_UDP, XDP_PASS);
	if (ip->frag_off & bpf_htons(0x2000 | 0x1FFF)) return stat_verdict(STAT_MALFORMED, XDP_PASS);

	__u32 ihl_bytes = ip->ihl * 4;

	if (ihl_bytes < sizeof(*ip) || ihl_bytes > MAX_IHL_BYTES) return stat_verdict(STAT_MALFORMED, XDP_PASS);

	//udp
	struct udphdr *udp = (void *)ip + ihl_bytes;

	if ((void *)(udp + 1) > data_end) return stat_verdict(STAT_MALFORMED, XDP_PASS);
	if (udp->dest != bpf_htons(DNS_PORT)) return stat_verdict(STAT_NOT_DNS_PORT, XDP_PASS);

	//dns
	struct dnshdr *dns = (void *)(udp + 1);

	if ((void *)(dns + 1) > data_end) return stat_verdict(STAT_MALFORMED, XDP_PASS);
	if (dns->flags & bpf_htons(0x8000)) return stat_verdict(STAT_NOT_QUERY, XDP_PASS);
	if (dns->qdcount != bpf_htons(1)) return stat_verdict(STAT_NOT_QUERY, XDP_PASS);	//one question per packet
	if ((void *)(dns + 1) + 1 > data_end) return stat_verdict(STAT_MALFORMED, XDP_PASS);	//at least one label byte

	stat_bump(STAT_REDIRECTED);

	/* XDP_PASS as the fallback: if no xsk is bound to this queue the
	 * packet goes up the stack instead of being dropped. */
	return bpf_redirect_map(&xsks_map, qidx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
