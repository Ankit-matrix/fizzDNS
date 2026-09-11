#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include "dns_iface.h"
#include "xsk_setup.h"
#include "dns_tcp.h"

/* The packet loop. Drains RX, hands DNS payloads to a worker pool, and
 * transmits what the workers produce.
 *
 * The one structural decision in this file: exactly ONE thread touches
 * rx, tx, fq, cq, the frame allocator and outstanding_tx. The obvious
 * design -- let each resolver thread push its own answer onto the TX
 * ring -- puts N producers on a single-producer ring and N threads on
 * an unlocked free-frame stack. It runs, it even looks right at low
 * load, and it corrupts descriptors under concurrency. The symptom is
 * packet loss that reads as "AF_XDP is lossy" rather than "we have a
 * data race". Workers only ever compute bytes.
 *
 *   RX ring
 *      | parse eth/ip/udp, copy the DNS payload + addressing into a
 *      | job, and release the frame back to the fill ring IMMEDIATELY
 *      v
 *   [pending queue]  mutex + condvar
 *      v
 *   workers -> dns_resolve_query()   blocking, ~1s upstream
 *      v
 *   [done queue]  mutex + eventfd
 *      v
 *   loop thread: allocate a TX frame, build the headers, submit
 *
 * Releasing the RX frame before resolution is the other half. Holding
 * one for the duration of an upstream walk means a few hundred
 * concurrent queries exhaust a 4096 frame UMEM. One 512 byte memcpy per
 * query is obviously the right side of that trade. */

#define MAX_XSKS	16
#define MAX_WORKERS	32
#define DEFAULT_WORKERS	8
#define MAX_PENDING	4096
#define POLL_TIMEOUT_MS	100

#define ETH_HLEN_	(int)sizeof(struct ethhdr)
#define L2L3L4_HLEN	(ETH_HLEN_ + (int)sizeof(struct iphdr) + \
			 (int)sizeof(struct udphdr))

/* Self contained: no reference back into the UMEM, so the frame this
 * came from is already in the fill ring before a worker sees the job. */
struct dns_job {
	struct dns_job *next;

	/* Which rx loop this arrived on. A reply MUST go back out
	 * through the same socket: only that loop's thread is allowed to
	 * touch its tx ring and frame stack, so a worker cannot simply
	 * hand the job to whichever loop is idle. */
	uint8_t loop_idx;

	uint8_t  client_mac[ETH_ALEN];
	uint8_t  server_mac[ETH_ALEN];
	uint32_t client_ip;		/* be32 */
	uint32_t server_ip;		/* be32 */
	uint16_t client_port;		/* be16 */

	uint8_t  tos;
	uint8_t  ttl;

	size_t   query_len;
	uint8_t  query[DNS_MAX_MSG_LEN];

	size_t   resp_len;
	uint8_t  resp[DNS_MAX_MSG_LEN];

	uint64_t t_rx_ns;
};

/* ---------------- queues ---------------- */

struct job_queue {
	struct dns_job *head, *tail;
	unsigned count, cap;		//cap 0 = unbounded
	bool shutdown;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
	int notify_fd;			//eventfd, or -1
};

static void queue_init(struct job_queue *q, unsigned cap, int notify_fd)
{
	q->head = q->tail = NULL;
	q->count = 0;
	q->cap = cap;
	q->shutdown = false;
	q->notify_fd = notify_fd;
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->not_empty, NULL);
}

/* Non blocking. false means at capacity, which is the backpressure
 * signal: drop rather than grow a backlog of jobs whose clients have
 * long since timed out. */
static bool queue_push(struct job_queue *q, struct dns_job *job)
{
	bool ok = true;

	pthread_mutex_lock(&q->lock);
	if (q->shutdown || (q->cap && q->count >= q->cap)) {
		ok = false;
	} else {
		job->next = NULL;
		if (q->tail)
			q->tail->next = job;
		else
			q->head = job;
		q->tail = job;
		q->count++;
	}
	pthread_mutex_unlock(&q->lock);

	if (ok) {
		pthread_cond_signal(&q->not_empty);
		if (q->notify_fd >= 0) {
			uint64_t one = 1;
			ssize_t n = write(q->notify_fd, &one, sizeof(one));

			(void)n;	//best effort, poll timeout covers a miss
		}
	}
	return ok;
}

static struct dns_job *queue_pop_wait(struct job_queue *q)
{
	struct dns_job *job = NULL;

	pthread_mutex_lock(&q->lock);
	while (!q->head && !q->shutdown)
		pthread_cond_wait(&q->not_empty, &q->lock);

	if (q->head) {
		job = q->head;
		q->head = job->next;
		if (!q->head)
			q->tail = NULL;
		q->count--;
		job->next = NULL;
	}
	pthread_mutex_unlock(&q->lock);
	return job;
}

/* Detach the whole list in one acquisition. Taking the mutex per job
 * would put worker contention directly on the packet path. */
static struct dns_job *queue_drain(struct job_queue *q)
{
	struct dns_job *list;

	pthread_mutex_lock(&q->lock);
	list = q->head;
	q->head = q->tail = NULL;
	q->count = 0;
	pthread_mutex_unlock(&q->lock);
	return list;
}

static void queue_shutdown(struct job_queue *q)
{
	pthread_mutex_lock(&q->lock);
	q->shutdown = true;
	pthread_mutex_unlock(&q->lock);
	pthread_cond_broadcast(&q->not_empty);
}

/* ---------------- globals ---------------- */

/* One of these per rx queue: its own socket, UMEM, rings, frame pool,
 * completion queue and eventfd, driven by exactly one thread.
 *
 * Nothing here is shared between loops. That is deliberate -- it keeps
 * the single-writer invariant that the whole AF_XDP side depends on,
 * and it means adding a second core adds a second independent packet
 * path rather than a second contender for one.
 *
 * The one thing that IS shared is pending_q, because any worker can
 * resolve any query. done_q cannot be shared for the reason in
 * struct dns_job. */
struct loop_ctx {
	struct xsk_env env;
	struct job_queue done_q;
	int done_eventfd;
	int idx;
	int queue_id;
	int cpu;			//-1 = don't pin
	pthread_t tid;
};

static struct loop_ctx loops[MAX_XSKS];
static int nloops = 1;

static struct job_queue pending_q;	//shared: any worker, any query
static struct dns_tcp_server *tcp_srv;

static pthread_t workers[MAX_WORKERS];
static int num_workers = DEFAULT_WORKERS;

static volatile sig_atomic_t global_exit;

static struct {
	int queue_id;
	int nqueues;
	bool pin;
	bool zerocopy;
	bool need_wakeup;
	bool busy_poll;
	bool verbose;
	bool allow_multiqueue;
	const char *ifname;
	const char *bpf_obj;
	const char *progname;
	enum xdp_attach_mode mode;
} opt = {
	.queue_id = 0,
	.nqueues = 1,
	.pin = true,
	.zerocopy = true,
	.need_wakeup = true,
	.busy_poll = false,
	.verbose = false,
	.allow_multiqueue = false,
	.ifname = NULL,
	.bpf_obj = "af_xdp_kern.o",
	.progname = NULL,
	.mode = XDP_MODE_NATIVE,
};

static atomic_ullong resolved_ok, resolved_drop;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint16_t ipv4_checksum(const void *buf, int len)
{
	const uint16_t *w = buf;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *w++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const uint8_t *)w;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)~sum;
}

/* ---------------- rx ---------------- */

/* NULL if this isn't something we can answer; the caller recycles the
 * frame either way. The XDP program already guaranteed IPv4/UDP/dport
 * 53/QR=0/QDCOUNT=1, but we re-check lengths regardless -- the kernel
 * filter is a fast path, not a trust boundary, and someone may run this
 * with a different program attached. */
static struct dns_job *parse_frame(const uint8_t *pkt, uint32_t len, int loop_idx)
{
	if (len < (uint32_t)L2L3L4_HLEN)
		return NULL;

	const struct ethhdr *eth = (const struct ethhdr *)pkt;

	if (eth->h_proto != htons(ETH_P_IP))
		return NULL;

	const struct iphdr *ip = (const struct iphdr *)(eth + 1);

	if (ip->version != 4 || ip->ihl < 5)
		return NULL;

	uint32_t ihl = (uint32_t)ip->ihl * 4;

	if (len < ETH_HLEN_ + ihl + sizeof(struct udphdr))
		return NULL;
	if (ip->protocol != IPPROTO_UDP)
		return NULL;

	const struct udphdr *udp = (const struct udphdr *)((const uint8_t *)ip + ihl);

	if (udp->dest != htons(53))
		return NULL;

	uint32_t udp_len = ntohs(udp->len);

	if (udp_len < sizeof(struct udphdr))
		return NULL;

	uint32_t dns_len = udp_len - sizeof(struct udphdr);
	uint32_t avail = len - (ETH_HLEN_ + ihl + sizeof(struct udphdr));

	/* Trust the shorter of the two. A UDP length longer than the frame
	 * is either a truncated capture or someone probing us. */
	if (dns_len > avail)
		dns_len = avail;
	if (dns_len < 12 || dns_len > DNS_MAX_MSG_LEN)
		return NULL;

	struct dns_job *job = malloc(sizeof(*job));

	if (!job)
		return NULL;

	memcpy(job->client_mac, eth->h_source, ETH_ALEN);
	memcpy(job->server_mac, eth->h_dest, ETH_ALEN);
	job->client_ip = ip->saddr;
	job->server_ip = ip->daddr;
	job->client_port = udp->source;
	job->tos = ip->tos;
	job->ttl = 64;

	job->query_len = dns_len;
	memcpy(job->query, (const uint8_t *)udp + sizeof(struct udphdr), dns_len);

	job->resp_len = 0;
	job->next = NULL;
	job->loop_idx = (uint8_t)loop_idx;
	job->t_rx_ns = now_ns();

	return job;
}

/* Hand n frames back to the kernel. Called after every drain so the
 * fill ring never runs dry. */
static void refill_fq(struct xsk_socket_info *xsk, unsigned n)
{
	unsigned avail = xsk_prod_nb_free(&xsk->umem->fq, n);
	uint32_t idx;

	if (n > avail)
		n = avail;
	if (n > xsk_free_frame_count(xsk))
		n = xsk_free_frame_count(xsk);
	if (!n)
		return;

	if (xsk_ring_prod__reserve(&xsk->umem->fq, n, &idx) != n)
		return;

	for (unsigned i = 0; i < n; i++)
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) =
			xsk_alloc_frame(xsk);

	xsk_ring_prod__submit(&xsk->umem->fq, n);
}

static void drain_rx(struct loop_ctx *lp)
{
	struct xsk_socket_info *xsk = lp->env.xsk;

	uint32_t idx_rx = 0;
	unsigned rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);

	if (!rcvd)
		return;

	for (unsigned i = 0; i < rcvd; i++) {
		const struct xdp_desc *d = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
		uint64_t addr = d->addr;
		uint32_t len = d->len;
		const uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		struct dns_job *job = parse_frame(pkt, len, lp->idx);

		xsk->stats.rx_packets++;
		xsk->stats.rx_bytes += len;

		if (!job) {
			xsk->stats.rx_dropped++;
		} else if (!queue_push(&pending_q, job)) {
			/* Backlog full. Dropping is the honest answer --
			 * queueing would just reply to a client that has
			 * already given up. */
			xsk->stats.queue_full++;
			free(job);
		}

		/* The job owns a copy, so the frame goes back now whatever
		 * happens to the query afterwards. */
		xsk_free_frame(xsk, xsk_frame_base(addr));
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
	refill_fq(xsk, rcvd);
}

/* ---------------- tx ---------------- */

static uint32_t build_response_frame(uint8_t *frame, const struct dns_job *job)
{
	struct ethhdr *eth = (struct ethhdr *)frame;
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	uint8_t *dns = (uint8_t *)(udp + 1);

	//just reverse the direction of the request
	memcpy(eth->h_dest, job->client_mac, ETH_ALEN);
	memcpy(eth->h_source, job->server_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	uint16_t udp_total = (uint16_t)(sizeof(*udp) + job->resp_len);
	uint16_t ip_total = (uint16_t)(sizeof(*ip) + udp_total);

	ip->version = 4;
	ip->ihl = 5;			//we never emit options
	ip->tos = job->tos;
	ip->tot_len = htons(ip_total);
	ip->id = 0;			//DF is set so this is unused
	ip->frag_off = htons(0x4000);	//DF
	ip->ttl = job->ttl;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;
	ip->saddr = job->server_ip;
	ip->daddr = job->client_ip;
	ip->check = ipv4_checksum(ip, sizeof(*ip));

	udp->source = htons(53);
	udp->dest = job->client_port;
	udp->len = htons(udp_total);
	/* Zero is legal for IPv4 UDP and means "not computed". Every
	 * resolver client accepts it and it keeps the TX path branch
	 * free -- no pseudo-header sum over the payload. */
	udp->check = 0;

	memcpy(dns, job->resp, job->resp_len);

	return (uint32_t)(L2L3L4_HLEN + job->resp_len);
}

/* With XDP_USE_NEED_WAKEUP the kernel tells us when a syscall is
 * actually needed. WITHOUT it there is no flag to consult and
 * needs_wakeup() is always false -- so we have to kick every time, or
 * nothing is ever transmitted at all. */
static void kick_tx(struct xsk_socket_info *xsk)
{
	if (!xsk->outstanding_tx)
		return;
	if (!xsk->need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx))
		sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void reclaim_tx(struct xsk_socket_info *xsk)
{
	uint32_t idx_cq;
	unsigned completed;

	if (!xsk->outstanding_tx)
		return;

	kick_tx(xsk);

	completed = xsk_ring_cons__peek(&xsk->umem->cq, TX_BATCH_SIZE, &idx_cq);
	if (!completed)
		return;

	for (unsigned i = 0; i < completed; i++)
		xsk_free_frame(xsk, xsk_frame_base(
			*xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++)));

	xsk_ring_cons__release(&xsk->umem->cq, completed);
	xsk->outstanding_tx -= completed < xsk->outstanding_tx
			     ? completed : xsk->outstanding_tx;
}

/* Take everything the workers have finished and put it on the wire. */
static void drain_done_and_tx(struct loop_ctx *lp)
{
	struct xsk_socket_info *xsk = lp->env.xsk;
	struct dns_job *list = queue_drain(&lp->done_q);

	while (list) {
		struct dns_job *batch[TX_BATCH_SIZE];
		unsigned n = 0, sent = 0;
		uint32_t idx_tx = 0;

		while (list && n < TX_BATCH_SIZE) {
			struct dns_job *job = list;

			list = job->next;
			if (job->resp_len == 0 || job->resp_len > DNS_MAX_MSG_LEN)
				free(job);
			else
				batch[n++] = job;
		}
		if (!n)
			continue;

		/* One reserve for the batch. Per-packet reserve/submit
		 * pairs are a lot of ring traffic for no reason. */
		unsigned want = n;
		unsigned slots = xsk_prod_nb_free(&xsk->tx, want);

		if (want > slots) {
			xsk->stats.tx_no_slot += want - slots;
			want = slots;
		}
		if (want > xsk_free_frame_count(xsk)) {
			xsk->stats.tx_no_frame += want - xsk_free_frame_count(xsk);
			want = xsk_free_frame_count(xsk);
		}

		if (want && xsk_ring_prod__reserve(&xsk->tx, want, &idx_tx) == want) {
			for (unsigned i = 0; i < want; i++) {
				uint64_t frame = xsk_alloc_frame(xsk);
				uint8_t *buf = xsk_umem__get_data(xsk->umem->buffer,
								  frame);
				uint32_t len = build_response_frame(buf, batch[i]);
				struct xdp_desc *d =
					xsk_ring_prod__tx_desc(&xsk->tx, idx_tx + i);

				d->addr = frame;
				d->len = len;

				xsk->stats.tx_packets++;
				xsk->stats.tx_bytes += len;
			}
			xsk_ring_prod__submit(&xsk->tx, want);
			xsk->outstanding_tx += want;
			sent = want;
		}

		for (unsigned i = 0; i < n; i++) {
			if (opt.verbose && i < sent)
				printf("  answered %zu bytes in %" PRIu64 " us\n",
				       batch[i]->resp_len,
				       (now_ns() - batch[i]->t_rx_ns) / 1000);
			free(batch[i]);
		}
	}

	kick_tx(xsk);
}

/* ---------------- workers ---------------- */

static void *worker_main(void *arg)
{
	(void)arg;

	for (;;) {
		struct dns_job *job = queue_pop_wait(&pending_q);
		size_t out_len = 0;
		int rc;

		if (!job)
			break;		//shutdown

		rc = dns_resolve_query(job->query, job->query_len,
				       job->resp, sizeof(job->resp), &out_len,
				       true);	/* UDP */

		if (rc != DNS_OK || out_len == 0) {
			atomic_fetch_add(&resolved_drop, 1);
			free(job);
			continue;
		}

		job->resp_len = out_len;
		atomic_fetch_add(&resolved_ok, 1);

		/* The only place a worker talks to the packet path, and it
		 * is a plain mutex plus an eventfd. No ring access -- and
		 * it must be the queue belonging to the loop this job
		 * arrived on, not any other. */
		if (!queue_push(&loops[job->loop_idx].done_q, job))
			free(job);
	}

	return NULL;
}

/* ---------------- main loop ---------------- */

static void drain_eventfd(int fd)
{
	uint64_t v;
	ssize_t n = read(fd, &v, sizeof(v));

	(void)n;	//EFD_NONBLOCK, EAGAIN when there is nothing
}

static void *loop_main(void *arg)
{
	struct loop_ctx *lp = arg;
	struct xsk_socket_info *xsk = lp->env.xsk;
	struct pollfd fds[2];

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk->xsk);
	fds[1].fd = lp->done_eventfd;

	while (!global_exit) {
		if (!opt.busy_poll) {
			fds[0].events = POLLIN;
			fds[1].events = POLLIN;

			int ret = poll(fds, 2, POLL_TIMEOUT_MS);

			if (ret < 0) {
				if (errno == EINTR)
					continue;
				perror("poll");
				break;
			}
		}

		/* Always drain it, busy-poll included, or the counter just
		 * climbs until write() starts failing. */
		drain_eventfd(lp->done_eventfd);

		//nudge the kernel if it wants frames
		if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq))
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0,
				 MSG_DONTWAIT, NULL, NULL);

		drain_rx(lp);
		drain_done_and_tx(lp);
		reclaim_tx(xsk);
	}

	//flush whatever the workers finished on the way out
	drain_done_and_tx(lp);
	reclaim_tx(xsk);
	return NULL;
}

/* ---------------- stats / shutdown ---------------- */

static void print_stats(void)
{
	struct xsk_stats t;
	uint64_t kern[STAT__MAX];
	uint32_t frames_free = 0;

	memset(&t, 0, sizeof(t));

	/* Summed across loops, then broken out per queue. The total is
	 * what the run produced; the per-queue lines are what say whether
	 * RSS actually spread the load or piled it onto one core, which
	 * a total alone will hide completely. */
	for (int i = 0; i < nloops; i++) {
		if (!loops[i].env.xsk)
			continue;

		const struct xsk_stats *s = &loops[i].env.xsk->stats;

		t.rx_packets += s->rx_packets;
		t.rx_bytes   += s->rx_bytes;
		t.rx_dropped += s->rx_dropped;
		t.queue_full += s->queue_full;
		t.tx_packets += s->tx_packets;
		t.tx_bytes   += s->tx_bytes;
		t.tx_no_slot += s->tx_no_slot;
		t.tx_no_frame += s->tx_no_frame;
		frames_free  += xsk_free_frame_count(loops[i].env.xsk);
	}

	printf("\n--- userspace ---\n");
	printf("  rx packets      %" PRIu64 "\n", t.rx_packets);
	printf("  rx bytes        %" PRIu64 "\n", t.rx_bytes);
	printf("  rx dropped      %" PRIu64 "  (unparseable)\n", t.rx_dropped);
	printf("  queue full      %" PRIu64 "  (resolver backlog)\n", t.queue_full);
	printf("  tx packets      %" PRIu64 "\n", t.tx_packets);
	printf("  tx bytes        %" PRIu64 "\n", t.tx_bytes);
	printf("  tx no slot      %" PRIu64 "  (TX ring full)\n", t.tx_no_slot);
	printf("  tx no frame     %" PRIu64 "  (UMEM exhausted)\n", t.tx_no_frame);
	printf("  frames free     %u / %d\n", frames_free, NUM_FRAMES * nloops);
	printf("  resolved ok     %llu\n",
	       (unsigned long long)atomic_load(&resolved_ok));
	printf("  resolved drop   %llu\n",
	       (unsigned long long)atomic_load(&resolved_drop));
	printf("  mode            %s, %s\n",
	       xsk_env_is_zerocopy(&loops[0].env) ? "zero-copy" : "copy",
	       opt.busy_poll ? "busy-poll" : "poll()");

	if (nloops > 1) {
		printf("--- per rx queue ---\n");
		for (int i = 0; i < nloops; i++) {
			if (!loops[i].env.xsk)
				continue;

			const struct xsk_stats *s = &loops[i].env.xsk->stats;
			double share = t.rx_packets
				     ? 100.0 * (double)s->rx_packets /
				       (double)t.rx_packets : 0.0;

			printf("  q%-2d cpu%-3d    rx %-10" PRIu64
			       " tx %-10" PRIu64 " (%.1f%% of rx)\n",
			       loops[i].queue_id, loops[i].cpu,
			       s->rx_packets, s->tx_packets, share);
		}
	}

	if (xsk_env_read_kern_stats(&loops[0].env, kern) == 0) {
		printf("--- xdp filter ---\n");
		for (int i = 0; i < STAT__MAX; i++)
			printf("  %-14s  %" PRIu64 "\n",
			       xdp_dns_stat_names[i], kern[i]);
	}
	printf("\n");

		uint64_t tcp_acc = 0, tcp_rej = 0, tcp_q = 0, tcp_a = 0;

	dns_tcp_server_stats(tcp_srv, &tcp_acc, &tcp_rej, &tcp_q, &tcp_a);
	printf("--- tcp fallback ---\n");
	printf("  accepted        %" PRIu64 "\n", tcp_acc);
	printf("  rejected        %" PRIu64 "  (at %d connection cap)\n",
	       tcp_rej, DNS_TCP_MAX_CONNS);
	printf("  queries         %" PRIu64 "\n", tcp_q);
	printf("  answered        %" PRIu64 "\n", tcp_a);
}

static void on_signal(int sig)
{
	(void)sig;
	global_exit = 1;
}

/* Count the NIC's RX queues from sysfs. -1 if it can't be determined,
 * which is treated as "don't know, don't block". No ethtool dependency:
 * /sys/class/net/<if>/queues/ has one rx-N directory per queue. */
static int nic_rx_queues(const char *ifname)
{
	char path[256];
	DIR *d;
	struct dirent *e;
	int n = 0;

	snprintf(path, sizeof(path), "/sys/class/net/%s/queues", ifname);
	d = opendir(path);
	if (!d)
		return -1;

	while ((e = readdir(d)))
		if (strncmp(e->d_name, "rx-", 3) == 0)
			n++;

	closedir(d);
	return n ? n : -1;
}

/* An XSK binds to exactly ONE rx queue. On a multi-queue NIC the
 * hardware spreads flows across all of them by RSS hash, so only the
 * fraction that lands on our queue ever reaches the socket. The rest
 * take XDP_PASS into a kernel stack with nothing bound to port 53 and
 * are dropped there.
 *
 * That failure is silent and it biases the experiment in the wrong
 * direction: the AF_XDP arm appears to lose most of its traffic while
 * the UDP control arm, which is bound to a normal socket and therefore
 * receives from every queue, does not. A benchmark run in this state
 * measures RSS distribution, not packet path cost.
 *
 * So refuse to start rather than produce a number that looks like data.
 * Either reduce the NIC to one queue:
 *
 *     ethtool -L IFACE combined 1
 *
 * or pass --allow-multiqueue if you genuinely intend to serve a single
 * queue and understand what the figures mean. */
static int check_queue_config(const char *ifname, int first_q, int nq_want)
{
	int nq = nic_rx_queues(ifname);

	if (nq < 0)
		return 0;		//unknown, don't block

	if (first_q + nq_want > nq) {
		fprintf(stderr,
			"ERR: asked for %d queue(s) starting at %d, but %s has "
			"only %d.\n", nq_want, first_q, ifname, nq);
		return -1;
	}

	if (nq_want == nq)
		return 0;		//serving all of them

	if (opt.allow_multiqueue) {
		fprintf(stderr,
			"WARN: %s has %d rx queues; serving %d. Traffic hashed "
			"elsewhere bypasses this resolver.\n",
			ifname, nq, nq_want);
		return 0;
	}

	fprintf(stderr,
		"ERR: %s has %d rx queues but only %d would be served.\n"
		"     An AF_XDP socket binds ONE queue, so queries RSS-hashed\n"
		"     to an unserved queue are dropped by the kernel stack and\n"
		"     any benchmark run this way measures RSS, not the packet\n"
		"     path. Either serve them all:\n"
		"\n"
		"         %s --queues %d\n"
		"\n"
		"     or reduce the NIC to match:\n"
		"\n"
		"         sudo ethtool -L %s combined %d\n"
		"\n"
		"     or pass --allow-multiqueue to proceed anyway.\n",
		ifname, nq, nq_want, "af_xdp_user", nq, ifname, nq_want);
	return -1;
}

/* Pin a thread to one cpu. An rx loop that migrates between cores loses
 * its UMEM and ring cache lines on every move, and worse, drifts away
 * from the core taking its queue's NIC interrupt -- so the NAPI poll
 * runs on one core and the userspace drain on another, with every
 * descriptor crossing between them. */
static int pin_to_cpu(pthread_t t, int cpu)
{
	cpu_set_t set;

	if (cpu < 0)
		return 0;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return pthread_setaffinity_np(t, sizeof(set), &set);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s -d IFACE [options]\n"
		"\n"
		"  -d, --dev IFACE       interface to attach to (required)\n"
		"  -Q, --queue N         first rx queue id (default 0)\n"
		"  -n, --queues N        number of rx queues to serve, one\n"
		"                        socket and one pinned thread each\n"
		"                        (default 1)\n"
		"      --no-pin          do not pin rx loop threads to cpus\n"
		"  -w, --workers N       resolver threads (default %d)\n"
		"      --filename FILE   BPF object (default af_xdp_kern.o)\n"
		"      --progname NAME   program name inside the object\n"
		"  -S, --skb-mode        attach in SKB (generic) mode\n"
		"  -c, --copy            force XDP_COPY instead of zero-copy\n"
		"  -b, --busy-poll       spin instead of blocking in poll()\n"
		"  -W, --no-wakeup       disable XDP_USE_NEED_WAKEUP\n"
		"  -v, --verbose         per-query service latency\n"
		"  -M, --allow-multiqueue\n"
		"                        run on a multi-queue NIC anyway; only\n"
		"                        traffic hashed to the chosen queue is\n"
		"                        served (see ethtool -L IFACE combined 1)\n"
		"  -h, --help\n",
		prog, DEFAULT_WORKERS);
}

int main(int argc, char **argv)
{
	static struct option longopts[] = {
		{ "dev",       required_argument, NULL, 'd' },
		{ "queue",     required_argument, NULL, 'Q' },
		{ "queues",    required_argument, NULL, 'n' },
		{ "no-pin",    no_argument,       NULL, 3   },
		{ "workers",   required_argument, NULL, 'w' },
		{ "filename",  required_argument, NULL, 1   },
		{ "progname",  required_argument, NULL, 2   },
		{ "skb-mode",  no_argument,       NULL, 'S' },
		{ "copy",      no_argument,       NULL, 'c' },
		{ "busy-poll", no_argument,       NULL, 'b' },
		{ "no-wakeup", no_argument,       NULL, 'W' },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "allow-multiqueue", no_argument, NULL, 'M' },
		{ "help",      no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	int c;

	while ((c = getopt_long(argc, argv, "d:Q:n:w:ScbWvMh", longopts, NULL)) != -1) {
		switch (c) {
		case 'd': opt.ifname = optarg; break;
		case 'Q': opt.queue_id = atoi(optarg); break;
		case 'n': opt.nqueues = atoi(optarg); break;
		case 3:   opt.pin = false; break;
		case 'w': num_workers = atoi(optarg); break;
		case 1:   opt.bpf_obj = optarg; break;
		case 2:   opt.progname = optarg; break;
		case 'S': opt.mode = XDP_MODE_SKB; break;
		case 'c': opt.zerocopy = false; break;
		case 'b': opt.busy_poll = true; break;
		case 'W': opt.need_wakeup = false; break;
		case 'v': opt.verbose = true; break;
		case 'M': opt.allow_multiqueue = true; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	if (!opt.ifname) {
		usage(argv[0]);
		return 1;
	}
	if (num_workers < 1)
		num_workers = 1;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	/* Before anything is attached or allocated -- a wrong queue
	 * config makes every number produced afterwards meaningless. */
	if (opt.nqueues < 1)
		opt.nqueues = 1;
	if (opt.nqueues > MAX_XSKS)
		opt.nqueues = MAX_XSKS;
	nloops = opt.nqueues;

	if (check_queue_config(opt.ifname, opt.queue_id, opt.nqueues))
		return 1;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	queue_init(&pending_q, MAX_PENDING, -1);

	/* Static storage zeroes these, and 0 is a perfectly good fd --
	 * stdin. The teardown path closes every done_eventfd it finds, so
	 * without this an early setup failure closes stdin instead. */
	for (int i = 0; i < MAX_XSKS; i++)
		loops[i].done_eventfd = -1;

	/* KERNEL SIDE, once per interface. The XDP program is attached to
	 * the device, not to a queue, and af_xdp_kern.c already keys its
	 * redirect on ctx->rx_queue_index -- so one attachment serves
	 * every queue and nothing in the BPF object changes when nloops
	 * goes from 1 to 2. */
	if (xsk_env_load_program(&loops[0].env, opt.ifname, opt.bpf_obj,
				 opt.progname, opt.mode))
		return 1;

	/* USER SIDE, once per queue. Each loop gets its own UMEM, rings,
	 * frame pool, completion queue and eventfd, and registers itself
	 * in the XSKMAP at its queue index. */
	for (int i = 0; i < nloops; i++) {
		struct loop_ctx *lp = &loops[i];

		if (i > 0)
			xsk_env_clone_program(&lp->env, &loops[0].env);

		lp->idx = i;
		lp->queue_id = opt.queue_id + i;
		lp->cpu = opt.pin ? i : -1;

		lp->done_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (lp->done_eventfd < 0) {
			perror("eventfd");
			goto err_teardown;
		}
		queue_init(&lp->done_q, 0, lp->done_eventfd);

		if (xsk_env_setup_socket(&lp->env, lp->queue_id, opt.zerocopy,
					 opt.need_wakeup))
			goto err_teardown;
	}

	if (dns_backend_init(num_workers)) {
		fprintf(stderr, "ERR: dns_backend_init failed\n");
		goto err_teardown;
	}

	/* Once. This was called twice: the second bind to port 53 fails,
	 * tcp_srv is overwritten with NULL, and the first server is left
	 * running with no handle to stop it. */
	tcp_srv = dns_tcp_server_start(53);

	if (!tcp_srv)
		fprintf(stderr, "warn: TCP fallback unavailable, UDP-only\n");

	for (int i = 0; i < num_workers; i++) {
		if (pthread_create(&workers[i], NULL, worker_main, NULL)) {
			perror("pthread_create");
			num_workers = i;
			break;
		}
	}

	/* One rx loop thread per queue, each pinned. Loop i takes cpu i
	 * by default, so on a 2 core box with --queues 2 the two packet
	 * paths run genuinely in parallel instead of taking turns. */
	int nstarted = 0;

	for (int i = 0; i < nloops; i++) {
		if (pthread_create(&loops[i].tid, NULL, loop_main, &loops[i])) {
			perror("pthread_create(rx loop)");
			global_exit = 1;	//stop the ones already running
			break;
		}
		nstarted++;

		if (opt.pin && pin_to_cpu(loops[i].tid, loops[i].cpu))
			fprintf(stderr, "warn: cannot pin rx loop %d to cpu %d\n",
				i, loops[i].cpu);
	}

	printf("resolver running: %d rx loop(s), %d workers, %s\n",
	       nloops, num_workers, opt.busy_poll ? "busy-poll" : "poll()");
	printf("ctrl-c to stop\n");
	fflush(stdout);

	for (int i = 0; i < nstarted; i++)
		pthread_join(loops[i].tid, NULL);

	printf("\nshutting down...\n");
	queue_shutdown(&pending_q);
	for (int i = 0; i < num_workers; i++)
		pthread_join(workers[i], NULL);

	/* Workers are gone, so anything left on a done queue is ours.
	 * Its loop thread has already exited, which is what makes it safe
	 * for this thread to touch those rings now. */
	for (int i = 0; i < nloops; i++) {
		if (!loops[i].env.xsk)
			continue;
		drain_done_and_tx(&loops[i]);
		reclaim_tx(loops[i].env.xsk);
	}

	print_stats();
	dns_tcp_server_stop(tcp_srv);
	dns_backend_fini();

err_teardown:
	for (int i = 0; i < nloops; i++) {
		if (loops[i].env.xsk || loops[i].env.prog)
			xsk_env_teardown(&loops[i].env);
		if (loops[i].done_eventfd >= 0)
			close(loops[i].done_eventfd);
	}
	/* loops[0] owns the interface attachment, so it goes last. */
	return 0;
}
