#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "dns_iface.h"
#include "dns_tcp.h"

/* The control arm: an ordinary UDP DNS server. socket(), bind(53),
 * recvfrom() loop, thread pool, sendto().
 *
 * Structured to mirror af_xdp_user.c as closely as the two transports
 * allow -- same backend object, same worker count, same queue depth,
 * same drop-on-backlog policy, one receive thread and N workers.
 *
 * The one structural difference is that here workers sendto() directly,
 * because a UDP socket is safe to write from many threads and a UMEM
 * ring is not. That difference is itself part of the result: the kernel
 * is doing synchronisation work on this path that the AF_XDP side has
 * to do in userspace. */

#define MAX_WORKERS	32
#define DEFAULT_WORKERS	8
#define MAX_PENDING	4096
#define RECV_BUF	1500

struct udp_job {
	struct udp_job *next;
	struct sockaddr_in client;
	socklen_t client_len;
	size_t len;
	uint8_t msg[RECV_BUF];
};

static struct {
	struct udp_job *head, *tail;
	unsigned count, cap;
	bool shutdown;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
} q;

static int sockfd = -1;
static volatile sig_atomic_t running = 1;
static int num_workers = DEFAULT_WORKERS;

static atomic_ullong rx_count, tx_count, drop_parse, drop_backlog;

static void queue_init(unsigned cap)
{
	q.head = q.tail = NULL;
	q.count = 0;
	q.cap = cap;
	q.shutdown = false;
	pthread_mutex_init(&q.lock, NULL);
	pthread_cond_init(&q.not_empty, NULL);
}

/* Same policy as the XDP side: drop when the backlog is full. Blocking
 * here instead would stall the receive thread and turn a resolver
 * backlog into socket buffer overflow, which is harder to observe. */
static bool queue_push(struct udp_job *job)
{
	bool ok = true;

	pthread_mutex_lock(&q.lock);
	if (q.shutdown || q.count >= q.cap) {
		ok = false;
	} else {
		job->next = NULL;
		if (q.tail)
			q.tail->next = job;
		else
			q.head = job;
		q.tail = job;
		q.count++;
	}
	pthread_mutex_unlock(&q.lock);

	if (ok)
		pthread_cond_signal(&q.not_empty);
	return ok;
}

static struct udp_job *queue_pop_wait(void)
{
	struct udp_job *job = NULL;

	pthread_mutex_lock(&q.lock);
	while (!q.head && !q.shutdown)
		pthread_cond_wait(&q.not_empty, &q.lock);

	if (q.head) {
		job = q.head;
		q.head = job->next;
		if (!q.head)
			q.tail = NULL;
		q.count--;
	}
	pthread_mutex_unlock(&q.lock);
	return job;
}

static void queue_shutdown(void)
{
	pthread_mutex_lock(&q.lock);
	q.shutdown = true;
	pthread_mutex_unlock(&q.lock);
	pthread_cond_broadcast(&q.not_empty);
}

static void *worker_main(void *arg)
{
	(void)arg;

	for (;;) {
		struct udp_job *job = queue_pop_wait();
		uint8_t resp[DNS_MAX_MSG_LEN];
		size_t resp_len = 0;
		int rc;

		if (!job)
			break;

		rc = dns_resolve_query(job->msg, job->len, resp, sizeof(resp),
				       &resp_len, true);	/* UDP */

		if (rc == DNS_OK && resp_len > 0) {
			ssize_t n = sendto(sockfd, resp, resp_len, 0,
					   (struct sockaddr *)&job->client,
					   job->client_len);

			if (n > 0)
				atomic_fetch_add(&tx_count, 1);
		} else {
			atomic_fetch_add(&drop_parse, 1);
		}

		free(job);
	}

	return NULL;
}

static void on_signal(int sig)
{
	(void)sig;
	running = 0;
	if (sockfd >= 0)
		shutdown(sockfd, SHUT_RDWR);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-p PORT] [-w WORKERS]\n"
		"  -p, --port N      listen port (default 53)\n"
		"  -w, --workers N   resolver threads (default %d)\n",
		prog, DEFAULT_WORKERS);
}

int main(int argc, char **argv)
{
	static struct option longopts[] = {
		{ "port",    required_argument, NULL, 'p' },
		{ "workers", required_argument, NULL, 'w' },
		{ "help",    no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	pthread_t threads[MAX_WORKERS];
	struct sockaddr_in addr;
	int port = 53, one = 1, rcvbuf = 8 * 1024 * 1024;
	int c;

	while ((c = getopt_long(argc, argv, "p:w:h", longopts, NULL)) != -1) {
		switch (c) {
		case 'p': port = atoi(optarg); break;
		case 'w': num_workers = atoi(optarg); break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	if (num_workers < 1)
		num_workers = 1;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	//match the XDP side's buffering so neither arm wins on sizing
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons((uint16_t)port);

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind(%d): %s\n", port, strerror(errno));
		if (errno == EACCES)
			fprintf(stderr, "  ports below 1024 need root or CAP_NET_BIND_SERVICE\n");
		close(sockfd);
		return 1;
	}

	queue_init(MAX_PENDING);

	if (dns_backend_init(num_workers)) {
		fprintf(stderr, "dns_backend_init failed\n");
		close(sockfd);
		return 1;
	}

	struct dns_tcp_server *tcp_srv = dns_tcp_server_start(port);

	if (!tcp_srv)
		fprintf(stderr, "warn: TCP fallback unavailable, UDP-only\n");

	for (int i = 0; i < num_workers; i++) {
		if (pthread_create(&threads[i], NULL, worker_main, NULL)) {
			perror("pthread_create");
			num_workers = i;
			break;
		}
	}

	printf("baseline UDP server on port %d, %d workers\n", port, num_workers);
	fflush(stdout);

	while (running) {
		struct udp_job *job = malloc(sizeof(*job));
		ssize_t n;

		if (!job) {
			usleep(1000);
			continue;
		}

		job->client_len = sizeof(job->client);
		n = recvfrom(sockfd, job->msg, sizeof(job->msg), 0,
			     (struct sockaddr *)&job->client, &job->client_len);

		if (n < 0) {
			free(job);
			if (errno == EINTR)
				continue;
			break;
		}

		atomic_fetch_add(&rx_count, 1);
		job->len = (size_t)n;

		if (!queue_push(job)) {
			atomic_fetch_add(&drop_backlog, 1);
			free(job);
		}
	}

	printf("\nshutting down...\n");
	queue_shutdown();
	for (int i = 0; i < num_workers; i++)
		pthread_join(threads[i], NULL);

	printf("--- baseline udp ---\n");
	printf("  rx              %llu\n", (unsigned long long)atomic_load(&rx_count));
	printf("  tx              %llu\n", (unsigned long long)atomic_load(&tx_count));
	printf("  drop (parse)    %llu\n", (unsigned long long)atomic_load(&drop_parse));
	printf("  drop (backlog)  %llu\n", (unsigned long long)atomic_load(&drop_backlog));

	uint64_t tcp_acc = 0, tcp_rej = 0, tcp_q = 0, tcp_a = 0;

	dns_tcp_server_stats(tcp_srv, &tcp_acc, &tcp_rej, &tcp_q, &tcp_a);
	printf("--- tcp fallback ---\n");
	printf("  accepted        %llu\n", (unsigned long long)tcp_acc);
	printf("  rejected        %llu  (at %d connection cap)\n",
	       (unsigned long long)tcp_rej, DNS_TCP_MAX_CONNS);
	printf("  queries         %llu\n", (unsigned long long)tcp_q);
	printf("  answered        %llu\n", (unsigned long long)tcp_a);
	dns_tcp_server_stop(tcp_srv);

	dns_backend_fini();
	close(sockfd);
	return 0;
}
