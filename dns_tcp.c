#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "dns_iface.h"
#include "dns_tcp.h"

#define ACCEPT_POLL_MS		200
#define IDLE_TIMEOUT_SEC	30	/* backstop; shutdown() below is
					 * what actually makes stop()
					 * prompt rather than waiting
					 * this out */

struct dns_tcp_server {
	int listen_fd;
	pthread_t accept_thread;
	volatile sig_atomic_t stop;

	/* Fixed connection table instead of a linked list: stop() needs
	 * to shutdown() every open fd to unblock threads sitting in
	 * recv(), and a bounded array under one mutex makes that a single
	 * short critical section instead of coordinating with N threads
	 * each owning their own fd. -1 marks an empty slot. */
	pthread_mutex_t conns_lock;
	int conn_fds[DNS_TCP_MAX_CONNS];
	atomic_int active_conns;

	atomic_ullong accepted, rejected, queries, answered;
};

struct conn_ctx {
	struct dns_tcp_server *srv;
	int fd;
	int slot;
};

/* ---------------- connection table ---------------- */

/* Claims a slot and records fd in it, atomically with the free-slot
 * scan -- otherwise two accept-time checks could both see room and
 * both claim the last slot. Returns -1 if the table is full. */
static int conn_reserve(struct dns_tcp_server *srv, int fd)
{
	int slot = -1;

	pthread_mutex_lock(&srv->conns_lock);
	for (int i = 0; i < DNS_TCP_MAX_CONNS; i++) {
		if (srv->conn_fds[i] == -1) {
			slot = i;
			srv->conn_fds[slot] = fd;
			break;
		}
	}
	pthread_mutex_unlock(&srv->conns_lock);

	if (slot >= 0)
		atomic_fetch_add(&srv->active_conns, 1);
	return slot;
}

/* Frees the slot and closes fd under the SAME lock stop() uses to
 * shutdown() fds. Without that, stop()'s scan could shutdown() an fd
 * number that this thread already closed and the kernel already
 * recycled onto an unrelated socket -- close-then-reuse racing a
 * concurrent shutdown() on the same integer. Serialising close()
 * against the scan removes the window entirely. */
static void conn_release(struct dns_tcp_server *srv, int slot, int fd)
{
	pthread_mutex_lock(&srv->conns_lock);
	srv->conn_fds[slot] = -1;
	close(fd);
	pthread_mutex_unlock(&srv->conns_lock);

	atomic_fetch_sub(&srv->active_conns, 1);
}

/* ---------------- framing ---------------- */

/* A 2 byte length prefix can legitimately arrive in its own TCP
 * segment, separate from the message it describes, so "short read" is
 * routine, not an error -- loop until n bytes, EOF, or a real error. */
static bool read_full(int fd, uint8_t *buf, size_t n)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = recv(fd, buf + got, n - got, 0);

		if (r == 0)
			return false;		//peer closed, or EOF
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return false;		//error, or our own timeout
		}
		got += (size_t)r;
	}
	return true;
}

static bool write_full(int fd, const uint8_t *buf, size_t n)
{
	size_t sent = 0;

	while (sent < n) {
		ssize_t w = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		sent += (size_t)w;
	}
	return true;
}

/* ---------------- per connection ---------------- */

static void *conn_main(void *arg)
{
	struct conn_ctx *ctx = arg;
	struct dns_tcp_server *srv = ctx->srv;
	int fd = ctx->fd, slot = ctx->slot;
	struct timeval tv = { .tv_sec = IDLE_TIMEOUT_SEC, .tv_usec = 0 };
	int one = 1;

	free(ctx);

	/* TCP DNS messages carry no realistic size limit of their own --
	 * DNS_MAX_ANSWERS bounds the record count, not the bytes, and a
	 * chain of long CNAME hops (each written out in full past the
	 * first, per dns_build_response()) can genuinely exceed 512
	 * bytes. Heap allocated per connection rather than on the stack:
	 * up to DNS_TCP_MAX_CONNS of these exist at once. */
	uint8_t *query = malloc(DNS_MAX_TCP_MSG_LEN);
	uint8_t *resp = malloc(DNS_MAX_TCP_MSG_LEN);

	if (!query || !resp)
		goto done;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	/* RFC 7766: a single connection may carry more than one query in
	 * sequence, each with its own 2 byte length prefix. Keep serving
	 * this connection until the client closes it, goes idle past the
	 * timeout, or stop() shuts it down from under us. */
	for (;;) {
		uint8_t lenbuf[2];

		if (!read_full(fd, lenbuf, 2))
			break;

		uint16_t mlen = (uint16_t)((lenbuf[0] << 8) | lenbuf[1]);

		if (mlen == 0)
			break;			//nothing legal is this size
		if (!read_full(fd, query, mlen))
			break;

		atomic_fetch_add(&srv->queries, 1);

		size_t resp_len = 0;
		int rc = dns_resolve_query(query, mlen, resp,
					   DNS_MAX_TCP_MSG_LEN, &resp_len,
					   false);	/* TCP: no UDP size cap */

		if (rc != DNS_OK || resp_len == 0 ||
		    resp_len > DNS_MAX_TCP_MSG_LEN) {
			/* Unanswerable: dns_backend.c's reasoning applies
			 * here too -- if we can't even identify the
			 * transaction, there's nothing coherent to send
			 * back. The framing stayed in sync since we read
			 * exactly mlen bytes either way, so the connection
			 * itself is still fine for the next query. */
			continue;
		}

		uint8_t outlen[2] = {
			(uint8_t)(resp_len >> 8),
			(uint8_t)resp_len,
		};

		if (!write_full(fd, outlen, 2) || !write_full(fd, resp, resp_len))
			break;

		atomic_fetch_add(&srv->answered, 1);
	}

done:
	free(query);
	free(resp);
	conn_release(srv, slot, fd);
	return NULL;
}

/* ---------------- accept loop ---------------- */

static void *accept_main(void *arg)
{
	struct dns_tcp_server *srv = arg;
	struct pollfd pfd = { .fd = srv->listen_fd, .events = POLLIN };

	while (!srv->stop) {
		int ret = poll(&pfd, 1, ACCEPT_POLL_MS);

		if (ret <= 0)
			continue;		//timeout, or EINTR: recheck stop

		int fd = accept(srv->listen_fd, NULL, NULL);

		if (fd < 0) {
			if (errno != EINTR)
				continue;	//transient, try again next poll
			continue;
		}

		int slot = conn_reserve(srv, fd);

		if (slot < 0) {
			/* At the connection cap. Dropping a fresh accept()
			 * is the honest answer, same policy as the UDP
			 * paths' backlog-full drop -- accepting it just to
			 * immediately starve it behind everyone else helps
			 * no one. */
			atomic_fetch_add(&srv->rejected, 1);
			close(fd);
			continue;
		}

		struct conn_ctx *ctx = malloc(sizeof(*ctx));

		if (!ctx) {
			conn_release(srv, slot, fd);
			continue;
		}
		ctx->srv = srv;
		ctx->fd = fd;
		ctx->slot = slot;

		pthread_t th;

		if (pthread_create(&th, NULL, conn_main, ctx)) {
			free(ctx);
			conn_release(srv, slot, fd);
			continue;
		}
		pthread_detach(th);
		atomic_fetch_add(&srv->accepted, 1);
	}

	return NULL;
}

/* ---------------- public ---------------- */

struct dns_tcp_server *dns_tcp_server_start(int port)
{
	struct dns_tcp_server *srv = calloc(1, sizeof(*srv));

	if (!srv)
		return NULL;

	for (int i = 0; i < DNS_TCP_MAX_CONNS; i++)
		srv->conn_fds[i] = -1;
	pthread_mutex_init(&srv->conns_lock, NULL);

	srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv->listen_fd < 0) {
		fprintf(stderr, "tcp: socket(): %s\n", strerror(errno));
		free(srv);
		return NULL;
	}

	int one = 1;

	setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = htons((uint16_t)port),
	};

	if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "tcp: bind(%d): %s\n", port, strerror(errno));
		if (errno == EACCES)
			fprintf(stderr,
				"  ports below 1024 need root or CAP_NET_BIND_SERVICE\n");
		close(srv->listen_fd);
		free(srv);
		return NULL;
	}

	if (listen(srv->listen_fd, 128) < 0) {
		fprintf(stderr, "tcp: listen(): %s\n", strerror(errno));
		close(srv->listen_fd);
		free(srv);
		return NULL;
	}

	if (pthread_create(&srv->accept_thread, NULL, accept_main, srv)) {
		fprintf(stderr, "tcp: pthread_create: %s\n", strerror(errno));
		close(srv->listen_fd);
		free(srv);
		return NULL;
	}

	printf("tcp fallback listening on port %d (max %d connections)\n",
	       port, DNS_TCP_MAX_CONNS);
	return srv;
}

void dns_tcp_server_stop(struct dns_tcp_server *srv)
{
	if (!srv)
		return;

	srv->stop = 1;
	pthread_join(srv->accept_thread, NULL);
	close(srv->listen_fd);

	/* Every connection thread is detached, so we can't pthread_join()
	 * them individually -- but we can make sure none of them is stuck
	 * in a blocking recv()/send() by shutting down every fd still in
	 * the table. Each thread then unwinds on its own and clears its
	 * slot via conn_release(). */
	pthread_mutex_lock(&srv->conns_lock);
	for (int i = 0; i < DNS_TCP_MAX_CONNS; i++)
		if (srv->conn_fds[i] != -1)
			shutdown(srv->conn_fds[i], SHUT_RDWR);
	pthread_mutex_unlock(&srv->conns_lock);

	while (atomic_load(&srv->active_conns) > 0)
		usleep(5000);

	pthread_mutex_destroy(&srv->conns_lock);
	free(srv);
}

void dns_tcp_server_stats(const struct dns_tcp_server *srv,
			  uint64_t *accepted, uint64_t *rejected,
			  uint64_t *queries, uint64_t *answered)
{
	if (!srv)
		return;
	if (accepted) *accepted = atomic_load(&srv->accepted);
	if (rejected) *rejected = atomic_load(&srv->rejected);
	if (queries)  *queries  = atomic_load(&srv->queries);
	if (answered) *answered = atomic_load(&srv->answered);
}