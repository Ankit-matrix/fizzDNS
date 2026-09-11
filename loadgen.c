/* Small DNS load generator, so the benchmark does not depend on dnsperf
 * being installed. Keeps up to -c queries outstanding, reports loss and
 * latency percentiles.
 *
 *   ./loadgen -s 10.11.0.1 -n 20000 -c 500
 *
 * -u gives every query a unique QNAME, which defeats the cache. Use it
 * when you want to measure the resolver; leave it off when you want to
 * measure the packet path. */

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define MAX_ID 65536

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

static size_t build_query(uint8_t *b, uint16_t id, const char *name)
{
	size_t o = 0;

	b[o++] = (uint8_t)(id >> 8);
	b[o++] = (uint8_t)id;
	b[o++] = 0x01; b[o++] = 0x00;		//RD
	b[o++] = 0; b[o++] = 1;			//qdcount
	b[o++] = 0; b[o++] = 0;
	b[o++] = 0; b[o++] = 0;
	b[o++] = 0; b[o++] = 0;

	const char *p = name;

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		b[o++] = (uint8_t)l;
		memcpy(b + o, p, l);
		o += l;
		if (!dot)
			break;
		p = dot + 1;
	}
	b[o++] = 0;
	b[o++] = 0; b[o++] = 1;			//A
	b[o++] = 0; b[o++] = 1;			//IN
	return o;
}

int main(int argc, char **argv)
{
	const char *server = "127.0.0.1";
	const char *base = "www.example.com";
	int port = 53, total = 10000, conc = 100, timeout_ms = 3000;
	bool unique = false;
	int c;

	while ((c = getopt(argc, argv, "s:p:n:c:t:u")) != -1) {
		switch (c) {
		case 's': server = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 'n': total = atoi(optarg); break;
		case 'c': conc = atoi(optarg); break;
		case 't': timeout_ms = atoi(optarg); break;
		case 'u': unique = true; break;
		default:
			fprintf(stderr,
				"usage: %s [-s IP] [-p PORT] [-n QUERIES] [-c CONCURRENCY] [-u]\n",
				argv[0]);
			return 1;
		}
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in dst;

	if (fd < 0) {
		perror("socket");
		return 1;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, server, &dst.sin_addr) != 1) {
		fprintf(stderr, "bad server address '%s'\n", server);
		return 1;
	}
	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		perror("connect");
		return 1;
	}

	int sndbuf = 4 * 1024 * 1024;

	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sndbuf, sizeof(sndbuf));

	uint64_t *sent_at = calloc(MAX_ID, sizeof(uint64_t));
	uint64_t *lat = calloc(total, sizeof(uint64_t));
	int sent = 0, got = 0, outstanding = 0, nlat = 0, send_fail = 0;
	uint64_t t0 = now_ns(), last_progress = t0;

	while (got < total) {
		while (sent < total && outstanding < conc) {
			uint8_t buf[512];
			char name[64];
			uint16_t id = (uint16_t)(sent % MAX_ID);

			if (unique)
				snprintf(name, sizeof(name), "q%d.example.com", sent);
			else
				snprintf(name, sizeof(name), "%s", base);

			size_t n = build_query(buf, id, name);

			sent_at[id] = now_ns();
			if (send(fd, buf, n, MSG_DONTWAIT) < 0) {
				if (errno == EAGAIN || errno == ENOBUFS)
					break;		//let the drain catch up
				send_fail++;
				sent++;
				continue;
			}
			sent++;
			outstanding++;
		}

		struct pollfd p = { .fd = fd, .events = POLLIN };
		int ret = poll(&p, 1, 50);

		if (ret > 0) {
			for (;;) {
				uint8_t buf[1500];
				ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);

				if (n < 12)
					break;

				uint16_t id = (uint16_t)((buf[0] << 8) | buf[1]);

				if (sent_at[id]) {
					lat[nlat++] = now_ns() - sent_at[id];
					sent_at[id] = 0;
				}
				got++;
				outstanding--;
				last_progress = now_ns();
			}
		}

		if ((now_ns() - last_progress) / 1000000 > (uint64_t)timeout_ms) {
			if (sent >= total)
				break;		//everything left is lost
			outstanding = 0;	//give up on the stragglers, keep going
			last_progress = now_ns();
		}
	}

	double secs = (double)(now_ns() - t0) / 1e9;

	qsort(lat, (size_t)nlat, sizeof(uint64_t), cmp_u64);

	printf("sent        %d\n", sent);
	printf("received    %d\n", got);
	printf("lost        %d (%.2f%%)\n", sent - got,
	       sent ? 100.0 * (sent - got) / sent : 0.0);
	if (send_fail)
		printf("send errors %d\n", send_fail);
	printf("elapsed     %.3f s\n", secs);
	printf("throughput  %.0f qps\n", secs > 0 ? got / secs : 0.0);
	if (nlat) {
		printf("latency     min %.3f ms  p50 %.3f  p95 %.3f  p99 %.3f  max %.3f\n",
		       lat[0] / 1e6,
		       lat[nlat / 2] / 1e6,
		       lat[(int)(nlat * 0.95)] / 1e6,
		       lat[(int)(nlat * 0.99)] / 1e6,
		       lat[nlat - 1] / 1e6);
	}

	free(sent_at);
	free(lat);
	close(fd);
	return (sent - got) > sent / 100 ? 1 : 0;	//>1% loss is a failure
}
