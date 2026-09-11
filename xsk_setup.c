#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xsk_setup.h"

const char *const xdp_dns_stat_names[STAT__MAX] = {
	[STAT_TOTAL]        = "total",
	[STAT_NOT_IPV4]     = "not_ipv4",
	[STAT_NOT_UDP]      = "not_udp",
	[STAT_NOT_DNS_PORT] = "not_dns_port",
	[STAT_MALFORMED]    = "malformed",
	[STAT_NOT_QUERY]    = "not_query",
	[STAT_REDIRECTED]   = "redirected",
};

int xsk_env_load_program(struct xsk_env *env, const char *ifname,
			 const char *bpf_obj, const char *progname,
			 enum xdp_attach_mode mode)
{
	char errmsg[256];
	int err;

	memset(env, 0, sizeof(*env));
	env->xsk_map_fd = -1;
	env->stats_map_fd = -1;
	env->attach_mode = mode;

	snprintf(env->ifname, sizeof(env->ifname), "%s", ifname);
	env->ifindex = if_nametoindex(ifname);
	if (!env->ifindex) {
		fprintf(stderr, "ERR: no such interface '%s': %s\n",
			ifname, strerror(errno));
		return -ENODEV;
	}

	if (!bpf_obj) {			//fall back to libxsk's own program
		env->custom_prog = false;
		env->owns_prog = true;
		return 0;
	}

	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts, .open_filename = bpf_obj);
	if (progname && progname[0])
		opts.prog_name = progname;

	env->prog = xdp_program__create(&opts);
	err = libxdp_get_error(env->prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: opening '%s': %s\n", bpf_obj, errmsg);
		env->prog = NULL;
		return err;
	}

	err = xdp_program__attach(env->prog, env->ifindex, mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: attaching to '%s': %s\n", ifname, errmsg);
		xdp_program__close(env->prog);
		env->prog = NULL;
		return err;
	}

	struct bpf_object *obj = xdp_program__bpf_obj(env->prog);
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, "xsks_map");
	if (!map) {
		fprintf(stderr, "ERR: 'xsks_map' not found in %s\n", bpf_obj);
		goto detach;
	}
	env->xsk_map_fd = bpf_map__fd(map);
	if (env->xsk_map_fd < 0) {
		fprintf(stderr, "ERR: bad fd for xsks_map\n");
		goto detach;
	}

	map = bpf_object__find_map_by_name(obj, "xdp_dns_stats");
	if (map)			//optional
		env->stats_map_fd = bpf_map__fd(map);

	env->custom_prog = true;
	env->owns_prog = true;
	return 0;

detach:
	xdp_program__detach(env->prog, env->ifindex, mode, 0);
	xdp_program__close(env->prog);
	env->prog = NULL;
	return -EINVAL;
}

static struct xsk_umem_info *configure_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
	int ret;

	if (!umem)
		return NULL;

	/* NULL config = libxsk defaults: 2048 entry fill and completion
	 * rings, 4096 byte frames, no headroom. */
	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		fprintf(stderr, "ERR: xsk_umem__create: %s\n", strerror(-ret));
		free(umem);
		return NULL;
	}

	umem->buffer = buffer;
	umem->size = size;
	return umem;
}

int xsk_env_setup_socket(struct xsk_env *env, int queue_id,
			 bool want_zerocopy, bool want_need_wakeup)
{
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	uint32_t idx;
	int ret;

	env->queue_id = queue_id;

	/* Only needed on kernels before 5.11; since then BPF and UMEM
	 * memory is charged to the cgroup instead. Warn and carry on --
	 * a container without CAP_SYS_RESOURCE can still run fine, and
	 * dying here means the resolver never starts for no reason. */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim))
		fprintf(stderr, "warn: setrlimit(MEMLOCK): %s (continuing)\n",
			strerror(errno));

	env->packet_buffer_size = (uint64_t)NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&env->packet_buffer, getpagesize(),
			   env->packet_buffer_size)) {
		fprintf(stderr, "ERR: cannot allocate %lu byte UMEM\n",
			(unsigned long)env->packet_buffer_size);
		return -ENOMEM;
	}

	env->umem = configure_umem(env->packet_buffer, env->packet_buffer_size);
	if (!env->umem) {
		free(env->packet_buffer);
		env->packet_buffer = NULL;
		return -EINVAL;
	}

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk) {
		ret = -ENOMEM;
		goto err_umem;
	}
	xsk->umem = env->umem;
	xsk->need_wakeup = want_need_wakeup;

	memset(&cfg, 0, sizeof(cfg));
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.xdp_flags = 0;
	cfg.bind_flags = want_zerocopy ? XDP_ZEROCOPY : XDP_COPY;
	if (want_need_wakeup)
		cfg.bind_flags |= XDP_USE_NEED_WAKEUP;
	/* We attached the program ourselves, stop libxsk loading its own. */
	cfg.libbpf_flags = env->custom_prog
			 ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;

	ret = xsk_socket__create(&xsk->xsk, env->ifname, queue_id,
				 env->umem->umem, &xsk->rx, &xsk->tx, &cfg);

	/* No veth and not every driver can do zero-copy. Retry in copy
	 * mode rather than dying, and remember which one we got so the
	 * benchmark reports it honestly. */
	if (ret == -EOPNOTSUPP && want_zerocopy) {
		fprintf(stderr,
			"WARN: zero-copy unsupported on %s, falling back to XDP_COPY\n",
			env->ifname);
		cfg.bind_flags &= ~XDP_ZEROCOPY;
		cfg.bind_flags |= XDP_COPY;
		ret = xsk_socket__create(&xsk->xsk, env->ifname, queue_id,
					 env->umem->umem, &xsk->rx, &xsk->tx,
					 &cfg);
		env->zerocopy = false;
	} else {
		env->zerocopy = want_zerocopy && !ret;
	}

	if (ret) {
		fprintf(stderr, "ERR: xsk_socket__create on %s q%d: %s\n",
			env->ifname, queue_id, strerror(-ret));
		goto err_xsk;
	}

	if (env->custom_prog) {
		ret = xsk_socket__update_xskmap(xsk->xsk, env->xsk_map_fd);
		if (ret) {
			fprintf(stderr, "ERR: xskmap update: %s\n",
				strerror(-ret));
			goto err_sock;
		}
	}

	/* Seed the free list with every frame, then hand the first half
	 * to the kernel for RX. What is left is the TX pool. */
	for (int i = 0; i < NUM_FRAMES; i++)
		xsk->umem_frame_addr[i] = (uint64_t)i * FRAME_SIZE;
	xsk->umem_frame_free = NUM_FRAMES;

	if (xsk_ring_prod__reserve(&xsk->umem->fq, FILL_RING_FRAMES, &idx)
	    != FILL_RING_FRAMES) {
		fprintf(stderr, "ERR: cannot reserve %d fill slots\n",
			FILL_RING_FRAMES);
		ret = -ENOSPC;
		goto err_sock;
	}
	for (int i = 0; i < FILL_RING_FRAMES; i++)
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) =
			xsk_alloc_frame(xsk);
	xsk_ring_prod__submit(&xsk->umem->fq, FILL_RING_FRAMES);

	env->xsk = xsk;

	printf("AF_XDP socket up on %s queue %d: %s, %d frames (%d fill / %d tx pool)\n",
	       env->ifname, queue_id,
	       env->zerocopy ? "zero-copy" : "copy mode",
	       NUM_FRAMES, FILL_RING_FRAMES, NUM_FRAMES - FILL_RING_FRAMES);

	return 0;

err_sock:
	xsk_socket__delete(xsk->xsk);
err_xsk:
	free(xsk);
err_umem:
	xsk_umem__delete(env->umem->umem);
	free(env->umem);
	env->umem = NULL;
	free(env->packet_buffer);
	env->packet_buffer = NULL;
	return ret;
}

bool xsk_env_is_zerocopy(const struct xsk_env *env)
{
	return env->zerocopy;
}

void xsk_env_clone_program(struct xsk_env *dst, const struct xsk_env *src)
{
	memset(dst, 0, sizeof(*dst));

	snprintf(dst->ifname, sizeof(dst->ifname), "%s", src->ifname);
	dst->ifindex      = src->ifindex;
	dst->attach_mode  = src->attach_mode;
	dst->xsk_map_fd   = src->xsk_map_fd;
	dst->stats_map_fd = src->stats_map_fd;
	dst->custom_prog  = src->custom_prog;

	/* prog stays NULL and owns_prog stays false, so teardown of this
	 * env frees its own rings and leaves the interface attachment
	 * alone -- detaching it here would silently kill every other
	 * socket's traffic. */
}

int xsk_env_read_kern_stats(struct xsk_env *env, uint64_t *out)
{
	int ncpus = libbpf_num_possible_cpus();

	if (env->stats_map_fd < 0 || ncpus <= 0)
		return -ENOENT;

	uint64_t *percpu = calloc(ncpus, sizeof(uint64_t));

	if (!percpu)
		return -ENOMEM;

	for (uint32_t key = 0; key < STAT__MAX; key++) {
		out[key] = 0;
		if (bpf_map_lookup_elem(env->stats_map_fd, &key, percpu))
			continue;
		for (int c = 0; c < ncpus; c++)
			out[key] += percpu[c];
	}

	free(percpu);
	return 0;
}

void xsk_env_teardown(struct xsk_env *env)
{
	if (env->xsk) {
		xsk_socket__delete(env->xsk->xsk);
		free(env->xsk);
		env->xsk = NULL;
	}
	if (env->umem) {
		xsk_umem__delete(env->umem->umem);
		free(env->umem);
		env->umem = NULL;
	}
	if (env->packet_buffer) {
		free(env->packet_buffer);
		env->packet_buffer = NULL;
	}
	if (env->prog && env->owns_prog) {
		xdp_program__detach(env->prog, env->ifindex, env->attach_mode, 0);
		xdp_program__close(env->prog);
		env->prog = NULL;
	}
}
