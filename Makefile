# CS331 AF_XDP DNS resolver
#
#   make          everything
#   make test     unit tests (no network, no root, no NIC)
#   make offline  unit tests + resolver against a fake hierarchy
#   make verify   check the BPF verifier accepts the kernel object
#   make clean
#
# Four binaries, two pairs:
#
#                    real resolver      stub backend
#   AF_XDP           af_xdp_user        af_xdp_user_stub
#   UDP              server             server_stub
#
# Within each row both binaries link the SAME dns_backend.o or
# resolver_stub.o -- not a copy, the same compiled object called through
# the same function. That is what reduces the comparison to exactly one
# independent variable.

CLANG   ?= clang
CC      ?= gcc
# Ubuntu ships bpftool behind a version-matching wrapper that refuses to
# run when the running kernel has no linux-tools package. The real
# binary under /usr/lib works fine, so prefer whichever actually exists.
# Ubuntu's /usr/sbin/bpftool is a version-matching wrapper that refuses
# to run when the running kernel has no matching linux-tools package --
# common in containers and on custom kernels. The real binary under
# /usr/lib works regardless, so prefer it when it exists.
BPFTOOL ?= $(firstword $(wildcard /usr/lib/linux-tools-*/bpftool) bpftool)

# Set LIBBPF_DIR/XDP_TOOLS_DIR if you built them out of tree; by default
# we use whatever pkg-config finds, and fall back to the system paths.
LIBBPF_DIR    ?=
XDP_TOOLS_DIR ?=

CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -D_FORTIFY_SOURCE=0
CFLAGS  += -I.
LDFLAGS +=

ifneq ($(LIBBPF_DIR),)
CFLAGS  += -I$(LIBBPF_DIR)/root/usr/include
LDFLAGS += -L$(LIBBPF_DIR)
endif
ifneq ($(XDP_TOOLS_DIR),)
CFLAGS  += -I$(XDP_TOOLS_DIR)/headers
LDFLAGS += -L$(XDP_TOOLS_DIR)/lib/libxdp
endif

XDPLIBS := -lxdp -lbpf -lelf -lz -lpthread
UDPLIBS := -lpthread

# asm/types.h lives in the multiarch include dir, which clang does not
# pick up on its own when targeting bpf.
ARCH_INCLUDE := $(shell $(CC) -print-multiarch 2>/dev/null)
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I.
ifneq ($(ARCH_INCLUDE),)
BPF_CFLAGS += -I/usr/include/$(ARCH_INCLUDE)
endif
ifneq ($(LIBBPF_DIR),)
BPF_CFLAGS += -I$(LIBBPF_DIR)/root/usr/include
endif

A_OBJS   := af_xdp_user.o xsk_setup.o dns_tcp.o
KERN_OBJ := af_xdp_kern.o
B_OBJS   := dns_backend.o dns_msg.o dns_cache.o dns_bloom.o resolver.o
STUB_OBJ := resolver_stub.o

BINS  := af_xdp_user server af_xdp_user_stub server_stub
TESTS := test_dns test_dns_tsan
BENCH := bench_bloom bench_nobloom

.PHONY: all clean test test-race offline adversarial verify bench

all: $(KERN_OBJ) $(BINS)

$(KERN_OBJ): af_xdp_kern.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# real backend
af_xdp_user: $(A_OBJS) $(B_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(XDPLIBS)

server: server.o dns_tcp.o $(B_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(UDPLIBS)

# stub backend, for transport isolation
af_xdp_user_stub: $(A_OBJS) $(STUB_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(XDPLIBS)

server_stub: server.o dns_tcp.o $(STUB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(UDPLIBS)

# tests are pure userspace, no libxdp needed
test_dns: test_dns.c dns_msg.c dns_cache.c dns_bloom.c
	$(CC) -O1 -g -Wall -Wextra -I. -fsanitize=address,undefined -o $@ $^ -lpthread

test: test_dns
	./test_dns

# The lock-free filter read is the one thing here that a single-threaded
# ASan run cannot check. TSan is a separate build because it cannot be
# combined with ASan.
test-race: test_dns.c dns_msg.c dns_cache.c dns_bloom.c
	$(CC) -O1 -g -Wall -Wextra -I. -fsanitize=thread -o test_dns_tsan $^ -lpthread
	./test_dns_tsan

# Same source, two builds. A compile-time switch and not a runtime flag,
# so neither binary carries a branch the other does not.
BENCH_SRC := bench_bloom.c dns_msg.c dns_cache.c dns_bloom.c

bench_bloom: $(BENCH_SRC)
	$(CC) -O2 -Wall -Wextra -I. -o $@ $^ -lpthread

bench_nobloom: $(BENCH_SRC)
	$(CC) -O2 -Wall -Wextra -I. -DDNS_BLOOM_DISABLED -o $@ $^ -lpthread

# Sweeps the cold-query fraction, which is the variable the filter is
# sensitive to. -t defaults to the number of online CPUs: at one thread
# the cache mutex is uncontended and the result understates the effect.
BENCH_THREADS ?= $(shell nproc 2>/dev/null || echo 4)
BENCH_ITERS   ?= 2000000

bench: bench_bloom bench_nobloom
	@for c in 99 90 50 0; do \
		echo "=== $$c% cold, $(BENCH_THREADS) threads ==="; \
		./bench_bloom   -t $(BENCH_THREADS) -n $(BENCH_ITERS) -c $$c; \
		./bench_nobloom -t $(BENCH_THREADS) -n $(BENCH_ITERS) -c $$c; \
		echo; \
	done

offline: test server
	@echo
	@echo "starting fake root/TLD/auth hierarchy..."
	@python3 fake_hierarchy.py & sleep 2; \
	 DNS_ROOT_HINTS=127.0.0.11 ./server -p 5354 -w 4 & sleep 2; \
	 python3 test_resolver.py; rc=$$?; \
	 pkill -INT -x server; pkill -f fake_hierarchy; exit $$rc

# The honest hierarchy (make offline) proves resolution WORKS. This one
# proves it refuses to be lied to, and that the cache, Bloom filter and
# acceptance rules still behave when driven concurrently.
adversarial: server
	./run_integration.sh AB

verify: $(KERN_OBJ)
	$(BPFTOOL) prog load $(KERN_OBJ) /sys/fs/bpf/dns_test && \
		echo "verifier OK" && rm -f /sys/fs/bpf/dns_test

clean:
	rm -f *.o $(BINS) $(TESTS) $(BENCH)

af_xdp_user.o:   af_xdp_user.c xsk_setup.h dns_iface.h
xsk_setup.o:     xsk_setup.c xsk_setup.h
server.o:        server.c dns_iface.h
dns_backend.o:   dns_backend.c dns_iface.h dns_msg.h dns_cache.h resolver.h
dns_msg.o:       dns_msg.c dns_msg.h
dns_cache.o:     dns_cache.c dns_cache.h dns_bloom.h dns_msg.h
dns_bloom.o:     dns_bloom.c dns_bloom.h
resolver.o:      resolver.c resolver.h dns_msg.h dns_cache.h
resolver_stub.o: resolver_stub.c dns_iface.h
dns_tcp.o:       dns_tcp.c dns_tcp.h dns_iface.h