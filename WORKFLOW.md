# WORKFLOW — setup, run, benchmark

Ordered by how much machine access each stage needs. Stages 1 and 2
need nothing but a compiler; stage 4 needs root and a real NIC. Do them
in order — if stage 2 fails there is no point debugging stage 4.

---

## Stage 0 — Dependencies

```sh
sudo apt-get update
sudo apt-get install -y \
	build-essential clang llvm \
	libbpf-dev libxdp-dev libelf-dev zlib1g-dev pkg-config \
	iproute2 ethtool bind9-dnsutils python3
```

For `make verify` you also need `bpftool`. On Ubuntu it lives in
`linux-tools-generic`:

```sh
sudo apt-get install -y linux-tools-common linux-tools-generic
```

`/usr/sbin/bpftool` is a wrapper that refuses to run unless a
`linux-tools` package matches your *running* kernel — which fails in
containers and on custom kernels. The real binary under
`/usr/lib/linux-tools-*/bpftool` works regardless, and the Makefile
prefers it automatically.

If you built libbpf or xdp-tools out of tree:

```sh
make LIBBPF_DIR=/path/to/libbpf XDP_TOOLS_DIR=/path/to/xdp-tools
```

---

## Stage 1 — Build

```sh
make
```

Produces four binaries and one BPF object:

```
                  real resolver          stub backend
AF_XDP            af_xdp_user            af_xdp_user_stub
UDP               server                 server_stub

                  af_xdp_kern.o          (the XDP program)
```

Expect **zero warnings**. The build is `-Wall -Wextra`; if something
warns, fix it before continuing rather than scrolling past it.

```sh
make verify        # load af_xdp_kern.o into the kernel verifier
```

Prints `verifier OK`. This needs root but no NIC, and catches BPF
problems before you go anywhere near a network setup. A successful
load reports the JIT size and bound map ids:

```
xdp  name xdp_dns_redirect  tag 29f517e4749b2451  gpl
xlated 2376B  jited 1385B  map_ids 6,5
```

---

## Stage 2 — Test without a network, NIC, or root

Run all four. They take about a minute total and none of them needs
privileges.

```sh
make test          # 227 unit checks, ASan + UBSan
make test-race     # the same suite under ThreadSanitizer
make offline       # 28 integration checks vs an honest DNS hierarchy
make adversarial   # 36 full-stack checks vs a hierarchy that lies
```

What each one is actually for:

| Target | Catches |
|---|---|
| `test` | wire-format bugs, cache logic, memory errors, Bloom filter invariants |
| `test-race` | the lock-free Bloom read path — invisible to a single-threaded ASan run |
| `offline` | referral following, glue, missing-glue fallback, CNAME chains, NXDOMAIN, NODATA |
| `adversarial` | cache poisoning, spoofed transaction IDs, and every feature running concurrently |

`test-race` is a separate build because TSan and ASan cannot be
combined.

**If `make adversarial` hangs**, check that nothing else is bound to
`127.0.0.21/22/23:53`. It needs root to bind port 53 on those aliases.

---

## Stage 3 — Run it for real, over UDP first

The UDP control arm needs no special setup, so use it to confirm the
resolver core works on your machine before adding AF_XDP:

```sh
sudo ./server -p 5353 -w 8
dig @127.0.0.1 -p 5353 www.example.com
```

Point it at a fake root instead of the real one if you have no outbound
DNS:

```sh
sudo python3 fake_hierarchy.py &
sudo DNS_ROOT_HINTS=127.0.0.11 ./server -p 5353 -w 8
dig @127.0.0.1 -p 5353 www.example.com     # expect 93.184.216.34
```

---

## Stage 4 — AF_XDP on a veth pair

You cannot send to yourself over an interface you have bound an XSK to,
so the client has to live in a separate network namespace.

```sh
sudo ip link add veth0 type veth peer name veth1
sudo ip netns add ns1
sudo ip link set veth1 netns ns1
sudo ip addr add 10.11.0.1/24 dev veth0
sudo ip link set veth0 up
sudo ip netns exec ns1 ip addr add 10.11.0.2/24 dev veth1
sudo ip netns exec ns1 ip link set veth1 up

# Nothing answers ARP on the XDP side, so pin both entries by hand.
sudo ip netns exec ns1 ip neigh replace 10.11.0.1 \
	lladdr $(cat /sys/class/net/veth0/address) dev veth1
sudo ip neigh replace 10.11.0.2 \
	lladdr $(sudo ip netns exec ns1 cat /sys/class/net/veth1/address) dev veth0
```

Run it:

```sh
sudo ./af_xdp_user -d veth0 --filename ./af_xdp_kern.o -S -w 8
```

Query from the other namespace:

```sh
sudo ip netns exec ns1 dig @10.11.0.1 www.example.com
```

**Read the startup line.** It tells you what was actually negotiated:

```
xsk: veth0 q0, copy mode, need-wakeup
```

On veth you will see `copy mode`. That is expected and it is the whole
reason stage 5 exists. Do not quote zero-copy numbers from a veth run.

Tear down with `sudo ip link del veth0 && sudo ip netns del ns1`.

---

## Stage 5 — A real NIC, for the numbers that matter

Everything above works on veth in generic (`-S`) mode. Neither
demonstrates kernel bypass: generic XDP hooks *after* the skb is
allocated, and AF_XDP in generic mode copies into the UMEM. To measure
what the project claims, you need a driver with AF_XDP zero-copy
support (i40e, ice, ixgbe, mlx5, ...) on bare metal or a VM with SR-IOV
passthrough.

Drop `-S` and confirm the startup line says `zero-copy`:

```sh
sudo ./af_xdp_user -d eth0 --filename ./af_xdp_kern.o -w 8
```

If it says `copy mode`, the driver declined; no amount of
configuration will change that.

---

## Stage 6 — Multi-core

### 6a. Kernel side, on the host

A container cannot do this — queue counts and IRQ affinity are
properties of the device and its interrupts.

```sh
sudo systemctl stop irqbalance     # or it reverts step 2 in seconds
sudo ./setup-2core.sh eth0 0 1
```

That script does two things:

1. `ethtool -L eth0 combined 2` — RSS needs somewhere to spread to.
   With one queue, a second socket has nothing to bind and your second
   core idles no matter what user space does.
2. Pins one queue's IRQ to each core. Miss this and both NAPI polls
   land on the same core: user space is parallel, the kernel half is
   not.

The XDP program needs no changes. It already keys its redirect on
`ctx->rx_queue_index`, so a socket registered at XSKMAP index N
receives queue N automatically.

### 6b. User side

```sh
sudo ./af_xdp_user -d eth0 --filename ./af_xdp_kern.o --queues 2 -w 4
```

One socket, UMEM, ring set and pinned thread per queue. On shutdown it
prints a per-queue breakdown:

```
--- per rx queue ---
  q0  cpu0     rx 481203     tx 481198    (49.8% of rx)
  q1  cpu1     rx 485011     tx 485009    (50.2% of rx)
```

**Check that split.** If it is 95/5, RSS is not spreading and you are
measuring one core with extra steps.

The resolver refuses to start if the NIC has more queues than you are
serving, because the unserved queues' traffic is silently dropped while
the UDP control arm receives from all of them — which biases the
comparison against AF_XDP. `-M` overrides if you mean it.

### 6c. Containerised

```sh
IFACE=eth0 docker compose -f docker-compose.mt.yml up resolver
```

Use `cpuset`, not `cpus`. `cpus: 2.0` is a CFS quota that throttles at
100 ms period boundaries, producing latency spikes that look like
contention. Pin to physical cores, not hyperthread siblings.

---

## Stage 7 — Benchmarking

### Bloom filter A/B (no NIC needed)

```sh
make bench
```

Sweeps the cold-query fraction with both builds. On a multi-core box,
also sweep thread count:

```sh
for t in 1 2 4 8; do
	taskset -c 0-$((t-1)) ./bench_bloom   -t $t -n 2000000 -c 90
	taskset -c 0-$((t-1)) ./bench_nobloom -t $t -n 2000000 -c 90
done
```

The filter's justification is that it lets a miss skip a *contended*
mutex, so the gap should widen with thread count. If it stays flat, the
filter still helps but not for that reason, and the report should say
so.

### Transport comparison

```sh
sudo ./run_tests.sh
```

**Three things to fix or disclose before quoting any number:**

1. **The control arm is naive.** `server.c` is one socket, one
   `recvfrom` thread — no `SO_REUSEPORT`, no `recvmmsg`. The result is
   "AF_XDP beats a single-threaded recvfrom loop", not "AF_XDP beats
   UDP sockets". Real resolvers use `SO_REUSEPORT` with N sockets.
2. **`-S` cannot show bypass.** Generic XDP plus a UMEM copy. Sanity
   check: under `-S`, `xdp_stub_poll` and `xdp_stub_copy` should be
   near-identical, since generic mode is always copy mode.
3. **The arms use different links.** `run_udp` uses `127.0.0.1` (`lo`:
   no driver, 64 KB MTU) while the XDP arm uses veth. Put both on the
   same veth pair.

Use the `_stub` binaries for packet-path measurements. The real
backend blocks on upstream DNS with a 2 s timeout, so throughput is
capped by worker count and you would be measuring the resolver, not the
transport.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `xsk_socket__create: Invalid argument` | no `CAP_NET_ADMIN`, or the driver has no AF_XDP support. Try `-S` |
| `setrlimit(MEMLOCK): Operation not permitted` | harmless warning; only matters pre-5.11 |
| Queries time out, no RX counted | XSK bound to a queue RSS isn't using — see stage 6a |
| `ERR: eth0 has N rx queues...` | working as intended; use `--queues N` or `ethtool -L` |
| Startup says `copy mode` on a real NIC | driver declined zero-copy; nothing to configure |
| `bpftool: not found` on `make verify` | `apt install linux-tools-generic` |
| `make adversarial` hangs | something else is on `127.0.0.21/22/23:53`, or not root |
| Per-queue split is lopsided | RSS hashing, or IRQ affinity was reverted by `irqbalance` |

### A shell gotcha worth knowing

`pkill -f evil_hierarchy` matches the shell's **own** command line and
kills your session. Use a bracket pattern:

```sh
pkill -f "[e]vil_hierarchy"
```

---

## What has and has not been verified

| | Status |
|---|---|
| Build, 4 binaries + BPF object | 0 warnings |
| `make verify` (kernel verifier) | passes — loads, JITs to 1385 B |
| `make test` | 227 checks, 0 failures |
| `make test-race` | 0 TSan warnings |
| `make offline` | 28 checks, 0 failures |
| `make adversarial` | 36 checks, 0 failures |
| **AF_XDP RX/TX data path** | **never executed** |

The last row is the one to keep in mind. The packet path — especially
the multi-queue restructure — is compiled, race-reviewed and reasoned
about, but has not been run, because the development environment had
neither `CAP_NET_ADMIN` nor a capable driver. **Bring it up with
`--queues 1` first** and confirm it matches the previous single-loop
behaviour before trusting `--queues 2`.
