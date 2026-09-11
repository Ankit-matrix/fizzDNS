# AF_XDP DNS resolver

A recursive DNS resolver whose packet path bypasses the kernel network
stack via AF_XDP, plus a conventional UDP server as the control arm.

## Layout

**Packet path — kernel side**

| File | What it is |
|---|---|
| `af_xdp_kern.c` | XDP program: classify and redirect DNS queries |

**Packet path — user side**

| File | What it is |
|---|---|
| `xsk_setup.h/.c` | UMEM, rings, socket creation, frame allocator |
| `af_xdp_user.c` | RX/TX loops, worker dispatch, frame construction |
| `server.c` | Baseline UDP server (control arm) |
| `dns_tcp.h/.c` | TCP/53 listener, shared by both transports |
| `dns_iface.h` | The contract between the two halves. Freeze it first |

**Resolver core**

| File | What it is |
|---|---|
| `dns_msg.h/.c` | Wire format: name codec, query/RR parsing, response building |
| `resolver.h/.c` | Iterative resolution from the root, and the acceptance rules |
| `dns_cache.h/.c` | Thread-safe LRU with real TTL handling |
| `dns_bloom.h/.c` | Counting Bloom filter in front of the cache |
| `dns_backend.c` | Glue implementing `dns_iface.h` |
| `resolver_stub.c` | Stand-in backend, and the benchmark isolation harness |

**Tests**

| File | What it is |
|---|---|
| `test_dns.c` | Unit tests, 227 checks, no network needed |
| `fake_hierarchy.py` | Offline root/TLD/auth chain that answers honestly |
| `test_resolver.py` | Integration tests, 28 checks against the fake chain |
| `evil_hierarchy.py` | Hostile chain: 7 named attacks on the resolver |
| `test_integration.py` | Full-stack tests, 36 checks: acceptance rules + concurrency |
| `run_integration.sh` | Brings up the hostile chain and runs them |

**Benchmarking and deployment**

| File | What it is |
|---|---|
| `bench_bloom.c` | A/B benchmark for the Bloom fast path |
| `loadgen.c` | Load generator, for when dnsperf is not installed |
| `run_tests.sh` | Benchmark harness |
| `setup-2core.sh` | Host-side kernel setup for a multi-core run |
| `docker-compose.mt.yml` | Two-core containerised run |
| `Dockerfile` | Single-container image, compiles at build time |
| `WORKFLOW.md` | Step-by-step setup, run, and benchmark guide |

## Build

```sh
make             # everything: 4 binaries + af_xdp_kern.o
make test        # 227 unit checks under ASan+UBSan
make test-race   # the same suite under ThreadSanitizer
make offline     # + 28 integration checks against the honest hierarchy
make adversarial # + 36 full-stack checks against a lying hierarchy
make bench       # Bloom filter A/B, sweeping the cold-query fraction
make verify      # check the BPF verifier accepts the kernel object
```

Needs `clang`, `libbpf-dev`, `libxdp-dev`, `libelf-dev`, `zlib1g-dev`.
If you built libbpf/xdp-tools out of tree, pass `LIBBPF_DIR=` and
`XDP_TOOLS_DIR=`; otherwise the system copies are used.

## Run

```sh
./af_xdp_user -d eth0 --filename ./af_xdp_kern.o -w 8
```

- `-Q N` — first rx queue id (default 0)
- `-n N` / `--queues N` — number of rx queues to serve, one socket and
  one pinned thread each (default 1)
- `--no-pin` — do not pin rx loop threads to cpus
- `-M` / `--allow-multiqueue` — run while serving fewer queues than the
  NIC has, accepting that the rest of the traffic is dropped
- `-b` / `--busy-poll` — spin instead of blocking in `poll()`
- `-c` / `--copy` — force `XDP_COPY`, to measure what zero-copy buys
- `-S` / `--skb-mode` — generic XDP; works on veth, **never zero-copy**
- `-w N` — resolver threads
- `-v` — per-query service latency

While it runs, `bpftool map dump name xdp_dns_stats` shows the
kernel-side classification counters live.

### Check the bind mode, not the attach mode

`xdp-loader status` reports the *attach* mode (native vs generic). That
is **not** the same as AF_XDP zero-copy, which is a *bind* flag —
native attach with a copy-mode bind is routine, and veth gives you
exactly that. The resolver prints what it actually negotiated at
startup and warns on `-EOPNOTSUPP` fallback:

```
xsk: eth0 q0, zero-copy, need-wakeup
```

Read that line. Any claim about zero-copy in the report should cite it.

## Using more than one core

An AF_XDP socket binds **one** rx queue. Parallelism therefore needs
work on both sides, and they are genuinely separate problems.

### Kernel side — per interface, and it must be done on the host

A container cannot set queue counts or IRQ affinity; both are
properties of the device and its interrupts. `setup-2core.sh` does it:

```sh
sudo ./setup-2core.sh eth0 0 1
```

1. `ethtool -L eth0 combined 2` — RSS needs somewhere to spread to.
   With one queue the second socket has nothing to bind and your second
   core idles no matter what user space does.
2. One queue's IRQ per core. Miss this and both NAPI polls land on the
   same core: user space is parallel, the kernel half is not, and you
   are measuring one core's softirq capacity.

The XDP program itself needs **no changes**. It already redirects with
`ctx->rx_queue_index` as the XSKMAP key, so a socket registered at
index N automatically receives queue N. Nothing in the BPF object
differs between a one-core and an N-core run.

`irqbalance` will revert step 2 within seconds if it is running; the
script warns about this.

### User side — per queue

```sh
./af_xdp_user -d eth0 --filename ./af_xdp_kern.o --queues 2 -w 4
```

Each loop gets its own `xsk_env`, UMEM, rings, frame pool, completion
queue and eventfd, driven by exactly one pinned thread. Nothing is
shared between loops. That preserves the single-writer invariant the
whole AF_XDP side depends on, so a second core adds a second
independent packet path rather than a second contender for one.

One thing must be shared and one thing must not be. `pending_q` is
shared, because any worker can resolve any query. `done_q` cannot be: a
reply **must** leave through the socket it arrived on, since only that
loop's thread may touch its TX ring and frame stack. So each loop owns
a completion queue, and `struct dns_job` carries a `loop_idx` tag set
at RX.

The resolver refuses to start if the NIC has more queues than you are
serving. That is deliberate — the failure is otherwise silent and
biases the experiment in the wrong direction, since the unserved
queues' traffic is dropped by a kernel stack with nothing on port 53
while the UDP control arm, on an ordinary socket, receives from every
queue. Pass `-M` to override.

### Containerised

```sh
IFACE=eth0 docker compose -f docker-compose.mt.yml up resolver
```

Use `cpuset`, not `cpus`. `cpus: 2.0` is a CFS quota that throttles at
every 100 ms period boundary, which shows up as latency spikes that
look like contention. `cpuset` is hard placement with no throttling.
Pin to physical cores, not hyperthread siblings — two threads sharing
one core's L1 will make lock contention look better than it is.

On exactly two cores, `--queues 2` is right for the **stub** benchmark,
where packet-path cost is what you are isolating. For the real resolver
it may well be worse: the backend blocks on upstream UDP, so throughput
is bounded by worker count, and two rx loop threads now compete with
those workers for the same two cores. Measure both rather than
assuming.

## Four binaries, two pairs

```
                  real resolver          stub backend
AF_XDP            af_xdp_user            af_xdp_user_stub
UDP               server                 server_stub
```

Within each row both binaries link the **same** `dns_backend.o` or
`resolver_stub.o`. Not a copy — the same compiled object, called
through the same function. That is what reduces the comparison to one
independent variable. If each transport carried its own parsing and
response construction, a measured difference between them would be a
difference between two programs and you could not attribute it to the
transport at all.

## Three design decisions worth defending in the viva

**1. One thread owns all four rings.**

AF_XDP rings are single-producer/single-consumer lock-free structures.
The natural design — each resolver thread transmits its own answer —
puts N producers on the TX ring and N threads on an unsynchronised
free-frame stack. It compiles, runs, and passes a `dig` test. Under
concurrent load it corrupts descriptors, and the symptom is elevated
packet loss that reads as "AF_XDP is lossy" rather than "we have a data
race."

Here, workers only compute bytes. Answers come back through a
mutex-protected queue plus an `eventfd`, and the loop thread does every
ring operation. With `--queues N` this becomes N independent
single-owner loops, not N threads sharing one socket.

**2. The RX frame is released before resolution, not after.**

If a frame is held for the duration of an upstream resolve (~1 s for an
iterative walk from the roots), then a few hundred concurrent queries
exhaust a 4096-frame UMEM and the NIC starts dropping at the driver. We
copy the ≤512-byte DNS payload and the client addressing into a
self-contained job and recycle the frame in the same batch. RX pool
occupancy is bounded by batch size, not by resolver latency.

Cost: one 512-byte `memcpy` per query. That is the trade, and it is
obviously the right side of it.

**3. Blocking `poll()` is the default; busy-poll is a flag.**

`poll()` on two fds — the XSK and the done-queue `eventfd` — means an
idle resolver costs no CPU. The `-b` flag spins instead. Having both is
the point: the CPU-cost half of the comparison is meaningless without a
baseline.

## Kernel-side classification

The XDP program does more than a port match. A packet only reaches the
XSK if it is IPv4, unfragmented, UDP, dport 53, has a complete 12-byte
DNS header, QR=0, and QDCOUNT=1. Everything else takes `XDP_PASS`.

Three consequences:

- Userspace never wakes for stray responses or malformed frames.
- `XDP_PASS` as the `bpf_redirect_map` fallback means the box degrades
  to an ordinary host if the resolver dies, instead of blackholing
  port 53.
- There is no `bpf_printk` on the hot path. Every `trace_printk` is a
  formatted write into a per-CPU ring plus a global lock, per packet,
  and it dominates the cost of the program. Counters live in a
  `PERCPU_ARRAY` instead.

Userspace still re-validates lengths in `parse_frame()`. The kernel
filter is a fast path, not a trust boundary.

## Acceptance rules: what the resolver refuses to believe

A resolver that caches whatever it is told is a cache-poisoning
appliance. Three rules gate everything that enters the cache, and
`evil_hierarchy.py` attacks each of them.

**Bailiwick.** `dns_name_in_bailiwick(name, zone)` — a server may only
speak about names at or below the zone we are currently asking it
about. Without it, a `.com` nameserver can hand back a delegation for
`bank.co.uk`, or an A record in someone else's zone, and we cache it.
It gates referrals, glue and answers alike. The label-boundary check
matters: `notexample.com` ends with `example.com` as raw text, and a
naive suffix comparison accepts it.

**CNAME chain.** Answers are accepted only for names on the chain
starting at the queried name. This catches the sharper attack: a record
injected for a *different name inside the server's own zone* passes the
bailiwick check, and only the chain gate stops it. The answer section
is rescanned until the chain stops growing, since records are not
required to arrive in chain order and a single forward pass would drop
legitimate ones and produce spurious SERVFAILs.

**Referral progress.** A delegation must be strictly *below* the
current zone, and the queried name must actually live under it.
Otherwise a server can point at itself forever, or delegate a zone that
has nothing to do with the query.

**Transaction IDs come from `getrandom()`.** `rand_r` seeded from
`time(NULL) ^ &seed` is an LCG with a few dozen bits of real entropy;
one observed query reconstructs every ID the thread will ever emit. IDs
are drawn 64 at a time so this is not a syscall per query. There is
deliberately **no weak fallback** — if the CSPRNG is unavailable the
query fails, because a resolver that quietly degrades to guessable IDs
is worse than one that refuses.

**Responses must match the question back.** qdcount, qname
(case-insensitive), qtype, qclass. `connect()` on the upstream socket
narrows the source but does not authenticate content, and an ID match
alone will happily accept an answer about a name we never asked for.

**Rejection must not become denial of service.** After discarding a bad
datagram the resolver keeps reading until its timeout. Otherwise an
attacker denies service to any name simply by racing it with one
spoofed packet.

## The Bloom filter

A counting Bloom filter in front of the cache hash map. The point is
not to make a hit cheaper — a hit still walks the bucket. The point is
that a **miss** never takes the cache mutex at all: four relaxed byte
loads out of a 64 KiB array answer "definitely not cached" with no
lock, no chain walk and no cache-line ping-pong between workers.

**Counting, not plain bits, because this cache deletes.** LRU eviction
and TTL expiry both remove entries, and a plain filter cannot clear a
bit without risking a false negative for some other key that shares it.
Bits would only ever accumulate, the false-positive rate would climb
toward 1, and the filter would decay into a branch that always says
"maybe" — passing a naive test suite while quietly doing nothing.

65536 one-byte counters, k = 4, m/n = 16 at the 4096-entry cache
capacity. Analytic false-positive rate `(1 - e^(-kn/m))^k ≈ 0.24%`;
measured 0.255% over 100k probes.

Reads are lock-free; updates ride the existing cache mutex. Both race
directions are benign, and the suite is clean under ThreadSanitizer.

**Measured**, single thread, 3M lookups, median of 5 (ns/op):

| | all-miss | all-hit |
|---|---|---|
| Bloom | **35** | 180 |
| no Bloom | 64 | 176 |

1.84× on the cold path. On the hit path the two are indistinguishable —
the ~4 ns difference sits inside the run-to-run spread of 169–199.

Two things this measurement is **not**. It is single-core, so the
central claim that the saving comes from skipping a *contended* mutex
is untested; run `make bench` on a multi-core box and see whether the
gap widens with thread count. If it stays flat, the filter still helps
but for a different reason than claimed. And the multi-thread rows
`make bench` prints on a single-core machine reflect futex convoy, not
contention, so they should not be used to argue either way.

**Statistics are sharded per thread, one cache line each.** They began
as three shared `_Atomic` counters `fetch_add`ed on every lookup — a
lock-prefixed RMW on a line every worker writes, which measured ~10 ns
per lookup uncontended and turned the whole thing into a 10%
*regression* on the hit path. The filter existed to avoid exactly that
kind of shared write, and its own bookkeeping was reintroducing it.

A blocked layout (all k slots inside one cache line) was tried and
measured **worse** — 41.6 vs 34.2 ns — because the dedupe needed for
add/delete symmetry costs more than the cache misses it saves when
64 KiB largely sits in L2. The scattered layout was kept.

## Testing without a network, a NIC, or root

**`make offline`** stands up three fake servers on `127.0.0.11/12/13:53`
that behave like root, `.com` and an authoritative zone, then points the
resolver at them with `DNS_ROOT_HINTS=127.0.0.11`. That covers referral
following, glue handling, missing-glue fallback, CNAME chains and
NXDOMAIN in about two seconds, none of which is pleasant to test
against the live root servers.

**`make adversarial`** does the opposite: `evil_hierarchy.py` lies, and
the tests assert the lie did not land — in the answer *or* in the
cache. A dropped-but-cached record poisons everything afterwards even
though the first answer looks clean, so every attack has a follow-up
query checking the zone it tried to hijack.

| Attack | What it tries |
|---|---|
| 1 | Out-of-bailiwick referral (`.com` delegating `bank.co.uk`) |
| 2 | Out-of-bailiwick glue (`ns1.attacker.net`) |
| 3 | Foreign record stapled into the answer section |
| 4 | In-bailiwick but **off-chain** injection |
| 5 | Right question, wrong transaction ID |
| 6 | Right ID, question section for a different name |
| 7 | Spoofed reply first, genuine reply second |

Part B then drives every feature at once from 16–24 threads: hot names
(cache hits), unique cold names (Bloom rejects), attack names
(acceptance rules) and 4000 churn names (LRU eviction, so Bloom
counters go both up *and* down) — concurrently. Plus 24 threads racing
a first lookup of one uncached name, colliding on Bloom add, LRU insert
and lookup for the same key at the same instant.

The counters afterwards are the strongest evidence that the features
coexist:

```
cache hits      269        bloom lookups   2842
cache misses   2573        bloom rejects   2573  (90.5% skipped the lock)
live entries   2568        bloom slots     9518 / 65536
```

`269 + 2573 = 2842` exactly, and rejects equal misses exactly: under
adversarial concurrent load the filter and the map never disagreed.
9518 slots for 2568 live entries is 3.7 per entry against a k = 4
ceiling — collisions, and no counter leak.

**For the AF_XDP path** you need a veth pair, since you cannot send to
yourself over an interface you have bound an XSK to:

```sh
ip link add veth0 type veth peer name veth1
ip netns add ns1 && ip link set veth1 netns ns1
ip addr add 10.11.0.1/24 dev veth0 && ip link set veth0 up
ip netns exec ns1 ip addr add 10.11.0.2/24 dev veth1
ip netns exec ns1 ip link set veth1 up
# nothing answers ARP on the XDP side, so pin both entries
ip netns exec ns1 ip neigh replace 10.11.0.1 \
	lladdr $(cat /sys/class/net/veth0/address) dev veth1
ip neigh replace 10.11.0.2 \
	lladdr $(ip netns exec ns1 cat /sys/class/net/veth1/address) dev veth0
```

Then `./af_xdp_user -d veth0 --filename ./af_xdp_kern.o -S` and query
it with `ip netns exec ns1 dig @10.11.0.1 www.example.com`.

## Things the implementation does that are easy to get wrong

**Name decompression is bounded.** A compression pointer can point
anywhere in the message, including at itself. `dns_name_decode` refuses
forward and self-referential pointers and caps the jump count, so a
single crafted datagram cannot hang a worker thread. There are explicit
tests for the self-pointer, forward-pointer and ping-pong cases.

**The question section is echoed verbatim, not re-encoded.**
Re-encoding normalises the case, which breaks clients using DNS-0x20
for spoof resistance.

**TTLs come off the wire.** The cache stores an absolute expiry derived
from the shortest TTL in the RRset, clamped to `[5, 86400]`, and serves
the *remaining* TTL on lookup. A cache that pins every record for a
fixed 300 seconds serves stale data and will visibly disagree with
`dig` in a demo.

**Negative caching is separate.** NXDOMAIN is cached for 60 seconds;
SERVFAIL is never cached, because that's our failure, not a fact about
the zone.

**CNAME chains return the whole chain.** The client gets every CNAME
plus the final A record, in order. `deep.example.com` in the test
hierarchy exercises a two-hop chain.

**Truncated upstream responses are not parsed.** If TC is set, what
came back is incomplete; we try the next server rather than acting on a
partial referral.

**`setrlimit(RLIMIT_MEMLOCK)` failure is a warning, not an error.** It
is only needed on kernels before 5.11; since then BPF and UMEM memory
is charged to the cgroup. Treating it as fatal means the resolver
refuses to start in any container without `CAP_SYS_RESOURCE`, for no
reason.

## Bugs the tests caught

Worth mentioning in the report, because "we wrote tests and they found
things" is a stronger claim than "we wrote tests":

- **The TC bit was set from uninitialised memory.** The response header
  is written last, but the truncation path read `out[2..3]` back to
  decide whether to preserve TC — before anything had written it. On a
  dirty buffer that read garbage and set TC on responses that fit
  perfectly well, so `dig` reported `;; Truncated, retrying in TCP
  mode` and then failed, intermittently. Now tracked in a local `bool`.
  `test_build_response` poisons the output buffer with `0xFF` before
  every call specifically to catch this class of bug.
- The cache hash was case-sensitive while its comparison function was
  not, so `EXAMPLE.com` landed in a different bucket from `example.com`
  and never matched. Silent, and invisible until you query with mixed
  case.
- `memcpy` from a `NULL` source on negative cache entries — legal
  looking, UB, caught by UBSan.
- **`dns_tcp_server_start(53)` was called twice** in `af_xdp_user.c`.
  The second bind fails, `tcp_srv` is overwritten with `NULL`, and the
  first server is left running with no handle to stop it.
- **The Bloom filter's own statistics were a 10% regression.** See
  above. Found by benchmarking the thing that was supposed to be an
  optimisation, rather than assuming it was one.
- **A teardown path could have closed stdin.** `loops[].done_eventfd`
  is zero-initialised and 0 is a perfectly good fd; the error path
  closes every eventfd it finds. Now initialised to `-1`.
- **A concurrency test that tested nothing.** The first version picked
  the key with `seed % CT_KEYS` and branched put-vs-get on `seed & 1`,
  so puts only ever landed on odd keys and gets only read even ones.
  It reported a 0.0% hit rate — the tell that it was exercising
  nothing.

## Comparison with the reference implementation

Checked against
`github.com/Karan-Gandhi/AF_XDP-Low-Latency-DNS-Resolver`.

The **kernel side agrees**: both attach one program per interface and
redirect on `ctx->rx_queue_index`. This project additionally validates
`ihl`, fragmentation and the DNS header, keeps counters in a
`PERCPU_ARRAY` rather than `bpf_printk`, and falls back to `XDP_PASS`
rather than `XDP_ABORTED` — the reference blackholes port 53 if no XSK
is bound.

The **user side differs fundamentally**. The reference's worker threads
call `send_dns_response()`, `complete_tx()` and `xsk_free_umem_frame()`
concurrently on the same socket, while its main loop does the same. The
only mutex in that file guards its work queue. Its own vendored
`xsk.h` shows why this cannot work:

```c
*idx = prod->cached_prod;
prod->cached_prod += nb;        /* plain non-atomic RMW */
```

Two threads reserving at once get the same index, write the same
descriptor slot, and advance the producer pointer wrong. Its workers
also hold the RX UMEM frame for the entire resolution, which starves
the fill ring under concurrency.

One thing the reference does better: it rewrites the response into the
RX frame in place, with no copy at all. That is cheaper than the
query → job → response-frame path here, but is only safe
single-threaded. The two `memcpy`s buy a safe concurrent backend, and
that trade is worth naming explicitly in the report.

Its README also claims native attach mode means zero-copy works. It
does not — see "Check the bind mode, not the attach mode" above.

## Benchmark methodology — read before quoting any number

Three caveats a reviewer will raise within the first minute.

**The control arm is a naive UDP server.** `server.c` is one socket,
one `recvfrom` loop thread, N workers — no `SO_REUSEPORT`, no
`recvmmsg`. So the measured result is "AF_XDP beats a single-threaded
`recvfrom` loop", not "AF_XDP beats UDP sockets". Knot and Unbound use
`SO_REUSEPORT` with N sockets and batched receives, and that baseline
would close a large part of the gap. Either add a third arm or scope
the claim explicitly. A smaller defensible number beats a large
indefensible one.

**`run_tests.sh` runs the XDP arms with `-S`.** Generic XDP hooks in
`netif_receive_skb`, *after* the skb has been allocated, and AF_XDP in
generic mode copies into the UMEM. Those runs cannot demonstrate kernel
bypass or zero-copy; they measure AF_XDP carrying its full setup cost
plus an extra copy, and can come out slower than the UDP arm. A
falsifiable check: under `-S`, `xdp_stub_poll` and `xdp_stub_copy`
should be near-identical, because generic mode is always copy mode and
`-c` changes nothing.

**The two arms do not use the same link.** `run_udp` sets
`SERVER_IP=127.0.0.1`, so the control arm talks over `lo` — no driver,
64 KB MTU, no real queueing — while the XDP arm runs over veth in a
netns. That is a second uncontrolled variable sitting next to the one
being measured, and arguably the larger of the two. Running the UDP arm
over the same veth pair is a mechanical fix.

## Verification status

| | Status |
|---|---|
| Build | 0 warnings, 0 errors; 4 binaries + BPF object |
| `make test` | 227 checks, 0 failures (ASan + UBSan) |
| `make test-race` | 0 ThreadSanitizer warnings |
| `make offline` | 28 checks, 0 failures |
| `make adversarial` | 36 checks, 0 failures |
| `make verify` | passes — loads, JITs to 1385 B, binds 2 maps |
| **AF_XDP data path** | **never executed** |

That last row is the honest one. The RX/TX path — and in particular the
multi-queue restructure — is compiled, race-reviewed and reasoned
about, but `xsk_socket__create` needs privileges and a capable driver
that the development sandbox did not have. Bring it up with
`--queues 1` and confirm parity with the previous single-loop behaviour
before trusting `--queues 2`.

## Known limitations

- IPv4 and A records only for upstream resolution. AAAA returns NOTIMP
  rather than an empty NOERROR, which is at least honest.
- **No DNSSEC validation.** The acceptance rules above raise the bar
  for off-path spoofing considerably, but they are not authentication.
- **Upstream TCP fallback is not implemented.** Downstream is: a UDP
  response that doesn't fit sets TC, and both binaries listen on TCP/53
  for the retry. But when a root/TLD/auth server truncates *its* answer
  to us, we fall through to the next server rather than retrying over
  TCP.
- EDNS0 (RFC 6891) is supported: a client that sends an OPT record gets
  UDP responses up to 1232 bytes (the 2020 DNS-flag-day value) instead
  of the classic 512, and gets an OPT record echoed back. We hold
  ourselves to 1232 regardless of what a client claims to accept, to
  stay clear of IP fragmentation. EDNS options (cookies, NSID, ...) and
  DNSSEC (the DO bit) are parsed but not acted on. A client requesting
  protocol version > 0 is not sent BADVERS.
- **NODATA is not cached.** Every AAAA query for an A-only host goes
  upstream, forever — a permanent miss stream.
- **The backend caps throughput well below the packet path.** Each
  upstream query is a blocking `recv` with a 2 s timeout on a worker
  thread, so in-flight resolutions max out at the worker count. A
  microsecond-scale packet path feeding a backend that holds 8
  outstanding network waits is an architectural mismatch. The stub
  binaries exist to isolate the packet path from this; the real
  resolver's ceiling is worker count, not packet I/O.
- **`malloc`/`free` per packet.** `struct dns_job` carries two
  1500-byte buffers and is allocated in `parse_frame()`, on the loop
  thread. At the rates AF_XDP exists to reach, the allocator is a
  measurable fraction of the cost. A preallocated job pool would remove
  it.
- `dns_cache_init()` zeroes the bucket table without freeing existing
  nodes, so calling it twice leaks. Only reachable in tests, which work
  around it with an explicit `fini()`.
