# Session 3 prompts — "Bloom filter"

Chat: `[FILL IN: claude.ai chat URL]`
Date: `[FILL IN]`

My messages, copied as sent, in order. Claude's replies were long (code +
measurement tables); a summary of what came back follows each.

---

### Prompt 1

> project : Project Description: This project implements a DNS resolver
> that sends and receives DNS packets using an AF_XDP (XSK) socket instead
> of the usual UDP/TCP socket. An XDP program attached to the NIC redirects
> DNS traffic (UDP dst port 53) to an AF_XDP socket; a user-space resolver
> crafts raw Ethernet/IPv4/UDP/DNS frames, transmits them via the XSK TX
> ring, and receives responses on the XSK RX ring. The project demonstrates
> low-latency, high-throughput packet I/O, zero-copy packet handling
> tradeoffs, and the extra plumbing required (UMEM, rings, descriptor
> management) compared to conventional sockets. Tools / Technologies Linux
> kernel AF_XDP / XDP support (recent kernel) clang/llvm (for compiling the
> XDP BPF program) libbpf / libxsk (or equivalent XSK helper code) for
> user-space XSK setup C (user-space resolver) for packet crafting and XSK
> ring handling bpftool / xdp-loader (to load/attach the XDP program)
> tcpdump / Wireshark / pkt-gen (for validation and packet inspection)
> Expected Outcome: Comparison vs standard UDP sockets: measurements of
> latency, throughput, and CPU overhead showing AF_XDP tradeoffs (zero-copy
> performance benefits vs implementation complexity).
>
> we are done with most part , i want to add bloom filter additionally in
> this : Before hitting the hash map, use a Bloom filter (implementable as
> a BPF array with bit operations) to quickly determine "definitely not in
> cache" vs "maybe in cache". Saves map lookup overhead for cold queries.
>
> also add some testing mechanism for this

(Attached: `dns_ax.zip`, the current codebase.)

**What came back:** Two design decisions stated up front, both departing
from the brief:

- **Not in the kernel.** `af_xdp_kern.c` only classifies and redirects — no
  cache lookup, no BPF map cache to guard. A filter there could only say
  "not cached", and a miss must reach userspace anyway, so it saves nothing
  and adds a userspace→kernel sync problem. Put in front of
  `dns_cache.c`'s userspace hash table instead. Noted
  `BPF_MAP_TYPE_BLOOM_FILTER` exists natively since 5.16 if the kernel-side
  version is wanted for the report.
- **Not a plain bit vector.** The cache deletes (LRU + TTL), so a plain
  filter's bits only accumulate, FPR climbs to 1, and it decays into a
  branch that always says "maybe" — passing a naive test suite while
  silently useless. Used a counting filter: 65536 one-byte counters
  (64 KiB), k=4, m/n=16 at 4096-entry capacity, analytic FPR ≈ 0.24%.

Delivered `dns_bloom.h/.c`, `bench_bloom.c`, a patch, and three test layers
in `make test` (212 checks). Reported an A/B table showing 1.55× at 99%
cold — and **0.90×, i.e. ~10% slower, at 0% cold**, presented as the honest
finding.

---

### Prompt 2

> make sure there's much overhead (like bloom filter usually doesn't) and
> ensure that caching is done alright

**What came back:** The challenge was accepted as valid — "a Bloom check
should cost a handful of nanoseconds, not 10%" — and the cause was found:
the filter had been instrumented with shared `_Atomic` counters
`fetch_add`ed on every lookup, i.e. a lock-prefixed RMW on a cache line
every worker writes. Isolated: 14.58 ns with counters vs 4.90 ns without.
Fixed by sharding stats one cache line per thread.

A blocked cache-line layout was also tried and **discarded on
measurement** (41.6 vs 34.2 ns cold), not kept as a plausible-sounding
optimisation.

Post-fix: hit path indistinguishable from no-bloom (~4 ns against 169–199
ns run-to-run spread), cold path 1.84×. The 0.90× regression gone entirely.

On the caching question: added a differential test (identical hit counts
through both binaries at every miss ratio — zero lost hits), a concurrent
test, and `make test-race` under TSan (213 checks, 0 failures).

**It also self-reported a bug in its own new test:** the first
`test_cache_concurrent()` showed a 0.0% hit rate and passed. Key was
`seed % CT_KEYS`, put/get branch was `seed & 1`, so puts only touched odd
keys and gets only even ones — a green test exercising nothing. Fixed, with
the explanation left in the source comment.

Still flagged, unfixed: `dns_cache_init()` zeroes the bucket table without
freeing nodes, so calling it twice leaks. Pre-existing; worked around in
tests with an explicit `fini()`.
