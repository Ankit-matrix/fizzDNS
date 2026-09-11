# dns_ax — Combined AI prompt log

All prompts, verbatim, in their original within-group order. Groups are
arranged design-first (scoping → packet path → resolver core), then
chronologically by session.

Sessions dated 5–11 September 2026.

---
---

# Part I — Design dialogue

## Group A — Scoping and architecture

Verbatim, in order. Note the explicit "do not write any code yet" — this
whole group is design dialogue, deliberately before implementation.

### Prompt A1

> I want to build a recursive DNS resolver whose packet path uses AF_XDP
> instead of the kernel network stack, and compare it against a plain UDP
> socket server. Before we discuss design: explain the AF_XDP data path
> precisely. What are the four rings, who produces and who consumes each,
> and what are the concurrency guarantees libbpf gives me on them? Quote
> the actual producer/consumer code from xsk.h if you can, don't
> paraphrase it. Do not write any code yet.

**Why phrased this way:** "quote, don't paraphrase" because the SPSC
guarantee is the load-bearing fact for the whole architecture, and a
paraphrase of a concurrency contract is exactly where a model smooths over
the detail that matters.

### Prompt A2

> Given that each ring is single-producer/single-consumer: I want N
> resolver worker threads, because an iterative walk from the roots blocks
> for ~1s and one thread can't cover that. Give me three candidate
> architectures for getting answers from N workers back onto one TX ring.
> For each: what breaks, under what load, and what the symptom looks like
> to someone who doesn't know the cause.

**Outcome:** the single-ring-owner design. One thread (the RX/TX loop)
touches the rings and frame allocator; workers only compute response bytes
and return them via a mutex-protected queue plus an `eventfd`. The
"symptom to someone who doesn't know the cause" clause is what tied this
to the ~18–19% packet loss in the prior implementation.

### Prompt A3

> This project has two halves: the packet path and the resolver core. I
> want to build them independently and have them meet. Design the single
> header that is the only thing both halves include. Constraints: the
> resolver core must never include xsk_setup.h, the packet path must never
> know how resolution works, and the same compiled backend object must
> link into both the AF_XDP binary and the UDP binary. Justify every
> parameter. In particular tell me what goes wrong if the response buffer
> capacity is implied rather than passed explicitly.

**Outcome:** `dns_iface.h`. Capacity is passed explicitly — an implied
capacity is how a 512-byte assumption becomes an overflow the day EDNS0 or
TCP raises the real limit.

### Prompt A4

> The deliverable is a comparison, so design the experiment first. What is
> the minimum set of binaries I need so that a measured difference between
> AF_XDP and UDP is attributable to the transport and nothing else? Then
> list every confounding variable that would still remain, and rank them by
> how badly they'd bias the result.

**Outcome:** the `_stub` binaries (`af_xdp_user_stub`, `server_stub`,
`resolver_stub.c`). The real backend blocks on upstream DNS for up to 2 s,
so benchmarking it measures the resolver, not the transport.

---

## Group B — Packet path / XDP program

### Prompt B1

> Write the XDP program. It should redirect only packets that are genuinely
> DNS queries — everything else takes XDP_PASS, including on redirect
> failure. Two constraints: no bpf_printk anywhere on the hot path, and
> tell me the per-packet cost of the one you'd otherwise have used. And
> explain why the fallback is XDP_PASS rather than XDP_ABORTED., I'll
> attach the final files holup

→ `af_xdp_kern.c`.

Three things are being asked for at once and each has a reason:

- **`XDP_PASS` on redirect failure** — a failed redirect should degrade to
  the normal kernel stack, not drop the packet. The resolver getting slower
  is recoverable; the resolver silently eating traffic is not.
- **`XDP_PASS` rather than `XDP_ABORTED`** — `XDP_ABORTED` drops *and*
  fires a tracepoint, so under any sustained failure it turns a degraded
  path into a second problem in the trace pipe.
- **No `bpf_printk` on the hot path, with its cost quantified** — asking
  for the number rather than accepting "it's slow" keeps the constraint
  arguable rather than superstitious.

### Subsequent prompts in this group

The closing "I'll attach the final files holup" indicates the exchange
continued with file attachments. Those messages were not recovered and are
therefore not reproduced here; they are not reconstructed from the
responses.

---

## Group C — Resolver core and cache-poisoning defence

### Prompt C1

> Implement the DNS wire format layer per RFC 1035: name encode/decode with
> compression pointers, question parsing, RR parsing, response building.
> Before writing it, list every way a malicious 512-byte datagram could
> make this code loop forever, read out of bounds, or allocate unboundedly.
> Then write the code with a named defence against each, and tell me which
> line implements which defence.

Produces code whose defences are traceable to a specific threat, which
makes review tractable — you check the mapping, not the whole file.
→ `dns_msg.c` / `dns_msg.h`.

### Prompt C2

> Iterative resolution means asking servers we don't trust. Write the rules
> that gate what may enter the cache. Frame it as an attacker: I am a .com
> nameserver and I want to poison this resolver. Enumerate every lie I can
> tell — in the referral, in the glue, in the answer section, in the
> transaction ID. For each lie, state the specific check that stops it, and
> then tell me the variant of the lie that check does NOT stop.

The last clause is the important one. Asking only for the defence gets a
confident list; asking for the residual gets the honest boundary of each
check.

### Prompt C3

> Is my bailiwick check label-aligned? Show me a name that ends with the
> zone as raw text but is not inside it.

Suffix matching is not containment — `evilexample.com` ends with
`example.com` as raw text and is not in that zone.

### Prompt C4

> Where do my transaction IDs come from? If the answer involves rand_r or
> time(NULL), tell me how many queries an observer needs to predict every
> future ID from that thread.

### Prompt C5

> I now reject bad datagrams. Have I just built a denial of service? What
> happens if an attacker races every legitimate response with one spoofed
> packet?

**Outcome:** discarding a spoofed response must not end the read. This is
the point carried in the Figure 4 caption in the report.

### Prompt C6

> Write a Python script that impersonates a root, a TLD and an
> authoritative server on loopback, and lies in each of the ways we
> enumerated. One named attack per lie. Then write the tests. For each
> attack assert two things: the lie is not in the answer, AND the lie is
> not in the cache.

**Outcome:** `evil_hierarchy.py` + `test_integration.py`. The two-part
assertion matters: answer-only checks would miss a poisoned cache that
serves the lie on the *next* query.

### Prompt C7

> Cache lookups take a mutex. Put a Bloom filter in front so a miss can
> answer "definitely not cached" without the lock. Constraint: this cache
> deletes — LRU eviction and TTL expiry both remove entries. Work out what
> that does to a plain bit-vector filter, and what it means for the
> filter's behaviour over a long run.

The constraint is stated rather than left for the model to notice. A plain
filter under deletion degrades silently — FPR climbs to 1 and it becomes a
branch that always says "maybe" — which passes tests and fails in
production.

### Prompt C8

> Benchmark it A/B and show me ns/op for all-miss and all-hit separately.
> If the hit path got slower, find out why before you explain it away.

The second sentence is the one that did the work. See Session 3 below — the
hit path *had* got slower, by ~10%, and the cause was the filter's own
atomic instrumentation, not the filter.

### Prompt C9

> State what this benchmark does NOT show.

Asked as a standing habit. In this case the answer was that every figure
was single-core, so the contention explanation for the filter's benefit
remained untested — which became the open question handed to whoever ran
the hardware measurements.

---
---

# Part II — Build sessions

## Session 1 — "Context check"

Date: 5 Sep 2026

These are my messages, copied as sent, in order. Claude's responses were
long (code + explanation); a one-line summary of what came back follows
each prompt. Full responses are in the chat itself / SUMMARY.md.

### Prompt 1.1

> Here's the context sire, check this out

(Attached: our team's existing write-up/notes on the project — brief,
subgroup split, our analysis of the benchmark numbers.)

**What came back:** Claude summarized the situation back to me, then
flagged two problems in our own numbers before I'd asked it anything —
an apparent unit error in a cycles-per-query table, and an inconsistency
between QPS and latency that it said probably meant our load generator
was the bottleneck. It then asked which of A1/A2/A3 I actually was,
since that changes what "finish Subgroup A" means.

### Prompt 1.2

> Get started and finish Subgroup A's work, then we will tweak and
> modify the codes, try to make it unique, so there's a distinction in
> the projects, let's go

**What came back:** Claude checked its own environment for a BPF/XDP
toolchain, found none, and wrote Subgroup A's files by hand
(`af_xdp_kern.c`, `xsk_setup.h/.c`, `af_xdp_user.c`, `dns_iface.h`,
`resolver_stub.c`, `Makefile`, `README_SUBGROUP_A.md`), syntax-checking
what it could against hand-built shim headers and fully
compiling-and-running the one dependency-free piece
(`resolver_stub.c`) with a small test driver it wrote itself.

### Prompt 1.3

> Complete part for B too

**What came back:** Claude built Subgroup B's files
(`dns_msg.h/.c`, `dns_cache.h/.c`, `resolver.c/.h`, `dns_backend.c`,
`server.c`, `test_dns.c`, `README_SUBGROUP_B.md`, `run_tests.sh`,
`Dockerfile`), and — because this environment had a working
compiler — actually built and ran the tests, found and fixed 3 real
bugs (case-sensitive cache hash, NULL-source memcpy, missing
`<stdio.h>`), got the unit suite to 78/78, built a fake offline DNS
hierarchy to test the iterative resolver without internet access, and
got the integration suite to 20/20.

---

## Session 2 — "dns_ax rewrite and testing"

Uploaded file: `dns_ax_ankitsaha.zip`
Date: 11 Sep 2026

These are my messages, copied as sent, in order.

### Prompt 2.1

> the files(1) contains the code that you gave me in a previous
> instance, now that was insanely buggy, and it was certainly not human
> like for sure, I have put in the zip a folder names "start" it
> contains an incomplete part of the project that I have typed using my
> own hands, it is comparatively concise and looks like what a human
> would type, you can take inspiration from it, your final goal is to
> give me a working code of the completed project, you may test it
> however many tims as you may like, but give me the final code that
> works and runs perfectly, run a few of your own tests, and check hwo
> well it performs

(Attached: `dns_ax_ankitsaha.zip`, containing `files (1)/` — the code
from session 1 — and `Start/` — my own hand-typed, incomplete version.)

**What came back:** Claude unzipped and read both folders, installed a
BPF/XDP toolchain, set up a veth pair + network namespace, built and
actually ran the session-1 code first and found two real bugs (the TC-
bit-from-uninitialized-memory bug, reproduced live with `dig`; and the
fatal `setrlimit` failure). It then rewrote the full project matching
the style of my `Start/` files, with a larger unit test suite (115
checks, including new tests specifically designed to catch the TC bug),
a larger integration suite (28 checks), a new load generator, ran a
1.2M-query soak test across flag combinations, and reported the results
honestly including where it had been wrong (see below). This used up
its full turn/tool budget, so it stopped partway through and gave a
progress report rather than a finished deliverable, explicitly flagging
one of its own earlier claims (about `--no-wakeup` dropping all
responses) as unverified.

### Prompt 2.2

> Continue

**What came back:** Claude picked up where it left off. Notably, it
went back and *tested* the unverified claim from the end of its
previous message before doing anything else — ran the old binary with
`-W` and with `-b -W` together, got 2000/2000 received both times (i.e.
the claim didn't reproduce), then wrote a small standalone C program to
query `xsk_ring_prod__needs_wakeup()` directly and found it returns
`1` in this kernel whether or not `XDP_USE_NEED_WAKEUP` is set — so
there was no bug there after all, and it said so explicitly rather than
quietly dropping the claim. It then finished the rest of the rewrite
(server.c, test_resolver.py, fake_hierarchy.py, run_tests.sh, Makefile,
Dockerfile, README.md), ran the full test suite from a completely clean
build, ran the AF_XDP binary end-to-end over the veth pair with real
`dig` queries against every case in the fake hierarchy, ran the 1.2M-
query soak test, and delivered the final zipped source tree.

---

## Session 3 — "Bloom filter"

My messages, copied as sent, in order. Claude's replies were long (code +
measurement tables); a summary of what came back follows each.

### Prompt 3.1

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

### Prompt 3.2

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

---

## Session 4 — Report LaTeX and TikZ figures

### Prompt 4.1 — message not recovered

The request was for workflow diagrams to accompany the report. The recovered
transcript preserves the response but not the message as sent, so no verbatim
text is given here rather than a reconstructed paraphrase.

**What came back:** Three workflow diagrams added (four TikZ figures
total), all drawn inline so the `.tex` still needs no uploaded assets:

- **Figure 1 — UMEM frame lifecycle (§2.3).** Free-frame stack in the
  middle with a receive half and a transmit half drawing from it. Makes the
  §3.3 argument visual: the receive frame is recycled before resolution
  starts, so pool occupancy is bounded by batch size rather than resolver
  latency.
- **Figure 3 — End-to-end query workflow (§3.4, full-width `figure*`).**
  Client → XDP → RX ring → job queue → Bloom → cache → build → TX, with
  the miss path dropping to iterative resolution and the acceptance gates.
  The Bloom fast-reject drawn in bold teal straight past the cache,
  labelled "definitely absent — no mutex acquired".
- **Figure 4 — Response acceptance pipeline (§4.2).** Five gates stacked
  from "upstream datagram" to "may be cached", dashed red exits. Caption
  carries the point that discarding does not end the read, or one spoofed
  packet becomes a DoS.

Two of the three needed rework after rendering: the workflow figure's
"miss" and "definitely absent" labels sat on top of the resolution box
because both elbow connectors ran horizontally at exactly that box's
height (fixed by stacking the nodes beneath the boxes they connect to, so
every connector is a clean vertical); the lifecycle figure had "kernel
sends" colliding with the COMPLETION box and a return curve looping
through a neighbouring node (redrawn as two sub-cycles). Recorded because
TikZ compiling cleanly tells you nothing about whether it looks right —
every page was rendered and inspected.

Final state: 8 pages, 0 errors, 0 undefined references. Transport results
table and contributions table left marked in red to be filled from real
hardware.

Deliverables: `report.tex`, rendered PDF preview.

---

## Session 5 — Running everything on real hardware

### Prompt 5.1

> i need to test everything and get the output , just tell me the code to
> do so on my pc

**What came back:** `collect_results.sh` — one script running everything
into `results/ALL.txt`, written and executed end-to-end in the sandbox
before being handed over, so it was tested rather than theoretical.

```sh
cd ~/dns_ax
chmod +x collect_results.sh

./collect_results.sh          # tiers 1-3: no NIC needed
./collect_results.sh eth0     # + tier 4 on a real interface
```

| Tier | Produces | Needs |
|---|---|---|
| 1 | Build warnings, BPF verifier | root |
| 2 | 227 unit checks, TSan | nothing |
| 3 | 28 offline + 36 adversarial, resolver counters, Bloom A/B table, scaling curve | port 53 |
| 4 | Zero-copy mode line, per-queue RX split, guard rail | root + NIC |

**Two bugs hit while writing it**, both reported rather than quietly fixed:

- `$SUDO VAR=x ./cmd` breaks silently when `$SUDO` is empty — shell
  assignments are recognised before variable expansion, so with no sudo the
  shell tries to execute `DNS_ROOT_HINTS=127.0.0.21` as a command. The
  adversarial tier failed with "no response" and looked like a server
  problem. Fixed with `env`.
- `pkill -f evil_hierarchy` matches the script's own command line and kills
  the shell running it. Fixed to `pkill -f "[e]vil_hierarchy"`.

**What the script cannot do:** transport throughput and latency need a load
generator with both arms on the same link, run manually:

```sh
gcc -O2 -Wall -o loadgen loadgen.c

# AF_XDP arm
sudo ./af_xdp_user_stub -d eth0 --filename ./af_xdp_kern.o --queues 2 -w 4
./loadgen -s <SERVER_IP> -p 53 -d 30 -c 4 | tee results/xdp_load.txt

# UDP arm — same IP, same link, same worker count
sudo ./server_stub -p 53 -w 4
./loadgen -s <SERVER_IP> -p 53 -d 30 -c 4 | tee results/udp_load.txt
```

Use the `_stub` binaries — the real backend blocks on upstream DNS for up
to 2 s, so otherwise you measure the resolver, not the transport.

**The open question it flagged:** every figure in the report was
single-core, and the filter's justification is that a miss skips a
contended mutex — untested. If the bloom/no-bloom gap widens with thread
count, the contention explanation holds and can be stated; if it stays
flat, the filter still helps but for a different reason and the report must
be corrected. Either result is worth reporting; guessing is not. The
shipped `sample_results.txt` is a 1-core container's output, so its
multi-thread rows are convoy artifacts — use it to check output formatting,
not as data.
