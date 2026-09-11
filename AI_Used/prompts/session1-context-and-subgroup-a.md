# Session 1 prompts — "Context check"

Chat: https://claude.ai/chat/a31e9934-ab97-40c2-bb61-737c892c30d9
Date: 5 Sep 2026

These are my messages, copied as sent, in order. Claude's responses were
long (code + explanation); a one-line summary of what came back follows
each prompt. Full responses are in the chat itself / SUMMARY.md.

---

### Prompt 1

> Here's the context sire, check this out

(Attached: our team's existing write-up/notes on the project — brief,
subgroup split, our analysis of the senior's benchmark numbers.)

**What came back:** Claude summarized the situation back to me, then
flagged two problems in our own numbers before I'd asked it anything —
an apparent unit error in a cycles-per-query table, and an inconsistency
between QPS and latency that it said probably meant our load generator
was the bottleneck. It then asked which of A1/A2/A3 I actually was,
since that changes what "finish Subgroup A" means.

---

### Prompt 2

> Here is the reference code

(Attached: `AF_XDP-Low-Latency-DNS-Resolver.zip`, the existing project from another claude chat- temporary work.)

**What came back:** Claude extracted and read the code directly (not
just skimmed filenames), diffed the three "variant" files against each
other, and reported three specific findings: the three benchmark
variants were identical except for one `#include` line each; the
reported CPU-cycle numbers were an artifact of `perf stat -p 1`
profiling bash instead of the resolver in the baseline arm; and there
was an actual unsynchronized data race on the AF_XDP TX ring / frame
allocator across the ten worker threads. It asked whether I wanted it
to sketch the corrected RX/TX ownership model as code, or work through
the benchmark methodology first.

---

### Prompt 3

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

---

### Prompt 4

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

*(End of my prompts for this session — 4 total messages driving the
whole build.)*
