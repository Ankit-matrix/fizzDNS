# Tools used

## 1. Claude (Anthropic)

- **Interface:** claude.ai web chat, with code execution / filesystem and
  file upload enabled.
- **Model:** identified in-app as Claude Sonnet 4.6.
- **Sessions:** 5 logged under `claude-contributor1/prompts/`, 3 thematic
  groups under `claude-contributor2/prompts/`.

**What it was used for:**

| Area | Extent |
|---|---|
| AF_XDP transport layer (`af_xdp_kern.c`, `xsk_setup.*`, `af_xdp_user.c`) | Written by AI, reviewed and rewritten to team style |
| DNS wire format, cache, iterative resolver (`dns_msg.*`, `dns_cache.*`, `resolver.*`) | Written by AI against human-specified constraints |
| Counting Bloom filter (`dns_bloom.*`, `bench_bloom.c`) | Written by AI, design constraint set by human |
| Test suites (`test_dns.c`, `test_resolver.py`, `test_integration.py`, `fake_hierarchy.py`, `evil_hierarchy.py`) | Written by AI, run by AI in-session and by the team on real hardware |
| Load generator (`loadgen.c`) | Written by AI |
| Report LaTeX + TikZ figures | Drafted by AI, numbers supplied by the team |
| Result-collection script (`collect_results.sh`) | Written by AI, run by the team |

**Notably NOT used for:** the subgroup split and the decision of what the
project should be. Those preceded any AI involvement.

## 2. Non-AI tooling used alongside it

Listed for completeness, since the AI's claims were checked against these
and not accepted on their own:

- `gcc` / `clang` / `llvm` — build, and `clang -target bpf` for the XDP object
- `-fsanitize=address,undefined` and `-fsanitize=thread` — the test suite
  is run under both; TSan is a separate target because it cannot be
  combined with ASan
- `bpftool` — BPF verifier output / program inspection (`make verify`)
- `dig` (bind9-dnsutils), `tcpdump` — live query and packet inspection
- `veth` pair + network namespace — running the real AF_XDP binary against
  real traffic without a physical NIC
- `perf stat` — CPU-cycle measurement
- `ethtool` — per-queue RX inspection for the zero-copy arm
- Docker / `docker-compose.mt.yml` — reproducible multi-core test environment

## 3. Tools NOT used

No other AI tool was used at any point — no ChatGPT, Copilot, Gemini,
Cursor, Perplexity or equivalent, in any capacity however brief. Claude was
the only one.
