# Thought process — how AI was integrated

## The short version

We did not use the AI as a code vending machine. The pattern that ended up
working, and that the prompt logs show, was:

**human sets the constraint → AI produces → AI is made to attack its own
output → machine checks (compiler, sanitizer, test, benchmark) arbitrate.**

The last step is the one that mattered. Almost every real defect in this
project was found by something that could fail, not by something that could
explain — a sanitizer, a differential benchmark, a `dig` that came back
`;; Truncated`. Where we relied on the AI's prose instead, we got confident
wrong answers, and those are recorded too.

## Why this project in particular needed that

AF_XDP is a domain where plausible code and correct code look identical
until traffic hits them:

- The rings are **single-producer / single-consumer by contract**, and
  nothing enforces it. Violating it compiles, links, runs, and passes a
  light test — then loses ~18% of packets under load. That is exactly the
  class of bug where "the model said it's fine" is worth nothing.
- A recursive resolver **parses bytes from servers it does not trust**. A
  compression-pointer loop or an unchecked length is a hang or an
  out-of-bounds read, not a wrong answer.
- The deliverable is a **comparison**, so a measurement artifact is as fatal
  as a code bug. A harness that profiles the wrong process — `bash -c "gcc
  ... && ./server"` does not exec-replace PID 1 when the command is
  compound, so `perf stat -p 1` measures an idle shell — yields a number
  that is well-formed, plausible, and meaningless.

## The four prompting habits we settled on

### 1. Ask for the failure mode before asking for the code

Repeatedly the prompt is "list every way this can break, *then* write it":

> *"Before writing it, list every way a malicious 512-byte datagram could
> make this code loop forever, read out of bounds, or allocate unboundedly.
> Then write the code with a named defence against each, and tell me which
> line implements which defence."*

This produces code whose defences are traceable to a threat, and it makes
review tractable: you check the mapping, not the whole file.

### 2. Make it argue against itself

The strongest prompts in this project ask the AI to defeat its own answer:

> *"For each lie, state the specific check that stops it, and then tell me
> the variant of the lie that check does NOT stop."*

> *"I now reject bad datagrams. Have I just built a denial of service?"*

The second one caught a real design error: discarding a spoofed response
must not end the read, or one forged packet per query becomes a DoS.

### 3. Demand the negative result

> *"State what this benchmark does NOT show."*

> *"If the hit path got slower, find out why before you explain it away."*

That second prompt is the reason the Bloom filter works. The AI's first
version was ~10% *slower* on an all-hit workload and offered a tidy
explanation. Pushed, it found the actual cause: it had instrumented the
filter with shared `_Atomic` counters and was doing a lock-prefixed
read-modify-write on a contended cache line on every lookup — the exact
cost the filter exists to avoid, reintroduced by the filter's own
bookkeeping. Isolated: 14.58 ns with counters, 4.90 ns without. Sharding
the stats one cache line per thread removed it entirely.

### 4. Never accept a green test

A passing test is a claim, and claims get checked:

- The 115-check suite was run against the **old** `dns_msg.c` to prove it
  actually caught the TC-bit bug (3 failures), then against the new one
  (0 failures). A regression test that has never failed has not been tested.
- The first concurrent cache test reported a **0.0% hit rate** and passed.
  The key was `seed % CT_KEYS` and the put/get branch was `seed & 1`, so
  puts only ever landed on odd keys and gets only read even ones. It
  exercised nothing. The fix, and the comment explaining it, are in the
  source so it cannot be reintroduced.
- Bloom correctness is checked **differentially**: the same seeded query
  sequence through the bloom and no-bloom binaries must yield identical hit
  counts at every miss ratio. The filter must never cost a cached answer.

## Where we overrode the AI, and where it overrode the brief

- **Session 2** exists because the session-1 output was rejected: "insanely
  buggy, and it was certainly not human like for sure". The rewrite was
  told to match a hand-written `Start/` folder's style — tabs, short inline
  comments, no banner essays.
- The Bloom brief said to implement it as a **BPF array in the kernel**.
  The AI declined and said why: the XDP program only classifies and
  redirects, there is no BPF map cache to guard, and a miss has to reach
  userspace anyway — so a kernel-side filter saves nothing and adds a
  userspace→kernel sync problem. It put the filter in front of
  `dns_cache.c`'s userspace hash table instead. We accepted that
  reasoning; it is flagged in the report rather than hidden.
- A **plain bit-vector Bloom filter was rejected** for a deleting cache.
  LRU eviction and TTL expiry both remove entries; a plain filter cannot
  clear a bit without risking a false negative, so bits accumulate, FPR
  climbs toward 1, and the filter silently degrades into a branch that
  always says "maybe". It would pass a naive suite and stop working in
  production. A counting filter (65536 one-byte counters, k=4) was used.
- A **blocked cache-line layout** was tried and discarded on measurement —
  41.6 ns vs 34.2 ns cold — because the dedupe needed for add/delete
  symmetry costs more than the misses it saves when 64 KiB mostly sits in
  L2. Recorded rather than kept as a plausible-sounding optimisation that
  does not pay.

## What this cost us

Being honest about the downside: the AI is fast at producing something that
looks finished, and that is a hazard when the failure modes are invisible.
Session 1's output looked complete and was not. The counting-filter
regression shipped in a version that had already been presented as done.
The time saved on writing was partly spent on verifying, and the net win
came from the verification being automatable — sanitizers, differential
benchmarks, an offline fake DNS hierarchy — not from the generation being
fast.
