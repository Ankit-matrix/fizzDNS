# Prompts — resolver core and cache-poisoning defence

Contributor: `[FILL IN]`
Chat: `[FILL IN]` · Date: `[FILL IN]`

---

### Prompt 1

> Implement the DNS wire format layer per RFC 1035: name encode/decode with
> compression pointers, question parsing, RR parsing, response building.
> Before writing it, list every way a malicious 512-byte datagram could
> make this code loop forever, read out of bounds, or allocate unboundedly.
> Then write the code with a named defence against each, and tell me which
> line implements which defence.

Produces code whose defences are traceable to a specific threat, which
makes review tractable — you check the mapping, not the whole file.
→ `dns_msg.c` / `dns_msg.h`.

---

### Prompt 2

> Iterative resolution means asking servers we don't trust. Write the rules
> that gate what may enter the cache. Frame it as an attacker: I am a .com
> nameserver and I want to poison this resolver. Enumerate every lie I can
> tell — in the referral, in the glue, in the answer section, in the
> transaction ID. For each lie, state the specific check that stops it, and
> then tell me the variant of the lie that check does NOT stop.

The last clause is the important one. Asking only for the defence gets a
confident list; asking for the residual gets the honest boundary of each
check.

---

### Prompt 3

> Is my bailiwick check label-aligned? Show me a name that ends with the
> zone as raw text but is not inside it.

Suffix matching is not containment — `evilexample.com` ends with
`example.com` as raw text and is not in that zone.

---

### Prompt 4

> Where do my transaction IDs come from? If the answer involves rand_r or
> time(NULL), tell me how many queries an observer needs to predict every
> future ID from that thread.

---

### Prompt 5

> I now reject bad datagrams. Have I just built a denial of service? What
> happens if an attacker races every legitimate response with one spoofed
> packet?

**Outcome:** discarding a spoofed response must not end the read. This is
the point carried in the Figure 4 caption in the report.

---

### Prompt 6

> Write a Python script that impersonates a root, a TLD and an
> authoritative server on loopback, and lies in each of the ways we
> enumerated. One named attack per lie. Then write the tests. For each
> attack assert two things: the lie is not in the answer, AND the lie is
> not in the cache.

**Outcome:** `evil_hierarchy.py` + `test_integration.py`. The two-part
assertion matters: answer-only checks would miss a poisoned cache that
serves the lie on the *next* query.

---

### Prompt 7

> Cache lookups take a mutex. Put a Bloom filter in front so a miss can
> answer "definitely not cached" without the lock. Constraint: this cache
> deletes — LRU eviction and TTL expiry both remove entries. Work out what
> that does to a plain bit-vector filter, and what it means for the
> filter's behaviour over a long run.

The constraint is stated rather than left for the model to notice. A plain
filter under deletion degrades silently — FPR climbs to 1 and it becomes a
branch that always says "maybe" — which passes tests and fails in
production.

---

### Prompt 8

> Benchmark it A/B and show me ns/op for all-miss and all-hit separately.
> If the hit path got slower, find out why before you explain it away.

The second sentence is the one that did the work. See
`../claude-contributor1/prompts/session3-bloom-filter.md` — the hit path
*had* got slower, by ~10%, and the cause was the filter's own atomic
instrumentation, not the filter.

---

### Prompt 9

> State what this benchmark does NOT show.

Asked as a standing habit. In this case the answer was that every figure
was single-core, so the contention explanation for the filter's benefit
remained untested — which became the open question handed to whoever ran
the hardware measurements.
