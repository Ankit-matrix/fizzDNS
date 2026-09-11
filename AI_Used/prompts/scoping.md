# Prompts — scoping and architecture

Contributor: `[FILL IN]`
Chat: `[FILL IN]` · Date: `[FILL IN]`

Verbatim, in order. Note the explicit "do not write any code yet" — this
whole group is design dialogue, deliberately before implementation.

---

### Prompt 1

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

---

### Prompt 2

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

---

### Prompt 3

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

---

### Prompt 4

> The deliverable is a comparison, so design the experiment first. What is
> the minimum set of binaries I need so that a measured difference between
> AF_XDP and UDP is attributable to the transport and nothing else? Then
> list every confounding variable that would still remain, and rank them by
> how badly they'd bias the result.

**Outcome:** the `_stub` binaries (`af_xdp_user_stub`, `server_stub`,
`resolver_stub.c`). The real backend blocks on upstream DNS for up to 2 s,
so benchmarking it measures the resolver, not the transport.
