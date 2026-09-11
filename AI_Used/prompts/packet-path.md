# Prompts — packet path / XDP program

Contributor: `[FILL IN]`
Chat: `[FILL IN]` · Date: `[FILL IN]`

---

### Prompt 1

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

---

### Subsequent prompts in this group

`[FILL IN — the "I'll attach the final files holup" suggests the
conversation continued with file attachments. Copy the remaining messages
from the chat rather than reconstructing them.]`
