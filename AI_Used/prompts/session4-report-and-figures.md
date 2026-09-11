# Session 4 prompts — report LaTeX and TikZ figures

Chat: `[FILL IN]`
Date: `[FILL IN]`

---

### Prompt 1

> `[FILL IN — the verbatim prompt asking for diagrams. The recovered
> transcript preserves the response but not this message as sent. Do not
> invent a tidier version; copy it from the chat.]`

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
