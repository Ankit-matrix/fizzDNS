# Session 2 prompts — "dns_ax rewrite and testing"

Chat: current session (uploaded file `dns_ax_ankitsaha.zip`)
Date: 11 Sep 2026

These are my messages, copied as sent, in order.

---

### Prompt 1

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

---

### Prompt 2

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

*(End of my prompts for this task in this session — 2 messages, plus
this current message asking for the AI-usage documentation itself,
which is a separate, later task and not part of the dns_ax build.)*
