# AI_Used — AI tool usage documentation

Project: **`dns_ax`** — a recursive DNS resolver whose packet path uses
AF_XDP (XSK) instead of the kernel network stack, benchmarked against an
otherwise-identical plain-UDP socket server.

This folder exists to satisfy the course requirement that every team
document its AI tool usage in the repository. The four required items map
to files as follows:

| Required item | Where it is |
|---|---|
| **Tools used** | `TOOLS.md` |
| **Prompts provided** | `*/prompts/*.md` — verbatim, one file per session |
| **Thought process (how AI was integrated)** | `THOUGHT_PROCESS.md` |
| **Step-by-step details (where/how AI contributed at each stage)** | `STEP_BY_STEP.md` |

## Layout

```
AI_Used/
├── README.md              <- this file / index
├── TOOLS.md               <- every tool, model, and what it was used for
├── THOUGHT_PROCESS.md     <- how AI was integrated into the workflow, and why
├── STEP_BY_STEP.md        <- stage-by-stage, file-by-file contribution map
├── TEMPLATE.md            <- copy this if another member/tool needs adding
├── claude-contributor1/   <- build, rewrite, Bloom filter, report, harness
│   ├── SUMMARY.md
│   ├── prompts/           <- sessions 1-5, verbatim
│   └── artifacts/         <- the final delivered source tree
└── claude-contributor2/   <- design-first / adversarial-review prompting
    ├── SUMMARY.md
    └── prompts/           <- scoping, resolver core, packet path
```

## Honesty notes

Two things are recorded here deliberately, because an accurate record is
the point of the exercise and a flattering one is not:

1. **Where the AI was wrong and it was caught.** Session 2 contains a bug
   claim Claude made, later tested, and retracted. Session 3 contains a
   ~10% performance regression the AI introduced with its own
   instrumentation and only found after being pushed on it. Session 3 also
   contains a concurrency test that was green while testing nothing.
2. **Gaps.** Some parts of the final tree are not covered by any prompt log
   in this folder — see the "Not covered" section of `STEP_BY_STEP.md`.
   They are listed rather than quietly attributed to AI or to humans.
