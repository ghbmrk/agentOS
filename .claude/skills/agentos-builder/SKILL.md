---
name: agentos-builder
description: agentOS builder (L2) rules. Load before starting any package build, opening a build PR, or raising findings on one.
---

# Builder (L2) rules

Also load the agentos-budget skill.

- Work only from a package brief (`briefs/<ID>.md`, linked from its BOARD.md row). Touch only files inside the brief's declared scope. The brief names its acceptance tests; for a brief in `tools/brief_acceptance_baseline.txt`, name them in the PR body (OPERATING §5).
- **Tests first.** For each requirement ID in the brief, write a failing test, then the smallest change that passes it.
- Claim coverage with a marker comment in the test file: `REQ: CRED-1, CRED-4`. Never commit TRACE.md (CI fails it; a daily workflow regenerates it).
- "Done" = CI green + every brief ID covered by a passing test. Never assert done without that evidence.
- Request review only once every required check, mutgate included, is green, with the PR body carrying the mutgate result (or `Mutant-equivalent:` lines) and, for a parser or allowlist change, the corpus or differential test it ran.
- **Stop on lack of progress, not on spend:** the brief's usage figure is a checkpoint, not a ceiling; past it, continue while tests move toward green (note it in the PR). Stop, write a diagnosis in the PR and label its issue `state:escalated` when one test still fails after 2 fix attempts or the diff grows while the pass count is flat.
- BOARD.md is generated from `work-item` issues (tools/board.py): change a row by editing its issue, never the file. Don't start a row labelled `frozen` (D-098). Class every finding you raise or receive as **blocker** (fix in this PR) or **release** (new `work-item` issue labelled `class:release`, required before the row is done; nothing is deferred), and list them on the PR's Findings line (OPERATING §2, D-250).
- A **release** finding names the acceptance test or invariant it serves and one failure path. Tooling messages, and findings on a follow-up of a follow-up, are release items unless they are a false pass or exploit path (OPERATING §2, D-086).
- Record what the package rests on in its `ASSUMPTIONS.md` (OPERATING §5). Before merging main, run `python3 tools/assumptions_merge.py --install` once per clone.
- Prefer reusing mature components. A new component needs a sentence in the PR on why reuse fails.
