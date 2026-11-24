---
name: agentos-builder
description: agentOS builder (L2) rules. Load before starting any package build, opening a build PR, or raising findings on one.
---

# Builder (L2) rules

- Work only from a package brief (`briefs/<ID>.md`, linked from BOARD.md). Touch only the brief's declared scope. The brief names its acceptance tests; for a brief in `tools/brief_acceptance_baseline.txt`, name them in the PR body (OPERATING §5).
- **Tests first.** For each requirement ID in the brief, write a failing test, then the smallest change that passes it.
- Claim coverage with a test-file marker: `REQ: CRED-1, CRED-4`. New tests: an external `zz_` file, plain-function hooks (internal tests run first; a `_test.go` method of a non-test type reaches every test; #6455). Never commit TRACE.md (CI fails it; a daily workflow regenerates it).
- "Done" = CI green + every brief ID covered by a passing test. Never assert done without it.
- Request review once every required check is green (mutgate may still run, OPERATING §7), with the PR body naming, for a parser or allowlist change, the corpus or differential test it ran. An unkillable survivor goes, with its reason, in `MUTANTS-EQUIVALENT` (`tools/mutgate.py waive`).
- **Stop on lack of progress, not on spend:** the brief's usage figure is a checkpoint: past it, continue while tests move toward green (note it in the PR). Stop, write a diagnosis in the PR and label its issue `state:escalated` when one test still fails after 2 fix attempts or the diff grows while the pass count is flat.
- BOARD.md is generated from `work-item` issues (tools/board.py): edit the issue, never the file. Don't start a row labelled `frozen` (D-098). Class every finding you raise or receive as **blocker** (fix in this PR) or **release** (new `work-item` issue labelled `class:release`, required before the row is done; nothing is deferred), and list them on the PR's Findings line (OPERATING §2, D-250).
- A **release** finding names the acceptance test or invariant it serves and one failure path. Tooling messages, and findings on a follow-up of a follow-up, are release items unless they are a false pass or exploit path (OPERATING §2, D-086).
- Record what the package rests on in its `ASSUMPTIONS.md` (OPERATING §5). Before merging main, run `python3 tools/record_merge.py --install` once per clone.
- Prefer reusing mature components. A new component needs a PR sentence on why reuse fails.
