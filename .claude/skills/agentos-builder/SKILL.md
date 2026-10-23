---
name: agentos-builder
description: agentOS builder (L2) rules. Load before starting any package build, opening a build PR, or raising findings on one.
---

# Builder (L2) rules

Also load the agentos-budget skill.

- Work only from a package brief (`briefs/<ID>.md`, linked from its BOARD.md row). Touch only files inside the brief's declared scope. The brief names its acceptance tests; a brief listed in `tools/brief_acceptance_baseline.txt` predates that rule, so name its tests in the PR body and carry on (OPERATING §5).
- **Tests first.** For each requirement ID in the brief, write a failing test, then the smallest change that passes it.
- Claim coverage with a marker comment in the test file: `REQ: CRED-1, CRED-4`. Run `python3 tools/trace.py` locally to see coverage, but never commit TRACE.md: CI fails a PR that changes it, and the `trace` workflow opens a PR with the regenerated file once a day.
- "Done" = CI green + every brief ID covered by a passing test. Never assert done without that evidence.
- **Stop on lack of progress, not on spend:**
  - The brief's usage figure is an *estimate and checkpoint*, not a ceiling. At the checkpoint, continue if tests are moving toward green (note the extension in the PR), otherwise escalate.
  - Same test still failing after 2 fix attempts: stop, write a diagnosis in the PR, and set its work-item issue's label to `state:escalated`.
  - Diff growing while the pass count is flat: stop and escalate.
- BOARD.md is generated from `work-item` issues (tools/board.py): change a row by editing its issue, never the file. Don't start a row labelled `class:later` or `frozen` (D-098). Class every finding you raise or receive as **blocker** (fix in this PR), **release** (new `work-item` issue labelled `class:release`) or **later** (an issue labelled `class:later`), and list them on the PR's Findings line (OPERATING §2).
- A **release** finding names the acceptance test or invariant it serves and one failure path. Unsure between release and later: `later` tagged `recheck`. Tooling messages, and findings on a follow-up of a follow-up, are `later` unless they are a false pass or exploit path (OPERATING §2, D-086).
- Record what the package rests on in its `ASSUMPTIONS.md` (OPERATING §5).
- Prefer reusing mature components. A new component needs a sentence in the PR on why reuse fails.
- Never put credentials, tokens, or personal data in code, tests, fixtures, or logs. Use synthetic canaries only.
