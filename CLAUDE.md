# Rules for agents building AgentOS

Read SPEC.md for what to build and PLAN.md for how. This file is the working contract for builder (L2) and reviewer (L3) agents.

## Builder (L2)
- Work only from a package brief on BOARD.md. Touch only files inside the brief's declared scope.
- **Tests first.** For each requirement ID in the brief, write a failing test, then the smallest change that passes it.
- Claim coverage with a marker comment in the test file: `REQ: CRED-1, CRED-4`. Run `python3 tools/trace.py` locally to see coverage, but never commit TRACE.md: CI fails a PR that changes it, and the `trace` workflow commits the regenerated file to main after each merge.
- "Done" = CI green + every brief ID covered by a passing test. Never assert done without that evidence.
- **Stop on lack of progress, not on spend:**
  - The brief's usage figure is an *estimate and checkpoint*, not a ceiling. At the checkpoint, continue if tests are moving toward green (note the extension in the PR), otherwise escalate.
  - Same test still failing after 2 fix attempts: stop, write a diagnosis in the PR, and mark the package `escalated` on BOARD.md.
  - Diff growing while the pass count is flat: stop and escalate.
- Prefer reusing mature components. A new component needs a sentence in the PR on why reuse fails.
- Never put credentials, tokens, or personal data in code, tests, fixtures, or logs. Use synthetic canaries only.

## Reviewer (L3)
- Review in a fresh context, from the diff plus the cited requirement IDs. Don't rely on the builder's reasoning.
- Verdict: **accept**, **fix-list**, or **reject**, each point citing a requirement ID or a concrete defect.
- Security-critical paths (broker, vault, executors, clean room, update signing) need the strongest reviewer tier and an explicit threat check.

## Budget (PLAN.md §4A)
- The only hard limit is the subscription (usage credits off). Target: ~100% of the weekly limit used by each reset, paced evenly at ~14% a day so it never runs out early (Mark, 2026-10-04); these are targets: spend where the next unit of work has clear value, don't idle to stay on pace, and don't spend just because budget remains.
- Near a session-window limit, finish the current step cleanly; start heavy new work after the reset.
- Keep contexts small: brief + touched files. Summarize CI logs instead of pasting them.

## Repository conventions
- Branch per package: `pkg/<id>-<slug>-<suffix>`. The coordinator sets the `pkg/<id>-<slug>` stem when it starts a thread; the server appends a session-unique suffix. Threads started without a stem keep their assigned `claude/…` branch, and the PR title starts with the package ID (DECISIONS.md). PRs use the template's trace table.
- A PR that fixes a defect in already-merged code carries a `Defect: <package ID>` line in its body; METRICS.md counts them for L4.
- SPEC.md changes only through an L1 spec-diff PR that Mark approves.
