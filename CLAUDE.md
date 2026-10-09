# Rules for agents building AgentOS

Read SPEC.md for what to build and PLAN.md for how. This file is the working contract for builder (L2) and reviewer (L3) agents: rules only, one line each. docs/OPERATING.md gives the procedures and reasons behind them, and README.md maps every document and gives each role its reading order.

## Builder (L2)
- Work only from a package brief (`briefs/<ID>.md`, linked from its BOARD.md row). Touch only files inside the brief's declared scope.
- **Tests first.** For each requirement ID in the brief, write a failing test, then the smallest change that passes it.
- Claim coverage with a marker comment in the test file: `REQ: CRED-1, CRED-4`. Run `python3 tools/trace.py` locally to see coverage, but never commit TRACE.md: CI fails a PR that changes it, and the `trace` workflow commits the regenerated file to main after each merge.
- "Done" = CI green + every brief ID covered by a passing test. Never assert done without that evidence.
- **Stop on lack of progress, not on spend:**
  - The brief's usage figure is an *estimate and checkpoint*, not a ceiling. At the checkpoint, continue if tests are moving toward green (note the extension in the PR), otherwise escalate.
  - Same test still failing after 2 fix attempts: stop, write a diagnosis in the PR, and mark the package `escalated` on BOARD.md.
  - Diff growing while the pass count is flat: stop and escalate.
- Don't start a row LATER.md lists as later. Class every finding you raise or receive as **blocker** (fix in this PR), **release** (new BOARD row) or **later** (one line in LATER.md), and list them on the PR's Findings line (OPERATING §2).
- Record what the package rests on in its `ASSUMPTIONS.md` (OPERATING §5).
- Prefer reusing mature components. A new component needs a sentence in the PR on why reuse fails.
- Never put credentials, tokens, or personal data in code, tests, fixtures, or logs. Use synthetic canaries only.

## Reviewer (L3)
- Review in a fresh context, from the diff plus the cited requirement IDs. Don't rely on the builder's reasoning.
- First line `Verdict: accept|fix-list|reject`; any verdict but accept adds `Cause: spec-gap|brief-gap|defect|scope`. Each point cites a requirement ID or a concrete defect and carries its class (OPERATING §4).
- A point outside the cited IDs is `release` or `later`, never a blocker.
- Review depth follows the risk tier `python3 tools/risk_tier.py --git origin/main HEAD` prints; the stages each tier needs are in OPERATING §3–4. Tier A needs the strongest model and an explicit threat check.
- Each review runs in a new session. There are no standing reviewer or lens sessions; lens memory lives in DECISIONS.md and `reviews/<lens>/README.md`.
- A kind of finding seen on a second PR becomes a lint rule, test or CI check in the next package that touches the area, listed in the lens README (OPERATING §4).

## Budget (reasons: OPERATING §1, §5)
- The only hard limit is the subscription (usage credits off). Target: ~100% of the weekly limit used by each reset, paced evenly at ~14% a day so it never runs out early (Mark, 2026-10-04); these are targets: spend where the next unit of work has clear value, don't idle to stay on pace, and don't spend just because budget remains.
- Near a session-window limit, finish the current step cleanly; start heavy new work after the reset.
- Keep contexts small: brief + touched files. Summarize CI logs instead of pasting them.
- `.claude/settings.json` compacts at 120k tokens (above a 20k brief plus touched files, below the 150k package ceiling); don't raise it.
- Size each package so its brief is 20k tokens or less and it finishes under 150k; split it before starting otherwise.
- One package or one review per session. Start a fresh session with a hand-off packet of 20k tokens or less (OPERATING §5) rather than reviving a session over ~150k that sat idle more than an hour.
- Mechanical subagent work (search, log triage, wording sweeps, test scaffolding) passes `model: "haiku"` and stays under 100k tokens, above which Haiku costs 5x; use `"sonnet"` when it needs judgment. Reviews of security-critical paths keep the session's model.
- Sonnet pilot (OPERATING §5, 2026-10-08 to the 2026-10-18 reset): tier B and C builder sessions run on a Sonnet-class model, tier A on the strongest model. Run `tools/risk_tier.py` before opening the PR; on A, stop and hand off. Name the builder model in the PR's Budget section.
- Read tool output narrowly (grep, tail, `go test -run`), never whole CI logs or large files. Send cross-session messages for decisions, blockers and hand-offs only; progress goes in the status checklist.

## Repository conventions
- Branch per package: `pkg/<id>-<slug>-<suffix>`. The coordinator sets the `pkg/<id>-<slug>` stem when it starts a thread; the server appends a session-unique suffix. Threads started without a stem keep their assigned `claude/…` branch, and the PR title starts with the package ID (DECISIONS.md). PRs use the template's trace table.
- A PR that fixes a defect in already-merged code carries a `Defect: <package ID>` line in its body; METRICS.md counts them for L4.
- SPEC.md changes only through an L1 spec-diff PR that Mark approves.
- Parallel teams (another subscription or another vendor's agent) work only in their own lane (docs/LANES.md), claim rows on BOARD.md before building, run their own fresh L3 review before marking a PR ready, and never merge; the repository is the only shared state (OPERATING §7).
