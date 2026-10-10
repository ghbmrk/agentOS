# AGENTS.md

Entry point for coding agents other than Claude Code (for example Codex). The rules are the same for every agent.

1. Read CLAUDE.md: it is the working contract for builders and reviewers, and it applies to you in full. README.md gives the reading order for your role.
2. Read docs/LANES.md: you work only inside your team's lane. If your team has no lane there, stop; the primary team adds it in an onboarding PR. The rules for parallel teams are docs/OPERATING.md §7.
3. Pick work only from BOARD.md rows in your lane whose issue is not labelled `class:later`. Claim a row (its issue's label `state:building`, owner your team in the issue) before writing code; BOARD.md is generated from the issues, so never edit its rows. The row links its brief.
4. Branch `pkg/<team>-<id>-<slug>`. Open a PR using the template, run a fresh L3 review of it (CLAUDE.md) and link the accept before marking it ready. Never merge, and never push to another team's branch.
5. Anything that crosses your lane goes as a PR or a `lane:<name>` issue to the owning team. Decisions you rely on must already be in DECISIONS.md.

Checks to run before pushing: `python3 -m unittest discover -s tests`, `python3 tools/trace.py --check` (never commit TRACE.md), `python3 tools/doclint.py`, and `go test ./...` in `broker/` for the packages you touched.
