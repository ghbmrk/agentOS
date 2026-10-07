# AGENTS.md

Entry point for coding agents other than Claude Code (for example Codex). The rules are the same for every agent.

1. Read CLAUDE.md: it is the working contract for builders and reviewers, and it applies to you in full.
2. Read docs/OPERATING.md, §7 first: you work only inside your team's lane in its Lanes table. If your team has no row there, stop; the primary team adds it in an onboarding PR.
3. Pick work only from BOARD.md rows in your lane that LATER.md does not list as later. Claim a row (state `building`, owner your team) on main before writing code.
4. Branch `pkg/<team>-<id>-<slug>`. Open a PR using the template, run a fresh L3 review of it (CLAUDE.md) and link the accept before marking it ready. Never merge, and never push to another team's branch.
5. Anything that crosses your lane goes as a PR or a `lane:<name>` issue to the owning team. Decisions you rely on must already be in DECISIONS.md.
6. Never put credentials, tokens or personal data in the repository. Use synthetic canaries only.

Checks to run before pushing: `python3 -m unittest discover -s tests`, `python3 tools/trace.py --check` (never commit TRACE.md), and `go test ./...` in `broker/` for the packages you touched.
