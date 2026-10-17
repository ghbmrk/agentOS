# Rules for agents building agentOS

Read SPEC.md for what to build and PLAN.md for how. This file is the working contract for builder (L2) and reviewer (L3) agents: rules only, one line each. docs/OPERATING.md gives the procedures and reasons behind them, and README.md maps every document and gives each role its reading order.

## Role rules (load before acting; the rules live in skills, not here)
- **Builder (L2):** before touching any file for a package, load the `agentos-builder` skill (`.claude/skills/agentos-builder/SKILL.md`). If the Skill tool is unavailable, Read that file.
- **Reviewer (L3 or lens):** before reading the diff or posting any verdict, load the `agentos-reviewer` skill (`.claude/skills/agentos-reviewer/SKILL.md`). A review that skipped it is invalid. If the Skill tool is unavailable, Read that file.
- **Budget:** builders, reviewers and coordinators also load the `agentos-budget` skill (`.claude/skills/agentos-budget/SKILL.md`) before spawning a session, picking a model or writing a hand-off.
- Never put credentials, tokens, or personal data in code, tests, fixtures, or logs. Use synthetic canaries only.

## Repository conventions
- Branch per package: `pkg/<id>-<slug>-<suffix>`. The coordinator sets the `pkg/<id>-<slug>` stem when it starts a thread; the server appends a session-unique suffix. Threads started without a stem keep their assigned `claude/…` branch, and the PR title starts with the package ID (DECISIONS.md).
- Nothing sits idle more than 48 hours: a PR or `building` row is finished, handed off, or returned to `queued`. No draft is exempt; the W5-D drafts D-095 keeps open as reference are exempt until SIM-cases lists their cases (OPERATING §5, D-098). There is no open-PR cap: a build does not start while an open PR touches files in its brief's scope (OPERATING §5, D-111).
- Questions for Mark go to the coordinator, who asks them on a Decisions card, one-word answerable, with a recommendation; actions only Mark can take are issues labelled `decision`.
- A PR that fixes a defect in already-merged code carries a `Defect: <package ID>` line in its body; METRICS.md counts them for L4.
- SPEC.md changes only through an L1 spec-diff PR that Mark approves.
- Mark's two Claude subscriptions are equal peers: either builds any row and arms the merge of any PR it just accepted under the same rule (D-099, D-120). Other teams (another vendor's agent, a teammate) work only in their own lane (docs/LANES.md), claim rows (their issue's `state:building` label) before building, run their own fresh L3 review before marking a PR ready, and merge only their own PRs through `tools/premerge.py` (D-100, OPERATING §7); the repository is the only shared state.
- Number decisions and new BOARD rows in your team's namespace (the peers use the plain `D-NNN`).
