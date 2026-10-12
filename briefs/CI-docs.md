# CI-docs: Records-only changes get a light CI path

Board section: Owner-benefit review (2026-10-09). Item 3 of Mark's 2026-10-12 waste review ("Yes all"): of 31 PRs merged through 12:30 UTC, 15 were records or queue bookkeeping, and records-only #1083 cost about 97 minutes of summed job runtime across PR CI, main CI and the generated-TRACE CI.

**Tier:** A (edits `.github/workflows/` and adds `tools/ci_scope.py`, which decides which jobs a change skips). Strongest model. Small: about 250 lines with tests.

**Needs:** nothing.

## Today

Every PR, push to main and bot-branch dispatch runs the whole of `ci.yml` (checks, broker, machines, hostcheck) and `assurance.yml` (canary, dependency audit), whatever it changes. A change to `LATER.md` and three review records builds and tests the broker three times.

## Requirements (local IDs)

- **CI-docs-a, one records set.** `tools/ci_scope.py` holds the only list of record paths: named record files (BOARD, LATER, LEDGER, DECISIONS, METRICS, TRACE, docs/MARK-QUEUE) and `*.md` under `reviews/`, `decisions/`, `briefs/`, `handoff/`. Anything else, an empty change, or any error is `full`. A test walks every tracked file: each one outside the set makes a change full, and every record path is non-executable Markdown.
- **CI-docs-b, skip but report.** The ruleset "main-checks" requires checks, broker, machines and hostcheck. On a records-only change broker, machines and hostcheck are skipped by a job-level `if` (a skipped job satisfies a required check); checks runs only the document checks (trace, doclint, board, the TRACE guard, risk tier) and those tools' tests. No workflow-level `paths` filter.
- **CI-docs-c, fail safe.** Jobs skip only when the scope job outputs exactly `true`; a failed or cancelled scope job means full CI. The workflow runs the base commit's copy of `ci_scope.py`, so a PR cannot widen the set for itself, and `ci_scope.py` is tier A.
- **CI-docs-d, every trigger.** Pull requests (the PR against its merge base), pushes to main (the pushed range) and dispatches on the bot branches (`bot/trace`, `bot/metrics`, `bot/board`, against main) use the same rule. Schedules and dispatches on main run full. `assurance.yml` uses the same scope job.

## Out of scope

`trace.yml`'s own generation run on main (about a minute); the content of any check.
