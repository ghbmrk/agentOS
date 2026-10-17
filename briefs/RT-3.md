# RT-3: `risk_tier.py --git` fails closed on an empty diff

Issue #2272 (promoted from `later` to a fix by the coordinator on 2026-10-17 after at least four mis-tiered builds: #2259, #2253, #2267, CH11 reactions).

**Tier:** A (the change edits `tools/risk_tier.py`, tier A by its own rule; `premerge.py --needs-mark` prints `mark`, so Mark merges). Strongest model. Small: about 40 lines with tests.

**Guard files:** none.

**Acceptance tests:** `test_uncommitted_changes_count_against_head` (RT-3a), `test_empty_diff_prints_no_tier` (RT-3b), both in `tests/test_risk_tier.py`.

## Today

`tools/risk_tier.py --git BASE [HEAD]` diffs `BASE...HEAD`, commits only. Before a builder's first commit that diff is empty, `tier_of_change([])` returns C, and the tool prints a bare `C` and exits 0. A tier-A package then starts on a Sonnet session with a C-tier review plan.

## Requirements (local IDs)

- **RT-3a, working tree counts.** When HEAD is the literal `HEAD` (the default, and the form CLAUDE.md and OPERATING §3 give), the paths are the committed diff plus staged, unstaged and untracked (not ignored) paths against the merge base of BASE and HEAD, so a run before commit tiers what the builder changed. With HEAD a named commit (CI, the lane gate, reviewpacket) only the committed diff counts, as today.
- **RT-3b, no tier without paths.** With `--git`, when the paths are empty the tool prints no tier, writes a message naming BASE and HEAD to stderr, and exits 2.

## Tests (`tests/test_risk_tier.py`, written first)

- An uncommitted edit to a tier-A file, staged and unstaged, and an untracked tier-A file, each with no commit ahead of BASE: `--git BASE HEAD` prints A.
- A named HEAD commit equal to BASE with a dirty tree: exit 2, empty stdout, message on stderr.
- A clean tree with no commit ahead: exit 2, empty stdout.
- The existing cases still pass.

## Scope

`tools/risk_tier.py`, `tests/test_risk_tier.py`, `briefs/RT-3.md`, `tools/ASSUMPTIONS.md` (one row).

## Not in scope

The path-list form (`risk_tier.py PATH...`) and `tier_of_change([])`, which callers inside other tools use; changing how CI passes refs.
