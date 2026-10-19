# RT-3b: `risk_tier.py --git` ignores `diff.relative`

Board section: Backlog refill (2026-10-15). Work item: #2290. Follow-up of RT-3 (#2272), release finding from the delta reviews of PR #2289. **Tier A** (edits `tools/risk_tier.py`, tier A by its own rule). `premerge.py --needs-mark` prints `mark` for it: a Mark-gate PR (D-125), needing a separate Security accept at an equal head; Mark's line is needed only until D-137 (#2426) merges.

**Why.** Serves RT-3's fail-closed rule: risk_tier never under-tiers a change. The `git diff --name-only` calls in `changed_paths` (`tools/risk_tier.py` lines 271, 277, 280) honour a user's `diff.relative=true`. Run from a subdirectory they list only paths under the cwd, relative to it. Failure path: a commit changes `image/b.sh` (tier A) and a file under `docs/`; from `docs/`, `--git base HEAD` prints the lower tier of the docs file, and a tier-A package gets a Sonnet builder and a tier-B review plan.

**Requirements:**
- RT-3b-1: every `git diff` call in `changed_paths` passes `--no-relative`, so its paths are repo-root relative whatever `diff.relative` says and wherever the tool runs.
- RT-3b-2: the committed, staged and unstaged forms all hold it.

**Acceptance tests (REQ: RT-3b-1, RT-3b-2), in `tests/test_risk_tier.py`, written first:**
- `test_diff_relative_config_does_not_drop_paths`: a temp repo with `diff.relative=true`, a commit changing `image/b.sh` and `docs/a.md`; `--git base HEAD` run from `docs/` prints A (mutant: drop `--no-relative` from the committed call).
- The same with an uncommitted (staged, then unstaged) tier-A edit and HEAD the literal `HEAD`, run from a subdirectory (mutant: drop it from the `--cached` call).
- Existing cases still pass.

**Out of scope.** `ls-files` (already `--full-name :/`); the path-list form.

**Scope:** `tools/risk_tier.py`, `tests/test_risk_tier.py`, `tools/ASSUMPTIONS.md` (one row), this brief. Build on a tier-A (strongest) session.

**Usage estimate:** 25k tokens; checkpoint at 40k. Small, so it must not grow beyond about 20 lines plus tests.
