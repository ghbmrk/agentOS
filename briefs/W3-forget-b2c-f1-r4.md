# W3-forget-b2c-f1-r4: the digest does not run while learning is down and forgets are held

Board section: Integration. Follows W3-forget-b2c-f1-r1 (ASSUMPTIONS R5, R6 in `broker/cmd/agentosd`); SPEC CAP-3. Issue #974. Class: release.

**Failure path (checked at main 59618fd):** `openLearning` fails, `main.go:738` calls `learningOff`, and `wireDigest` (`main.go:743`) is skipped, so the digest is never told which goals are forgotten. `go dg.run(ctx)` (`main.go:851`) starts regardless. The box's own `forgets` set is loaded from its saved state (`digest.go:199`, `Forgets`), but the goals a restored log names (CAP-3) reach it only through `wireDigest`. A restore with a broken learn dir therefore sends a batch that names a goal the owner had forgotten.

**Requirement IDs** (the builder writes the failing test first):
- **F1R4-1 (no run without the wiring):** when `lp == nil`, agentosd starts no digest run; a `digestBox` whose forgets cannot be known sends nothing that names a goal. The skip is logged once (existing log style, no owner text).
- **F1R4-2 (learning up is unchanged):** with `lp != nil` the digest wires and runs as today; the existing digest and forget tests pass untouched.
- **F1R4-3 (the other digest sources):** a digest that names no goal (the unclear-digest source) is not in scope; if the builder finds the skip also silences it, the PR says so as a finding, not a silent regression.

**Design (recommended; Mark's call):** skip `dg.run` while `lp == nil`, the smallest change that cannot leak. The alternative, running with every saved forget held, keeps the digest alive but needs a way to tell a goal from a non-goal batch line in `digestBox`, a larger change in a tier A file.

**Acceptance tests:**
- F1R4-1: `broker/cmd/agentosd/digest_learning_off_test.go::TestDigestDoesNotRunWhenLearningIsOff` (fails on main: run starts), `::TestDigestSendsNoBatchNamingARestoredGoalWhenLearningFailed` (restored log names a goal, learn dir unopenable; the fake sink sees no send).
- F1R4-2: `::TestDigestStillRunsWhenLearningIsOn`.
Mutants: start the run unconditionally; skip it on every start.

**Scope:** `broker/cmd/agentosd/main.go` (the `go dg.run` guard, extracted to a small helper the test calls), `broker/cmd/agentosd/digest_learning_off_test.go` (new), this brief. Not `tools/ASSUMPTIONS.md`; `broker/cmd/agentosd/ASSUMPTIONS.md` R6 gets a "closed by r4" note only if the builder finds it says the leak is accepted.

**Guards:** the source-scanning lint tests in the package (`forget_inform_lint_test.go`, `deadline_send_lint_test.go`) stay green; no new owner-facing text; the helper adds no import (arc2 and `netOK` untouched).

**Tier and model:** A (`tools/risk_tier.py` prints A for `broker/cmd/agentosd`): strongest model. **Dependencies:** none; no open PR touches `main.go` in scope (check at start, D-111). **Usage estimate:** 40k tokens, checkpoint 30k.

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| 1 | `digestBox` gets restored goals only through `wireDigest`. | `main.go:743`, `forget.go` `wireDigest` | If `open` also reads the log, F1R4-1 narrows to the saved set. |
| 2 | A digest down while learning is down is acceptable. | Learning down already disables routing held by `caps.learning` | If not, take the alternative above. |
