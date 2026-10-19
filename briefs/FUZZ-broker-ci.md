# FUZZ-broker-ci: the six FUZZ-broker targets join CI's short fuzz step

Board section: Harness and operating model. Work item: #2240. Follow-up of FUZZ-broker (#2149, merged); serves FUZZ-6 in `briefs/FUZZ-broker.md`. **Tier A** (`.github/`; Mark-gate): a Security review and a combined review at an equal head, built on the strongest model. Under D-137 (#2426) it is armed at its last accept; no Mark line.

**Why.** The short fuzz step in `.github/workflows/ci.yml` (`for t in sockets:FuzzRequest sockets:FuzzFrames browser:FuzzParse modemlink:FuzzInbound guest:FuzzMCP`, near line 301, run by `tools/fuzzrun.py --budget 20s`) lists only five targets. The six #2149 targets run in CI only on their seeds under plain `go test`. Failure path: a defect reachable only by fuzzing, such as the FuzzCheck external-address deny (Security review of #2149, point 2), is never searched for.

**Requirements:**
- FUZZ-broker-ci-1: the step lists `grants:FuzzApprovals`, `localsrv:FuzzSessions`, `netguard:FuzzSourcesRead`, `netguard:FuzzGatewayPolicy`, `netguard:FuzzCheck`, `vault:FuzzSlots`.
- FUZZ-broker-ci-2: every listed `pkg:Target` names a `func FuzzX(` that exists in that package's tests, so a rename cannot leave a target silently unrun.
- FUZZ-broker-ci-3: the job stays inside its timeout (six targets at 20s add about 2 minutes to a 30-minute limit); the PR body shows the job's duration.

**Acceptance tests:** (REQ: FUZZ-broker-ci-1, FUZZ-broker-ci-2): written first, in `tests/test_ci_scope.py`
- `test_fuzz_step_lists_broker_targets` parses `ci.yml` (mutant: remove one target).
- `test_fuzz_step_targets_exist` greps each package for the `Fuzz` function (mutant: misspell one).
- The PR body shows the CI log with all eleven targets run.

**Out of scope.** Changing the budget, the corpus, or adding new targets.

**Scope:** `.github/workflows/ci.yml`, `tests/test_ci_scope.py`, this brief. Do not run beside CI-mainguard or INFER-CI (same file, D-111).

**Usage estimate:** 20k tokens; checkpoint at 35k.
