# UPD-5r: local requalification before a stable release installs

Work items #4031 (slice a) and #4032 (slice b). Written 2026-10-30 against main at d5cd78e8.

## Goal

UPD-5's stable row ends "plus local requalification": before an ordinary release installs on a stable box, the box re-tests it on its own held-out suite, replays and security suite (HLD-2, HLD-3). That lived in the change engine (`broker/change`, `ProposeRelease`), which #3468 (c3) deletes. Mark chose option C on the UPD-7w card (decision record on #3961, comment 6520945951): delete the engine now, rebuild requalification as the very next row, and ship no ordinary stable release to an owner box until it is back. This package rebuilds it outside the change engine, so the ship gate is the rule itself failing closed, not a flag.

## What main shows

- `update.Verified` names a release exactly (`Ref`), and `Store.Installed` names the running one (`Version`, `UsrRootHash`, `ManifestSHA256`).
- `StableReady` (UPD-7t) decides soak plus attestations; UPD-7w (#3961) builds the release check that calls it and schedules through the applier.
- No sandbox boots a candidate image, and the new core has no held-out cases, replay records or security cases yet (`broker/replay` and the change engine's suites are deleted or being deleted).

## Slice (a), #4031: the rule, the record and the ship gate

`broker/update/requal.go`:
- `Runner` interface: `Run(ctx, rel *Verified, suite string) (Score, error)`; a nil `rel` is the installed release, the baseline.
- `Score{Suite, Digest, Cases, Passed, Unadmitted}`; suites `SuiteHeldOut`, `SuiteReplay`, `SuiteSecurity`, run in that order.
- `NewRequalifier(store, runner, path)`; `(*Requalifier).Requalify(ctx, v) (Verdict, error)`.
- Rule per suite (HLD-2, HLD-3): candidate and baseline ran the same suite (digest and case count); held-out and replay pass no fewer than the baseline (an empty suite passes); replay has no unadmitted step; security passes every case, has at least one, and no fewer than the box's floor, which only grows.
- A malformed score, a `Runner` error or an unreadable record is an error and saves nothing (fail closed). No verdict is kept: every call runs every suite as it is now (#4033 L3: a kept pass skipped cases added since). The floor is saved before the verdict is returned.
- **Ship gate:** a nil `Runner` answers `RequalUnavailable`, never passed. UPD-7w's check holds an ordinary stable release on any answer but passed, so no owner box on stable takes one until slice (b) is wired.
- Scope: requalification gates ordinary releases on stable only. Fast boxes take them at once (UPD-4), security fixes follow UPD-8, as UPD-5's table sets, and first boot (UPD-3) installs before trust with no suites to run; test boxes run on fast, which is how they install meanwhile. Owner approval for behaviour-changing releases (UPD-5's third row) is out of scope.

**Requirement IDs:** UPD-5, HLD-3.

**Acceptance tests** (`broker/update/requal_test.go`, marker `REQ: UPD-5, HLD-3`): `TestNoRunnerHoldsTheRelease`, `TestRequalifyPassesWithNoRegression`, `TestEmptyTaskSuitesPass`, `TestRequalifyFailures` (held-out and replay regressions, an unadmitted replay step, a failing or empty security suite, a different digest or case count), `TestSecuritySuiteOnlyGrows`, `TestSuiteGrowthIsRunAgain`, `TestFailureIsRunAgain`, `TestNoRunnerAfterAPassStillHolds`, `TestRunnerErrorKeepsNothing`, `TestMalformedScoreFailsClosed`, `TestCorruptRecordFailsClosed`, `TestRequalifyRefusesUncheckedRelease`. Each named rule has a one-line revert mutant its test kills (PR body).

**Scope:** `broker/update/requal.go`, `broker/update/requal_test.go`, `broker/update/ASSUMPTIONS.md` (row UPD-5r-1), `briefs/UPD-5r.md`, `briefs/UPD-7w.md` (the ship gate replaces its open point).

**Tier:** A (`update` is in `TIER_A_BROKER`). **Guard files:** none (no new package, no new import).

## Slice (b), #4032: the sandbox runner (outline; its builder writes the full brief)

The production `Runner`: boots the candidate's `/usr` image in a sandbox (`broker/vm`) with no live effects, and runs against it and against the installed release the held-out cases (owner outcomes in the kernel log, KRN-9), replays of past tasks with recorded clerk responses (HLD-2) and the security suite (§16 injection tests plus HLD-5 regression cases), metered against an evaluation budget the candidate cannot change. Wired in `cmd/agentosd` beside UPD-7w's check (serial, D-111). It likely needs kernel-side suite sources first; its brief splits them out if so. Until it lands, the ship gate holds.

## Dependencies

None for slice (a). UPD-7w (#3961) consumes it: its brief now makes `Requalify` a required part of the check, so it builds after this merges (scopes are disjoint under D-111). Before starting, no open PR touches `broker/update/`.

## Estimate

Slice (a): about 200 lines of code and 250 of tests, 60k to 90k tokens.
