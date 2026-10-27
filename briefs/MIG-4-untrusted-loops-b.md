# MIG-4-untrusted-loops-b: loop settings off the journal (#2786, part b)

Part (a) merged as #2809 (Loop 1 and the Harvester deleted). Mark approved the a/b split on the Decisions 7 card (#2786 comment 6344182040). This brief is part (b) as main stands at 90dd141. It is tier A (`loops` is in `TIER_A_BROKER`): two reviews, Security and L3. It touches no gate file, so no separate Security accept is needed.

**Waits on #3310.** That PR holds `broker/loops/plainname.go` and `broker/daemon/arc2_test.go` (D-111). Start the build once it merges.

## What changed since (b) was parked

(b) was parked waiting for "a kernel spare admission class" (#2786 comment 6340723018, point 2). Reading main today shows that wait was about the `meter` half, and that half is done:

- **Spend is already on the kernel.** `loops/spare.go` is the spare envelope, a kernel key with a day spend cap (MIG-4-spend-m). Raising the cap calls `Spare.Widen` (the owner's passkey, KEY-6) and lowering it calls `Spare.Revoke`. No file in `loops`, `probecmd` or `machprobe` imports `meter`.
- **Nothing in production runs the scheduler.** #2801 removed the scheduler, Loop 2's guard and the spare meter from `cmd/agentosd`. agentosd still uses two things from `loops`: `loops.ParseText`, which gives a loop setting text a fixed reply, and `loops.Executor`, a string in `learnstate.go`'s `registerRetired`. `loops.New` is called only from tests (`loops`, `maintain`, `grants`) and `NewGuard` only from the `assurance/loop2` harness.
- **What still uses the old core** splits into two groups:
  1. **The settings path.** `settings.go` sends each owner setting through the journal as a `meta.loops.*` intent and implements `journal.Executor` (`Check`, `Execute`, `Reconcile`), plus the approval card for a budget raise (`BudgetAsk`, `Line`, `ErrNeedsOwner`, `ErrPending`). `scheduler.go` has `Config.Journal`, `Attach` and the `journal.Executor` assertion. `settings.go` also uses `durable.ErrDirSync`. The tests that go with this are `settings_test`, `updates_test`, `wiring_test`, `repeat_setting_test` and `dirsync_test`, plus the scheduler half of `rig_test`. This brief ports this group.
  2. **Tests that build a `change.Pipeline`.** `secure_test`, `report_test` and the pipeline half of `rig_test` open a `journal.Engine` only because `change.Pipeline.Attach` needs one. The production files `secure.go` and `report.go` import `change` and not `journal`. This group moves only when `change` does, so it **folds into #2785b**. No separate row: #2785b's done-check gains "and `loops`' pipeline tests".

The RES-1 and RES-5 bound is still missing from the kernel: spare work should draw a pool only down to the owner's reserve and the foreground forecast, and `AdmitSpend` has no admission class. That gap matters when the scheduler is wired again (A11, G4). It does not matter for this port, which wires nothing. It goes on the Findings line as `later` (recheck), filed if no row covers it.

## Design

Owner settings are untrusted-side local state. A budget change is the one setting that is a key change (KEY-6), and the kernel already holds that through the spare envelope. So the journal round trip is replaced, not adapted:

- **`Set(ctx, r, unlocked)` applies directly.** It validates, applies and saves the setting, then returns. Who may send which setting does not change: the owner channel authenticates the sender, and a locked session may make only narrowing settings (pauses, a lower budget, slower or more cautious updates). `Set` takes `unlocked` and checks `narrowing` itself, under the lock that orders budget changes (below). Today `Text` checks it before the call and the old `Execute` checked it again under the lock (settings.go:796). Without that recheck, a racing lower could turn a locked "lower to 400" into a raise from 100. LOOPS ON and faster updates are accepted only in a session unlocked with an approval code (CH-14). That is how this brief reads HLD-4's "turning it back on is an owner-approved change". Record it in ASSUMPTIONS.
- **Only narrowings apply during STOP.** Today the journal holds LOOPS ON and update settings while STOP is in force (settings.go:521-526, `TestLoopsOffWorksDuringStop`). `Set` keeps that: it refuses a non-narrowing setting while `cfg.Stopped()` is true.
- **Every raise goes through the passkey.** KEY-6 makes every budget raise a widening. Today `Spare.SetCap` calls `Widen` only above the envelope's cap (spare.go:100). So after a lower, a raise back up to the envelope's cap derives a new key without the passkey, and only the approval card stops it. That card goes, so **`SetCap` changes too**: it widens whenever `n` exceeds the current cap, not only the envelope's. If `Widen` is nil or fails, the reply says that raising spare-time AI use needs the owner's passkey, and neither the setting nor the cap changes. A lowering still revokes through `Revoke`. Remove the approval-card path: `BudgetAsk`, `Line`, `LowTierRaiseMax`, `ErrNeedsOwner`, `ErrPending`, and the `owner` import from non-test files.
- **A narrowing never waits on the passkey.** `Widen` can block for as long as the owner takes, and today `SetCap` holds `Spare.mu` across it (spare.go:99-113). `Cap`, `Key` and `EvalKey` take that same lock, and `Tick` reads `Room` and `Used`. So `SetCap` splits in two:
  - `Spare.Prepare(n) (widened key.Key, err error)` returns a zero key when `n` needs no widening. Otherwise it calls `Widen(n)` with no lock held, and checks that the result holds day cap `n`.
  - `Spare.Commit(n, widened)` runs under `Spare.mu`. It rechecks that the envelope tip and the cap are the ones `Prepare` saw, and refuses with `ErrMoved` if either changed. Then it derives and revokes as `SetCap` does today.
  - `SetCap(n)` stays as `Prepare` followed by `Commit`, for callers that do not race.

  In `Scheduler`, a dedicated `budgetMu` orders budget `Set`s. A raise first calls `Prepare` with no lock held. It then takes `budgetMu` and, holding it, rechecks narrowing, calls `Commit`, records `SpareCalls` and saves. A lower takes `budgetMu` and commits straight away, so it never waits on a passkey. A raise whose `Commit` returns `ErrMoved` is refused, and the owner is asked to send it again. `Settings()`, `Narrows`, the run loop and non-budget settings never take `budgetMu`.

  The builder may instead take a smaller route (L3 item 3 on #3434): on a lower, replace the held envelope with its `LowerSpendDay(n)` derivation. The kernel then makes every later raise exceed the envelope's cap and need `Widen`, and today's "widen only above the envelope cap" condition stays unchanged. The `Prepare`/`Commit` split is still needed either way.
- **Saved state is the settings only.** Delete `Seq`, `Applied`, `Order`, `settingID`, `parseSetting`, `keepApplied`, `pruneLocked`, `orderLocked`, `fencedReply`, `heldReply` and the journal-error cases in `Text`. Old saved JSON that still has `seq`, `applied` or `order` must load its settings; `encoding/json` ignores the extra fields.
- **A failed save rolls back only a widening.** If a raise, LOOPS ON or faster updates fails to save, it rolls back: the setting and, for a raise, the cap (`Commit` of the previous cap, which is a lowering) go back to what they were, and the reply is "I could not save that setting." A narrowing that fails to save stays applied in memory: LOOPS OFF, LOOP n OFF, a lower, slower updates, or security updates set to ask. The reply says it is in effect now but was not saved, so it lapses on restart. This is KEY-6: a narrowing "takes effect before any further step is checked". Rolling back a lower would also be a raise, which needs the passkey (L3 item 1 on #3434). `Config.Store` becomes a `loops.Store` interface with the same `Load`/`Save` methods, which `change.MemStore` still satisfies. Its contract: `Save` returns `privfile.ErrUnsynced` (`broker/kernel/privfile`) when the new form is in place but the directory sync failed. `saveLocked` counts that as applied and logs it, as #1320 did with `durable.ErrDirSync`. privfile.go:98-101 says such a write "neither failed nor took effect for certain", so the ASSUMPTIONS row records counting it as applied as a choice. No production store exists, because agentosd wires no scheduler. The row that wires the scheduler again adds a `FileStore` over `privfile.WriteAtomic`, as owner/state.go:174 does. `change.FileStore`, which returns `durable.ErrDirSync`, is not a valid `loops.Store` for production, and the type's doc comment says so.
- **Remove the journal vocabulary.** Delete `ActionOff`, `ActionOn`, `ActionBudget`, `ActionBudgetLower`, `ActionUpdates`, `OriginOwner`, `Config.Journal`, `Attach`, the `Journal` alias, `runIntent`, and `Check`, `Execute` and `Reconcile`. **Keep `Executor = "loops"`**, with a comment saying agentosd registers it as a retired executor (#2801) and that it goes when the journal does. It is a string constant, not code between the old core and the new, and keeping it keeps this PR out of `cmd/agentosd`.
- **`grants/loops_test.go` shrinks.** Delete the tests that drive a real `loops.Scheduler`: `TestLoopSettingsGoThroughTheScheduler`, `TestOnlyTheOwnerChangesLoopSettings`, `TestAnUnansweredRaiseLapses` and `TestALapsedRaiseIsNotAChangeDecision`, with their rig. Keep `TestLoopSettingsDeniedWithoutScheduler` and `TestOnlyTheLoopsSentinelItselfAsks`, with a local `NeedsOwner` sentinel in place of `loops.ErrNeedsOwner`. They cover gate.go's `evaluateLoops`, which daemon tests still reach. The file then no longer imports `loops`. `grants` is old core, and this is a net shrink, which the ratchet allows.
- **Split the test rig.** `rig_test.go` keeps the scheduler, spare and clock with no journal, and uses a recording fake for `Sharing`. A real `Pipeline.SetSharing` runs a journal intent (change/effect.go:742-790). The journal engine, the pipeline, `policy`, `tasks`, `current` and `rig.task` move to a new `pipelinerig_test.go`, which only `secure_test` and `report_test` use. `TestStopSharingGoesToThePipeline` is rewritten against the fake. After this PR, the only files in `loops` that import `journal` are `pipelinerig_test.go`, `secure_test.go` and `report_test.go`.

## Requirements and acceptance tests

New and rewritten tests cite v1.0 IDs (`REQ: HLD-4, RES-5, KEY-6, UPD-4, UPD-5, CH-14`). LOOP-*, OP-* and CHG-* are retired (SPEC Appendix A), and the ratchet must not see the old-core marker count rise.

**Acceptance tests:**
- `broker/loops/settings_test.go::TestOwnerTextAppliesSettingsWithoutAJournal` (HLD-4, UPD-4, UPD-5): with no journal anywhere in the rig, LOOPS OFF, LOOPS ON, LOOP n OFF, UPDATES FAST, UPDATE SOAK n and the security-ask text each apply on `Text`, and survive a restart through `New` over the same store. It catches a settings path that still needs an attached journal.
- `settings_test.go::TestRaisingTheSpareBudgetNeedsThePasskey` (KEY-6, RES-5) covers four cases:
  - With `Widen` nil, the reply names the passkey, and `SpareCalls` and the spare key's day cap do not change.
  - With `Widen` returning an error, nothing changes.
  - With a working `Widen`, both are raised.
  - A lower followed by a re-raise below the envelope's cap, with `Widen` nil, is refused.

  It catches a raise made without the kernel key. Revert mutants, each of which must fail the test: (i) write `SpareCalls` before `SetCap` and ignore its error; (ii) put back "widen only above the envelope cap" in `SetCap`.
- `spare_test.go::TestWidenRunsOutsideTheSpareLock` (KEY-6): while `Widen` blocks, `Cap`, `Key`, `Used` and a lowering `SetCap` return. When the blocked raise's `Commit` runs after that lowering, it returns `ErrMoved` and the lower stands. It catches `Spare.mu` held across the passkey wait.
- `settings_test.go::TestLoweringTheBudgetRevokesKeysAtTheOldCap` (KEY-6, RES-5): a lower from a locked session applies, and the kernel refuses a key that `Spare.Key()` handed out before the lower. It catches a lower that changes only the local number.
- `settings_test.go::TestNarrowingsNeverWaitOnThePasskey` (HLD-4, KEY-6): while a raise blocks inside `Widen`, these all complete within a short deadline: LOOPS OFF from a locked session, a budget lower, `Settings()`, `Narrows`, `Spare.Cap()` and one scheduler `Tick`. It catches a lock held across the passkey wait.
- `settings_test.go::TestConcurrentBudgetChangesEndConsistent` (RES-5): raises and lowers race, some of them blocked in `Widen`. At the end, `Settings().SpareCalls` maps to the cap the `Spare` holds. Run it with `go test -race -count=50` before opening the PR.
- `settings_test.go::TestALockedLowerCannotBecomeARaise` (CH-14, KEY-6): a locked "SPARE BUDGET 400" is checked against the cap current under `budgetMu`. If a lower to 100 lands first, it is refused as a raise.
- `settings_test.go::TestOnlyNarrowingsApplyDuringStop` (HLD-4, KEY-6), which replaces `TestLoopsOffWorksDuringStop`: while `Stopped()` is true, LOOPS OFF, a lower and slower updates apply, and LOOPS ON, a raise and faster updates are refused.
- `wiring_test.go::TestALockedSessionTakesOnlyPauses` (CH-14, HLD-4), rewritten: a locked session refuses LOOPS ON, a budget raise and faster updates, and takes LOOPS OFF and a lower. Revert mutant: make `narrowing` return true; this test must fail.
- `dirsync_test.go::TestAnUnsyncedSaveCountsAsApplied` (HLD-4, RES-5): with `privfile.ErrUnsynced`, the setting is applied and logged.
- `dirsync_test.go::TestAFailedSaveRollsBackOnlyAWidening` (HLD-4, KEY-6, RES-5) covers two cases, each with `Widen` nil and with it set:
  - A raise that fails to save leaves the setting and the spare cap as they were, and the reply says it could not save.
  - A lower or LOOPS OFF that fails to save stands: the cap stays lowered, keys at the old cap stay revoked, `Widen` is never called, and the reply says the setting is not saved.

  It catches rolling back a narrowing. Revert mutant: roll back every setting on a failed save; this test must fail.
- `wiring_test.go::TestOldSavedStateLoads` (HLD-4): a saved state with `seq`, `applied` and `order` loads its settings. It catches a strict decoder that would refuse old state.
- Deleted with the intent path:
  - `TestNeedsOwnerIsRecognizedWithoutImportingLoops`
  - `TestABudgetRaiseIsALowTierLineFromBrokerState`
  - `TestASettingAppliedLateIsKeptForReconcile`
  - `TestOldStateIsOrderedOnLoad`
  - `TestBudgetRaiseAskComesFromBrokerState`
  - `TestOnlyTheOwnerChangesLoopSettings` (loops' copy)
  - `TestSpareBudgetLowersOnTextAndRaisesOnlyWithApproval`, which the passkey and lowering tests replace
  - `TestUpdateSettingIntentsAreOwnerOnly`
  - the journal-replay half of `TestP6RepeatedOwnerSettingAfterAFailedOne`

  `updates_test.go` and `repeat_setting_test.go` are rewritten to drive `Text` and `Set` directly. Keep the repeat case: a setting sent again after a failed save applies.

**Done-check:** `grep -lE '"github.com/ghbmrk/agentos/broker/(journal|durable|meter)"' broker/loops/*.go broker/probecmd/*.go broker/machprobe/*.go` lists only `pipelinerig_test.go`, `secure_test.go` and `report_test.go`. From `broker/`, `go vet ./...` and `go test -race ./loops/... ./grants/... ./maintain/... ./control/... ./corpus/... ./probecmd/... ./daemon/...` pass. Also run `python3 tools/trace.py --ratchet origin/main`, the `checks` job's commands, `tools/g1_scope.py --git origin/main HEAD` and `tools/risk_tier.py --git origin/main HEAD` (OPERATING §5, speed rules).

## Scope

- `broker/loops/settings.go`, `scheduler.go`, `spare.go`, `doc.go` (comments only), `ASSUMPTIONS.md`. Rewrite L2's settings row for direct apply, strike rows that describe agentosd wiring #2801 removed (#2801's Findings flagged one), and add rows for the CH-14 reading of "owner-approved" and the `ErrUnsynced` choice.
- Tests in `broker/loops/`: `settings_test.go`, `updates_test.go`, `wiring_test.go`, `repeat_setting_test.go`, `dirsync_test.go`, `spare_test.go`, `rig_test.go`, new `pipelinerig_test.go`, plus any of `scheduler_test.go`, `pe5_test.go`, `race_test.go`, `ownertext_test.go`, `secure_test.go` and `report_test.go` that only need the rig split.
- `broker/grants/loops_test.go` (shrunk, as above).
- `broker/maintain/*_test.go`, but only if a removed `Config` field breaks them. Today they set only `Store`, `Spare`, `Sources`, `Now` and `Busy`.

**Guard files:** `broker/daemon/arc2_test.go`. The `loops` allowlist entry drops `journal` and `owner` and adds `kernel/privfile`. No `tools/risk_tier.py` or `tools/g1_scope*` change: `loops` is already classed.

**Out of scope:** `cmd/agentosd`, `change`, `journal`, `grants/gate.go`, the kernel, `secure.go`, `report.go`, `probecmd` and `machprobe`. `probecmd` and `machprobe` import no old core, so whether they stay is decided when the scheduler is wired again under HLD-5.

## Usage estimate

About 120-130k tokens. Most of it is about 1.3k lines of test rewrite; the net production change is about −200 lines. If the build passes 150k, the first thing to drop is the `TestOldSavedStateLoads` rewrite.
