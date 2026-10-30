# UPD-7w: the release check that wires the stable-release gate

Work item #3961 (release finding of UPD-7t, #1013). Written 2026-10-30 against main at ec0c3c78.

## Goal

A box on the stable channel must eventually install an ordinary release, and only after UPD-5's soak plus attestations; a box on fast takes it at once; a security fix follows UPD-8. `update.Verified.StableReady` (`broker/update/soak.go`, UPD-7t) decides that, but nothing calls it: #3452 deleted `broker/maintain` Loop 3, which was the release check, unwired. This package rebuilds that check as one component in `broker/apply` (the update clerk), drives the real `Applier` with it, and owns the lifecycle matrix below. It is the "A1 wiring" `broker/apply/ASSUMPTIONS.md` A1, A5 and A9 refer to.

## What main shows (read before building)

- **The gate exists and is tested** (`update/soak.go`, `soak_test.go`); its doc comment fixes where `firstSeen` and `now` come from.
- **The pattern exists:** `broker/firstboot/firstboot.go` `Gate.Step` tries `Mirrors()` in order with `Store.Check` and calls `Applier.ScheduleFirstBoot`. The ongoing check is the same loop after first boot, with an adoption, the gate and attestations.
- **The old design is in git history:** `git show 0198427b^:broker/maintain/maintain.go` (and `maintain_test.go`). Reuse its `check` flow, its `Seen` map (a stable box also runs a fast-channel `Store.Check` only to note sightings, so a release promoted from fast to stable keeps its first sight), its single read of the attestor lists per check (SR3-6f-1), and its test cases. Do not bring back the scheduler, `loops`, `change` or the owner-approval path.
- **`ProposeRelease` is going away.** It lives in the change engine (`broker/change/pipeline.go`), which MIG-4-untrusted-change-c3 (#3468) deletes; nothing in production builds a `change.Pipeline` today (brief `MIG-4-untrusted-change.md`, "What main shows"). So this check does **not** call it, and nothing in production implements `apply.Stager` (`ConfirmStaged`, `StageFailed`, `StageDropped`), which `apply.New` requires. The check therefore mints the adoption ID itself and is the applier's `Stager` (contract below).
- **No network mirror and no attestation fetch exist.** `update.DirSource` is the only `Source`; nothing fetches attestations. Both stay behind config functions here (Out of scope).
- **Clock:** `clock.Guard.Earliest` is the earliest credible time (a soak's `now`); `Latest` the latest. Both answer while restricted; the caller reads `Status.State`.

## Requirement IDs

UPD-5 (stable soak plus attestations; security fixes auto-staged), UPD-7 (no central staged rollout), UPD-4 (channels: fast at once, pinned never), UPD-8 (attestations only from the allow-list; security fix needs one), UPD-1 (A/B with fallback; a fallen-back release is not re-offered), CH-12 (owner text for each `Wait` reason).

## Contract (names are the builder's)

`broker/apply/check.go`: `type Check`, `NewCheck(CheckConfig) (*Check, error)`, `(*Check).Step(ctx) error` (one check; the daemon calls it daily and when the channel or attestor lists change), `(*Check).Line() string` (the STATUS line, or ""), and `*Check` implements `apply.Stager`.

`CheckConfig` (every function required unless noted; a missing one is an error from `NewCheck`):
- `Store *update.Store`; `Applier` as a small interface (`Schedule(*update.Verified, string) error`, `FellBack(int64) bool`), so tests can use the real `*Applier` or a fake.
- `Mirrors func() []update.Source` (tried in order, first verified answer counts, as firstboot).
- `Attestors func() (allow, interim []ed25519.PublicKey, err error)`: read once per `Step`; an error fails the step closed (nothing scheduled).
- `Attestations func(ctx, *update.Verified) ([][]byte, error)`: an error counts as no attestations (narrows only).
- `Own ed25519.PublicKey` (this box's attestation key; never counts).
- `Channel func() (string, error)`: an error or unknown value is pinned (fail closed).
- `Earliest`, `Latest func(ctx) (time.Time, bool)`: the wiring adapts the clock guard; `ok` is false unless `State` is `Agreed`, `NetworkOnly` or `CarrierOnly`. `apply` does not import `clock`.
- `Trusted func() bool`: the first-boot gate has finished (`firstboot.Gate.Trusted`); until then `Step` does nothing, so first boot keeps its own path (UPD-3, apply A8).
- `Requalify func(ctx, *update.Verified) (update.Verdict, error)`: UPD-5's local requalification, `(*update.Requalifier).Requalify` (UPD-5r, #4031). Required: the wiring passes a `Requalifier` even when it has no runner, so the ship gate below can never be configured away.
- `State Store` (its own file, not the applier's), `SoakDays`, `MinPasses` (defaults 7 and 1; `StableReady` clamps them; the owner's way to change them is out of scope).

**One `Step`, in order:**
1. Not `Trusted()`: return. Channel pinned (or unreadable): no `Store.Check`; `Line` is the pinned line; return.
2. Read the attestor lists once. `Store.Check` each mirror with `Options{Channel, Attestors, InterimAttestors}` until one verifies. On a stable box, also run a fast-channel check to record sightings only (as the old Loop 3); its release is never scheduled.
3. **Sightings:** key = `UsrRootHash` plus a SHA-256 over the sorted `Images()` digests (the image, not the version, so a fast release republished as stable is not soaked twice). Record a new key with `Latest`, never `Earliest`: an early first sight would shorten the soak. When `Latest` is not ok, record nothing this step. Prune keys older than twice `update.MaxSoakDays`. Save before using.
4. For `res.Release` (or none: clear `Line`, return): fetch attestations, `v = v.WithAttestations(atts, Own)` (so `Security()` holds for the applier's A9 check), then `w, err := v.StableReady(atts, Own, channel, seen, now, SoakDays, MinPasses)` with `now` from `Earliest`; when `Earliest` is not ok, pass a zero `now` (not ready for an ordinary release; a security fix needs no soak and proceeds).
5. Not ready (or `ErrNeedsAttestation`): set `Line` from the reason; return. Ready: if `FellBack(version)`, set the fallback line and return (UPD-1, apply A1). If an adoption for this exact `update.Ref` is staged, confirmed or failed, return. **Ship gate (Mark's decision C, #3961 comment 6520945951):** Then, ordinary (not `Security()`) and on stable: call `Requalify`; unless the verdict is `Passed`, set the requalification line (unavailable, or failed) and return; an error sets the unavailable line and returns (fail closed). A fast box and a security fix skip it, as UPD-5's table sets. `Requalify` keeps no verdict and runs every suite, so it comes after the fallback and adoption checks and runs once per offer. Otherwise mint the next ID (`upd:<version>:<n>`), **save it as staged first**, then `Schedule`. The applier settles every `Schedule` refusal (`ErrApplying`, `ErrFellBack`, `ErrRefused`) through `StageDropped` (A5), so a refused release is re-offered at a later step unless it fell back; record the outcome for `Line`. Re-offers of an `ErrRefused` release repeat until the owner's `Retry` (A5's LATER A5-reask); keep that bound, do not add one.

**Stager (the adoption record):** `ConfirmStaged(id)` → confirmed; `StageFailed(ctx, id)` → failed (never re-offered: the applier's `FellBack` also refuses it); `StageDropped(ctx, id)` → dropped, so the next `Step` re-offers the release under a new ID (apply A5, A9). Each is idempotent, saves before it returns, answers for IDs minted by an earlier process (the applier settles across restarts, A10), and returns an error whose `Permanent()` is true (what `apply.permanent` tests) for an ID it never minted. Prune settled IDs older than the newest confirmed version.

**Owner text (CH-12).** One STATUS line per wait reason, plus fallback and pinned: soak (with the date from `Until`, in the box's zone), attestations, no attestor listed, security fix waiting for an attestation, requalification unavailable, requalification failed, fell back. The unavailable line will stand on every stable box until #4032, so it says nothing is needed and security fixes still install, with no "requalification" word and no switch-to-fast step (that would skip the soak and attestations too), e.g. "Update 42 waits until this box can test it itself. Security fixes still install. Nothing is needed from you." The failed line says this update did not pass this box's own tests and nothing is needed from the owner, and names no retry or date (a held-out or replay failure is retried at each step; a security failure is final for that release on that suite). GSM-7, one segment, no identifiers or reason codes, each with a cause and, where the owner can act, the step (the UX lens recurring kinds: "a problem text names a step that cannot work", "a STATUS line gives no cause or next step"). Ordinary waits need nothing from the owner and say so. Example tone only: "Update 42 installs after 3 Nov, once early boxes have tested it. Nothing is needed from you." The UX screen may reword.

## Lifecycle matrix (this package is the integration owner)

| Stage → / outcome ↓ | First boot | Steady daily check | Process restart | Fallback | Channel change |
|---|---|---|---|---|---|
| Ordinary, stable | no step until `Trusted` | waits soak, then attestations, then requalification (held while unavailable or failed); then scheduled once | staged-but-lost release (A5 drops it) re-offered under a new ID | not re-offered; fallback line | stable→fast: scheduled next step; →pinned: nothing scheduled, pinned line |
| Ordinary, fast | as left | scheduled at once | as left | as left | fast→stable: soak counts from the fast sighting |
| Security fix | as left | scheduled with one listed fast attestation, no soak; waits with its line otherwise | as left | as left | pinned: not scheduled (the applier's `Paused` holds) |
| Mirror unreachable or unverified | as left | nothing scheduled; sightings kept | as left | as left | as left |
| Attestor list narrowed | — | a dropped security fix (A9) is re-offered only under the current policy | — | — | — |

Each filled cell is a test (Acceptance tests). Construction in `cmd/agentosd` is one call beside the applier, which MIG-4-adapters-e-wire-b (#3677) builds; whichever of #3677 and this row lands second adds it, with the check passed as the applier's `Pipeline` (comment on #3677), and this package's matrix runs against the real `Applier`, `update.Store` and `updatetest` mirror so the agentosd call adds no untested behaviour.

## Acceptance tests

**Acceptance tests:** new `broker/apply/check_test.go` (marker `// REQ: UPD-5, UPD-7, UPD-4, UPD-8, UPD-1, CH-12`), using the real `Applier` from `rig_test.go` where the row says so, the `updatetest` mirror, and a fake clock with `ok` switchable.

- UPD-5, UPD-7: `TestStableSchedulesAfterSoakAndPass` (real applier) — first step records the sighting and schedules nothing; at 7 days with no pass, waits on attestations; with one listed fast pass, `Schedule` is called once with a minted ID; a further step does not schedule again. Catches a check that skips the gate or schedules twice.
- UPD-5: `TestPromotedReleaseSoaksFromFastSighting` — image first seen on the fast channel 7 days ago, now published on stable: ready on its first stable sighting (with a pass). And a different image under the same version is a new sighting. Catches keying by version.
- UPD-5: `TestSightingUsesLatestAndSoakUsesEarliest` — `Latest` ahead of `Earliest` by 2 days: the soak ends 2 days later than with equal clocks, never earlier; `Latest` not ok records nothing; `Earliest` not ok schedules no ordinary release but still schedules a security fix. Catches swapped clocks (mutant: record with `Earliest`).
- UPD-4: `TestFastSchedulesAtOnce`, `TestPinnedOrUnreadableChannelSchedulesNothing` (`"pinned"`, `""`, an error).
- UPD-8: `TestSecurityFixNeedsListedAttestation` — with none: not scheduled, security line; with one: scheduled with no soak and `Security()` true on the scheduled `*Verified`. `TestAttestorReadErrorFailsClosed`.
- UPD-1: `TestFallenBackReleaseNotOffered` (real applier: fall back once through `Resume`; `StageFailed` marks it failed; later steps schedule nothing for that version and show the fallback line; a newer version is scheduled).
- UPD-1: `TestDroppedAdoptionReofferedUnderNewID` (real applier: a restart drops the pending release, A5; next step schedules it under a new ID) and `TestStagerAnswersAcrossRestart` (IDs minted by one `Check` are confirmed, failed and dropped through a second `Check` on the same `State`; an unknown ID is a permanent error).
- UPD-1: `TestSaveBeforeSchedule` — a `State.Save` failure schedules nothing.
- UPD-3: `TestNothingBeforeFirstBootTrusted`.
- UPD-5 ship gate: `TestStableHoldsUntilRequalified` (real applier, real `update.Requalifier`): with no runner, a soaked and attested ordinary release on stable is never scheduled and shows the unavailable line; with a failing runner, the failed line; with a passing runner, scheduled once. `TestRequalifyErrorHoldsTheRelease`. `TestFastAndSecuritySkipRequalification`: a fast box and a security fix are scheduled with no runner. `NewCheck` refuses a nil `Requalify`. Mutant: drop the `Requalify` call.
- CH-12: `TestCheckLinesAreOneGSM7Segment` — every line, at the longest version number and date, is GSM-7 in one segment (use `modem.Segments` if `apply`'s tests may import `modem`, else an inline GSM-7 table) and names no reason code.
- Mirrors: `TestMirrorFailureSchedulesNothing` (first mirror unverified, second good: uses the second; all fail: nothing, sightings kept).
- Mutants (potency recurring kind): the PR body lists, per test, the one-line mutant of `check.go` it kills.

## Scope

`broker/apply/check.go` (new), `broker/apply/check_test.go` (new), `broker/apply/ASSUMPTIONS.md` (A1 and A5 now name this check instead of "the change pipeline" and "the A1 wiring"; one new row for the check: the sighting key, the clocks, the adoption record, and the open point below), `briefs/UPD-7w.md`.

**Tier:** A (`apply` is in `TIER_A_BROKER`): strongest model, L3 plus the separate Security accept (OPERATING §3, §7).

**Guard files:** none (no new package; `apply` gains no broker import).

## Ship gate (settled: Mark's decision C, #3961 comment 6520945951)

UPD-5's stable row ends "plus local requalification", which lived in the change pipeline that c3 (#3468) deletes. It is rebuilt as UPD-5r (#4031, `update.Requalifier`), the next row, and no ordinary stable release reaches an owner box until requalification is back: this check schedules one only on a `Passed` verdict, and a `Requalifier` with no runner never passes, so the gate lifts when the sandbox runner (#4032) is wired. Test boxes run on fast and install meanwhile; record that gap as an ASSUMPTIONS row. This replaces the earlier option-A default (schedule without requalification). Owner approval for behaviour-changing releases (CHG-3) stays out of scope.

## Out of scope

A network mirror `Source` and the mirror list (UPD-b3, agentosd); the attestation transport (PUB-1, D-088); the owner's way to change soak days or passes; the requalification runner (#4032) and owner approval (above); the quiet window and jitter (`Applier`, A3); re-offer after an unpin (#3822, which rechecks once this merges); construction in `cmd/agentosd` (#3677).

## Dependencies

Code: `update.Requalifier` (UPD-5r-a, #4031) must be on main first. The declared scope is `broker/apply` only, so neither #3979 (`broker/update`) nor #3994 (`broker/clock`) overlaps it under D-111; the row was held for them by the coordinator and is ready to build once both merge. Before starting, check that no open PR touches `broker/apply/` (D-111).

## Estimate

Medium: about 300 lines of code, 500 of tests, two ASSUMPTIONS edits. 110k to 130k tokens; split the Stager into its own PR first if the matrix tests push past 150k.
