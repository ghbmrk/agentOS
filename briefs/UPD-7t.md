# UPD-7t: the stable-release gate (soak plus attestations), with its test and marker

Work item #1013 (the 2026-10-29 pre-migration triage put it in "brief first"). Acceptance from `docs/conv-5-uncovered.md` (UPD-7t row).

## Goal

UPD-7 says soak plus attestations replace a central staged rollout: fast-channel boxes are the canary population, and no project-run service decides who updates when. Until #3452 (MIG-4-untrusted-change-c1, commit `0198427b`) that rule lived in `broker/maintain`'s Loop 3 (its old M6: a stable box proposes an ordinary release only after the soak and `MinPasses` passing attestations). #3452 deleted Loop 3 unwired, so on main nothing decides UPD-5's stable gate any more: `update.Verified` can count passes (`IndependentPasses`) and decide a security fix (`SecurityAutoStage`), but no function answers "may this ordinary release be proposed on a stable box yet?". The row's "test and marker" therefore needs the gate itself first.

This package adds that gate to `broker/update` as one pure decision, beside `SecurityAutoStage`, tests it, and marks UPD-7. It does not wire it (see Integration owner).

## Requirement IDs

UPD-7 (primary), UPD-5 (the stable soak row), UPD-4 (fast boxes take releases unsoaked; they produce the attestations), UPD-8 (attestations count only from the allow-list, fast channel, never a signing-role key; interim test box).

## The gate (contract; names are the builder's)

`func (v *Verified) StableReady(atts [][]byte, own ed25519.PublicKey, channel string, firstSeen, now time.Time, soakDays, minPasses int) (Wait, error)`

- `Wait` is a small typed result: ready, or not ready with a reason the wiring can turn into owner text (CH-12) and, where one exists, an `Until` time. Reasons: `soak` (with `Until`), `attestations` (with how many more independent passes are needed), `no attestor listed`, `pinned`.
The rules apply in this order: pinned, then security fix, then fast, then ordinary stable.

- **Pinned** (`"pinned"` or any value other than stable or fast): not ready, reason `pinned`. Fail closed on an unknown channel.
- **Security fix**, on either channel: the answer is `SecurityAutoStage(atts, own)`, with no soak (UPD-5 security row). Branch on the predicate `SecurityAutoStage` itself uses (`v.release.Security || v.coversFix`, `attest.go`), never on `v.Security()`: that is true only once `WithAttestations` has checked an attestation (`store.go`, "never the manifest flag alone"), so an unattested fix would fall through to the soak, and a release that only covers a fix (`coversFix`) would be missed. UPD-8 has no fast-box exception, so a security fix on a fast box also needs one independent attestation. One entry point, so the wiring cannot pick the wrong rule.
- **Fast box** (`channel == ChannelFast`), ordinary release: ready with no soak and no attestation (UPD-4, UPD-7: fast boxes are the ones that produce attestations).
- **Ordinary release on a stable box:** ready only when both hold (UPD-5 "whichever is later"):
  - `now >= firstSeen + soakDays×24h`, where `soakDays` below 7 is raised to 7 (UPD-5 "at least 7") and above `loops.MaxSoakDays` (60) is capped at 60. Define the bounds in `update` rather than import `loops`.
  - `v.IndependentPasses(atts, own) >= minPasses`, where `minPasses` below 1 is raised to 1.
- **Fail closed on every bad input** (security lens recurring kind: a guard fails open on a missing or out-of-range value): nil or unsealed `v` returns `ErrNotChecked`; a zero `firstSeen` or a zero `now` is not ready; `now` before `firstSeen` (clock moved back) is not ready with `Until = firstSeen + soak`; a negative `soakDays` or `minPasses` takes the floor, never zero.
- **Empty allow-list** (neither `v.allowed` nor `v.pinned` holds a key, the same test as `restsOnPolicy` in `store.go`; a box whose only entry is the interim test box is not empty): not ready, reason `no attestor listed`. This is the brief's reading of SPEC v1.0 and differs from the deleted M6, which let the soak alone apply when no attestor was listed (because the owner then approved every image release). v1.0 UPD-5 says soak **and** attestations, UPD-8 pins the project's test box as the interim entry so a correctly built image never has an empty list, and UPD-9 says ordinary releases never ask the owner, so the old fallback would let a release in with neither attestation nor approval. A reviewer who reads it otherwise raises it at the first review (OPERATING §4 "doubt about direction"), not as a late blocker.
- `now` must be the clock guard's `Earliest` (`broker/clock`, "a soak … uses Earliest"), so a clock moved forward cannot end the soak early. The gate takes `now` as a value; its doc comment says where it must come from.
- **Not in the gate:** UPD-5's "local requalification" before an ordinary stable release (the wiring row's, through the change pipeline's qualification), behavior-changing releases needing the owner (CHG-3, the change pipeline's), the quiet window and jitter (`broker/apply` A3), and the first-sighting record.

## Acceptance tests

**Acceptance tests:** new `broker/update/soak_test.go` (marker `// REQ: UPD-7, UPD-5, UPD-4, UPD-8`), plus one named case in `broker/update/hardening_test.go`.

- UPD-5: `soak_test.go::TestStableWaitsForSoakAndPasses` — table over (days elapsed 6d23h / 7d, passes 0 / 1): only (7d, 1) is ready; (7d, 0) returns reason `attestations`, (6d23h, 1) returns `soak` with the right `Until`. Catches an `||` for `&&` and an off-by-one at the boundary.
- UPD-5: `soak_test.go::TestSoakDaysAreFloored` — `soakDays` 0, -1 and 3 behave as 7; 61 behaves as 60. Catches a zero or negative soak (fails open).
- UPD-8: `soak_test.go::TestOnlyIndependentFastPassesCount` — a pass on the stable channel, a fail, a pass by the box's own key, a pass by a root-listed key, and a pass by an unlisted key each leave the release not ready; one listed fast pass makes it ready. With `minPasses` 2, two passes from one attestor count once.
- UPD-8: `soak_test.go::TestEmptyAllowListNeverReady` — no attestor listed, soak long over: not ready, reason `no attestor listed`.
- UPD-4, UPD-7, UPD-8: `soak_test.go::TestFastBoxTakesReleaseUnsoaked` — fast channel, `firstSeen == now`, no attestations: an ordinary release is ready; a security fix returns `ErrNeedsAttestation`. Catches fast checked before security.
- UPD-4: `soak_test.go::TestPinnedAndUnknownChannelNeverReady` — `"pinned"`, `""` and `"beta"` are not ready.
- UPD-5: `soak_test.go::TestSecurityFixFollowsSecurityAutoStage` — a security release on a stable box with `firstSeen == now` is ready with one listed fast pass and returns `ErrNeedsAttestation` (not reason `soak`) with none; the same holds for a newest release that only covers a fix (`coversFix`). Catches routing on `v.Security()`.
- UPD-5: `soak_test.go::TestClockBackAndZeroTimesFailClosed` — zero `firstSeen`, zero `now`, `now` before `firstSeen`, and a nil `*Verified` are each not ready (nil returns `ErrNotChecked`).
- UPD-7: `hardening_test.go::TestManifestOnlyImagesAndStrict` gains a case: a signed manifest that adds `"rollout_percent": 10` or `"cohort": "a"` is refused by the strict decoder, so no release metadata can carry a project-run rollout setting. Add `UPD-7` to that file's `REQ:` line. Check first whether the existing unknown-key case already covers it; if so, add the two keys to its table rather than a new test.
- Mutants (potency recurring kind): the PR body lists, for each of the eight `soak_test.go` tests, the one-line mutant of `StableReady` it kills.

## Scope

`broker/update/soak.go` (new), `broker/update/soak_test.go` (new), `broker/update/hardening_test.go`, `broker/update/ASSUMPTIONS.md` (one new `U` row: the gate, the empty-list reading above, and where `firstSeen` and `now` must come from), `briefs/UPD-7t.md`.

**Tier:** A. `broker/update` is in `TIER_A_BROKER` (`tools/risk_tier.py`), so the build runs on the strongest model and needs L3 plus the separate Security accept (OPERATING §3, §7), although the row's label says tier C. All paths are on the G2 list (`tools/g1_scope.py` passes).

**Guard files:** none (no new package; `update`'s imports do not change beyond `time`).

## Integration owner (the lifecycle rule, OPERATING §5)

The gate needs a caller: the release check that Loop 3 used to be (fetch from the mirrors, `Store.Check`, record the first sighting of each image keyed by its `/usr` root hash and signed file hashes so a fast release republished as stable is not soaked twice, call `StableReady`, then `ProposeRelease` and `apply.Schedule`; `broker/apply/ASSUMPTIONS.md` A1 calls it "the A1 wiring"). No BOARD row covers it on main 1a37568; MIG-4-adapters-e-wire (#3428) and -wire-b (#3677) build the update clerk but not the check. That wiring row owns the stage-by-outcome matrix (first boot, restart, fallback, channel change). The builder files it as one `class:release` work-item issue citing UPD-5 and UPD-7, failure path "no ordinary release ever reaches a stable box", and lists it on the PR's Findings line.

## Out of scope

The release check and first-sighting store (above). A signed publish date in the manifest to measure the soak from (the old M6's "if it changes" note); first sight by this box stays the measure. The publication switch that lets fast boxes publish attestations (PUB-1, D-088). Owner-facing wording for each `Wait` reason (the wiring's, with a UX screen).

## Dependencies

None on main: `Verified.IndependentPasses`, `SecurityAutoStage` and `Security` exist in `broker/update`. D-111: start only while no open PR touches `broker/update/`.

## Estimate

Small: one function of about 60 lines, one test file, one table case, one ASSUMPTIONS row. Under 80k tokens.
