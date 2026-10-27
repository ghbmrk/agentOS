# MIG-4-adapters: the remaining trusted-side ports, cut into one-session rows

Work item: #2579 (sub A row; ours under Mark's 2026-10-25 note on #2578, comment 6396935897). Tier A. This file is the brief for every slice below; each slice is its own work item and its own session. A builder reads **Shared rules** and its own section, nothing else here.

## What is left (main at 90dd141)

Generated from `broker/` with the LANES.md importer command, reduced to directories this row or its siblings own. "Test" means only `_test.go` files import it.

| Directory | Old-core imports | Who takes it |
|---|---|---|
| `photo/keep` | `journal`, `recall`, `durable` | **a** (no importer: delete) |
| `recalltool` | `journal`, `recall`, `grants` (test) | **a** (only `recall/backs_append_test.go` imports it: delete) |
| `route` | `egress`, `vault` (test) | **a** |
| `recall`, `events` | `durable`; `recall` | **b** (delete once `mail` and `vault` stop importing them) |
| `/var/lib/agentos/recall` at rest | read by `cmd/agentosd/recallheld.go` | **c** (carried release finding, #2579 comments 6365347287, 6399643797) |
| `modelroute` | `journal` (`journal.go`: `Journal`, `EgressGate`), `egress` | **d** |
| `apply` | `journal` | **e** |
| `follow` | `grants`, `journal`, `durable` | **f1**, **f2** |
| `e2e/boxe2e`, `e2e/boxe2e/codexstub` | `egress`, `vault` (test), `provagent` | **g** |
| `e2e`, `provagent` | `egress`, `journal`, `vault` (`provagent` only in tests) | **h** |
| `cmd/agentos-a8scan` | `vault` | **i** |
| `clock`, `update`, `apnet`, `vm`, `vm/gvisor`, `cmd/agentos-ap` | `durable` only (`WriteFile`, `Rename`, `SyncDir`, `PublishDir`, `StageDir`, `SweepTemp`, `ErrDirSync`) | **no row if the durable decision below holds** |
| `reversible` | `journal` | no row: only `grants` imports it, so #2576 (MIG-4-keys) deletes it with `grants` |
| `firstboot` | `vault` (`card_test.go` only) | no row: #2571 deletes `vault` and ports its importers in the same PR (LANES.md "Deleting waits on importers") |
| `smsapi` | none (the fence test names `broker/vault` as a string) | no row |
| `infer`, `photo`, `routerule`, `maintain`, `test`, `cmd/agentos-photo`, `cmd/agentos-infer` | none | no row: they import no old core, so nothing of theirs writes outside the kernel (`pubid` and `evals/review/` no longer exist) |

#2579 closes when a to i have merged (or been re-homed) and the check under **Done for #2579** passes.

## Decisions this brief rests on

1. **`durable` stays as a kept stdlib leaf (recommended; needs Mark, since D-139 lists `durable` as old core).** `durable` is 6 exported helpers over the standard library (D6, `TestLeaf`) that make a write survive a power cut (fsync file, rename, fsync dir). Nothing in it is the old journal: the journal-shaped part is only the OP-11 vocabulary in `durable/stores.txt` and its lifecycle guard. Six kept host directories use only the helpers, for host files the kernel log does not hold (the clock floor, TUF metadata, AP state, VM snapshots). Deleting `durable` means re-implementing the same five calls in each of them, or moving them under a new name, which churns about 30 importers across open PRs for no behaviour change. If kept: `durable` leaves `tools/old_core.txt`, #2577 (MIG-4-log) deletes only `journal` and rewrites `stores.txt`'s kinds to SPEC v1.0 (`log`, `content`, `config`, `external-session`), and these six directories need no row. If Mark declines: one row per group (`clock`+`apnet`+`cmd/agentos-ap`, `update`, `vm`+`vm/gvisor`) moves them onto `broker/kernel/privfile.WriteAtomic` plus a new `SyncDir` there; this brief is then amended before those rows are filed.
2. **The key for an update activation (e only; needs Mark).** UPD-6 makes every update "a logged plan step with a rollback point", and KRN-4 says only a standing key covers an irreversible step without a per-step approval. UPD-3 activates a release on first boot, before the owner holds any key. Recommended: the image pins a standing key for the update clerk's `activate` verb only, caveated to a release that passed UPD-8's TUF threshold and is newer than the installed one, so its authority is the project's signing threshold (UPD-2), not the owner's; the pinned channel (UPD-4) pauses it. Alternative: activation is not a plan step at all but a kernel-logged host event (`update.activated`) with no key, which reads UPD-6's "plan step" loosely. e does not start until this is settled on its issue.
3. **`follow` is kept, not deleted.** Its requirement OSS-10 is retired into PUB-1, but docs/migration/cases.md keeps its case (#957, look-alike names, CH-10), so it is ported: the owner's switch of update root is a tier-4 step the owner approves at its tier (KRN-4, CH-10).
4. **Old-core tests are deleted, not ported, when they only drive old-core wiring** (Mark, Decisions 7, 2026-10-22, recorded on #2784 comment 6344183001). A test whose requirement still holds in SPEC v1.0 (A5, A14, CRED-5, the route failover cases) is rebuilt on the kernel, the clerk exit or a local fake.

## Shared rules (every slice)

- Load the `agentos-builder` skill first. Claim the slice's issue with `state:building`.
- Delete what the slice replaces in the same PR; add no adapter that keeps an old-core type alive (#2578 rules).
- `go vet ./...` and the touched packages' tests pass in `broker/`; `python3 tools/trace.py --ratchet origin/main` passes.
- `durable/stores.txt` follows every persisting package you delete (`TestStaleManifestEntryFails` catches a stale line).
- A deleted directory's lines leave `tools/g1_scope_g2.txt` and `tools/assumptions_legacy_ids.txt`. Both are gate files (`premerge.py --needs-mark` prints `mark`), so such a PR needs the separate Security accept (OPERATING §7).
- `cmd/agentosd` edits run in the serial agentosd slot (D-111); the coordinator gives the slot.
- A finding you cannot place in your slice is asked on its issue, not guessed.

## a: delete the dead read side and port route's tests

**Scope:** `broker/photo/keep/` (delete), `broker/recalltool/` (delete), `broker/recall/backs_append_test.go` (drop its `recalltool` use; if the test only proves recalltool's behaviour, delete it), `broker/route/route_test.go`, `broker/photo/ASSUMPTIONS.md` (rows naming `keep`), `broker/durable/stores.txt`, `tools/g1_scope_g2.txt`, `tools/assumptions_legacy_ids.txt`.
**Needs:** none. Conflict guard: `tools/g1_scope_g2.txt` is held while an open PR touches it.
**Requirement IDs:** CAP-3 (no store left without a lifecycle), A13 (route failover).
**Route tests:** the rig's upstream is `egress.Proxy` over a `vault`. Replace it with an `httptest` upstream that injects the provider key itself, so every route test keeps its assertion. `TestDeniedHeaderMatchesEgress` and `TestProxyLimitsStayPerMachine` test egress, not route: delete them, and say so in the PR body. Keep `TestRouterHoldsNoCredentialAndDialsNothing`.
**Guard files:** `tools/g1_scope_g2.txt`, `tools/assumptions_legacy_ids.txt` (Security accept).
**Acceptance tests:** `broker/route/route_test.go::TestServesFromFirstRouteThroughEgress` (renamed `...ThroughUpstream`) and the failover tests pass with no old-core import in `route` (catches a port that dropped the upstream's key check); `broker/durable/lifecycle_guard_test.go::TestStaleManifestEntryFails` passes (catches a stale `photo/keep` line); `go list -deps ./... | grep -c 'broker/recalltool'` prints 0.
**Size:** S (mostly deletion; about 9k lines removed).

## b: delete recall and events

**Scope:** `broker/recall/` and `broker/events/` (delete), `broker/durable/stores.txt`, `tools/g1_scope_g2.txt`, `tools/assumptions_legacy_ids.txt`, `tools/risk_tier.py` and `tools/ci_split.py` entries naming them, `tools/old_core.txt` (drop `recall` and `recalltool`).
**Needs:** a; #2574 (MIG-4-mail deletes `mail`, which imports both) and #2571 (MIG-4-exit deletes `vault`, whose test imports `recall`). If either is still open when the rest is ready, ask on its issue whether its builder drops the import first.
**Requirement IDs:** CAP-3.
**Guard files:** the four `tools/` files above (Security accept).
**Acceptance tests:** none new: `go build ./...` and `go vet ./...` in `broker/` with both directories gone, and `tools/trace.py --ratchet` passing, are the proof (a missed importer fails the build).
**Size:** S.

## c: the recall directory at rest ends safely

The carried release finding (#2579 comments 6365347287 and 6399643797; agentosd ASSUMPTIONS FD-3, VLC-1, VLC-5, VLC-6). agentosd reads `/var/lib/agentos/recall` at each start to find agent lineages still holding a record the owner deleted, rolls them back and records each in `<machines>/recall-settled.json`.

**Scope:** `broker/cmd/agentosd/recallheld.go` (+test), the STATUS line for the unknown case (where `recallheld.go`'s result is rendered), `broker/cmd/agentosd/ASSUMPTIONS.md` (FD-3, VLC rows).
**Needs:** the agentosd slot.
**Requirement IDs:** CAP-3, LOG-4.
**Do:** after a start whose reader result is known, every held lineage is in `recall-settled.json` and every entry has `told: true`, remove the directory (contents first, then the directory, then sync the parent) and record that it is gone so later starts skip the reader. Keep it in every other case: any file unreadable (result unknown), a lineage not yet settled, an untold notice. Give STATUS's unknown line ("The old memory directory could not be read: agents cannot fork or merge") one step the owner can take: retire the held lineages, which rolls each back as a settled lineage, after which the next start removes the directory.
**Lifecycle matrix:**

| Stage | Outcome | Test |
|---|---|---|
| Upgrade, all lineages settled and told | directory removed, parent synced | `TestRecallDirRemovedWhenAllSettledAndTold` |
| A lineage's rollback failed | directory kept, lineage contained | `TestRecallDirKeptWhileALineageIsHeld` |
| A file unreadable (unknown) | directory kept, every lineage contained, STATUS shows the step | `TestRecallDirKeptWhenUnknown` |
| An entry with `told: false` | directory kept; notice retried at next start | `TestRecallDirKeptUntilTold` |
| Crash mid-removal | next start finishes the removal or keeps the rest; no lineage freed | `TestRecallDirRemovalResumesAfterCrash` |
| Owner retires held lineages | rolled back and settled; next start removes the directory | `TestRetireHeldLineagesThenRemove` |

**Guard files:** none.
**Acceptance tests:** the six in the matrix, in `broker/cmd/agentosd/recallheld_test.go`, each failing on main's code (main never removes the directory and has no retire step).
**Size:** M.

## d: modelroute stops writing denials to the journal

`modelroute.Journal` turns each denial the model router reports into a `journal.EgressNote`, rate-gated by `journal.EgressGate`; agentosd wires it at `cmd/agentosd/main.go` (`Denied: modelroute.Journal(eng, log.Printf)`). SPEC v1.0 has no denial-audit requirement, and denials are not kernel-admitted steps.
**Scope:** `broker/modelroute/journal.go` and `journal_test.go` (delete), `broker/modelroute/` files using `egress.ErrNoLogin`, `egress.DeniedHeader`, `egress.CodexAuthFile` (take the constant into `modelroute`, keeping the wire value), `broker/cmd/agentosd/main.go` (the `Denied` hook becomes a coalesced log line: same coalescing rule, written to the service log), `broker/modelroute/ASSUMPTIONS.md`.
**Needs:** #3402 (holds `modelroute`); the agentosd slot. If #2790 (MIG-4-untrusted-agentosd-log) starts first, it takes this slice into its PR and this issue closes as folded.
**Requirement IDs:** none changes behaviour visible to the owner; record the dropped journal note as an ASSUMPTIONS row (the reviewer may ask for a kernel entry type instead, which is a LOG-5 schema change).
**Guard files:** none.
**Acceptance tests:** `broker/modelroute/denied_test.go::TestDeniedCoalescedPerMachine` (a guest looping on a refused request logs once per window; catches a hook that floods the service log); `broker/modelroute`: `go list -deps` shows no `journal` or `egress`.
**Size:** S.

## e: apply activates a release through the kernel

`apply` hands a verified release to the A/B activator through a journaled intent (`journal.ActionReleaseActivate`), and commits or drops it after the restart's health check. It is not wired in production yet (#888 wires first-boot; nothing calls `apply.New` outside tests).
**Scope:** `broker/apply/` (and `apply/activatortest/`), `broker/firstboot/firstboot.go` (+test) only if `Scheduler`'s signature changes, `broker/daemon/arc2_test.go` allowlist (apply may import `broker/kernel` and `broker/clerk`), `broker/apply/ASSUMPTIONS.md`.
**Needs:** decision 2 above, recorded on this slice's issue.
**Requirement IDs:** UPD-1, UPD-1a, UPD-3, UPD-6, KRN-4, KRN-8.
**Do:** `apply` becomes the update clerk in place: `Facts`, `Do` and `Probe` over `kernel.Request` for one verb, `activate` (step args: the release's verity root hash and boot entry, UPD-1a). The free-box check (UPD-6) is a precondition the clerk re-checks before it acts (CLK-2). The rollback point is the step's logged result. After the restart, `Probe` reads the boot counter and answers committed or fell back, so an unknown result is settled by probe, never by a second activation (KRN-8). Delete the journal vocabulary (`Executor`, `Origin`, `Action`) and every `journal` use.
**Lifecycle matrix:** stage (staged, box busy, activated, restart healthy, restart fell back, crash between activate and answer) by outcome (step result logged, activator called at most once) in `broker/apply/clerk_test.go`, driven by `broker/kernel/sim`.
**Guard files:** `broker/daemon/arc2_test.go` (allowlist), `tools/risk_tier.py` only if `apply`'s class changes (it should not).
**Acceptance tests:** `broker/apply/clerk_test.go::TestActivateOnceAcrossCrash` (catches a second activation after an unknown result), `::TestBusyBoxHoldsActivation` (catches activation during a call, UPD-6), `::TestFallbackAnswersFellBack` (UPD-1), `::TestStepWithoutKeyRefused` (KRN-4); no `journal` in `go list -deps ./apply/...`.
**Size:** M to L (4.4k lines, about half tests). If the read shows L, split the commit/fallback half off before building.

## f1: follow becomes a clerk

`follow` switches the update root of trust to one the owner approved on the local page (by digest of the bytes shown), with an alert at once. Today the approval is a tier-4 `grants.FollowIntent` executed through the journal.
**Scope:** `broker/follow/` only, `broker/daemon/arc2_test.go` allowlist, `broker/follow/ASSUMPTIONS.md` (if absent, create).
**Needs:** none.
**Requirement IDs:** UPD-2, UPD-8, CH-10, KRN-4; the #957 case in docs/migration/cases.md (look-alike names refused).
**Do:** `follow` implements `Facts`, `Do` and `Probe` over `kernel.Request` for one verb, `follow`, whose args are the root digest and the owner's name for it. It keeps `Describe`, the digest check against the bytes the page showed, the clock guard's `Latest` for expiry (WF2), the project-root rule for an empty name (WF1') and the look-alike refusal. Delete `grants.FollowIntent` handling and every `journal` and `grants` use. Wiring is f2's.
**Guard files:** `broker/daemon/arc2_test.go`.
**Acceptance tests:** `broker/follow/clerk_test.go::TestFollowsOnlyTheShownDigest` (catches bytes swapped after the owner saw them), `::TestLookAlikeProjectNameRefused` (#957), `::TestExpiredRootRefusedByGuardClock` (WF2), `::TestFollowOnceAcrossCrash` (KRN-8); no `grants` or `journal` in `go list -deps ./follow/...`.
**Size:** M.

## f2: the owner's follow approval reaches the kernel

**Scope:** `broker/localsrv/localsrv.go` (+test: the follow approval submits a plan whose one step the owner approves at tier 4, instead of a `grants.FollowIntent`), `broker/cmd/agentosd/follow.go` (+test: hosts the follow clerk instead of `cfg.BrokerExecutors[grants.FollowExecutor]`), `broker/daemon/daemon.go`, `unconfirmed.go`, `follow_test.go`, `settle_guard_test.go` (drop the follow executor route).
**Needs:** f1; the agentosd slot; no open PR on `localsrv` or `daemon` (D-111); the kernel's start-up slice in agentosd (#2682's, merged as #3072).
**Requirement IDs:** CH-10, KRN-4, OWN-4 (the alert at once).
**Guard files:** none expected; name any found.
**Acceptance tests:** `broker/cmd/agentosd/follow_test.go::TestOwnerApprovedFollowRunsOnce` (page approval, kernel admits, clerk switches, owner alerted), `::TestUnapprovedFollowRefused` (catches a follow without the owner's tier-4 approval); `grep -c FollowIntent` over `broker/` prints 0 outside `grants`.
**Size:** M.

## g: the box e2e off egress

`e2e/boxe2e` is the in-image end-to-end run (`image/ci_boot.sh`, `E2E`); `codexstub` stands in for Codex behind `egress.PlanLogins`, `egress.NewWorkerRoute` and `egress.Codex` constants.
**Scope:** `broker/e2e/boxe2e/` and `broker/e2e/boxe2e/codexstub/`, the e2e unit and drop-ins under `image/` that name egress sockets (only those), `broker/e2e/boxe2e/ASSUMPTIONS.md` if present.
**Needs:** #2571 (the clerk exit replaces egress) unless the image already routes the guest's model calls through `broker/clerk/plan` and the model clerk (check `cmd/agentosd`'s wiring on main first; if it does, this slice can start before #2571). Conflict guard: image files held by an open PR wait.
**Requirement IDs:** PLN-5, CLK-7 (the image's end-to-end run, #1688).
**Do:** the stub serves the plan endpoint the model clerk dials (`broker/clerk/plan`), and the guest task reaches it only through the model clerk; drop `provagent` and every `egress` and `vault` import.
**Guard files:** image files are tier A; name each.
**Acceptance tests:** the image job's e2e boot (`console-e2e.log` verdict line) passes; `broker/e2e/boxe2e/codexstub/stub_test.go` passes with no old-core import (catches a stub that still speaks the old login store).
**Size:** M.

## h: A5 and A14 rebuilt on the kernel; provagent deleted

`broker/e2e` composes broker packages the way the box does: A5 canary and A14 egress proof (`a14_test.go`), OP-8 routed settlement (`routed_test.go`), Codex containment (`codex_contain_test.go`), and a journal SIM-check (`journal_check_test.go`).
**Scope:** `broker/e2e/` (all files), `broker/provagent/` (delete), `tools/g1_scope_g2.txt`, `tools/assumptions_legacy_ids.txt`, `tools/risk_tier.py` and `tools/ci_split.py` entries for `provagent`, `broker/durable/stores.txt` if listed.
**Needs:** g; #2780 (agentosd off `provagent`); #2571 (the clerk exit).
**Requirement IDs:** A5, A14 (G2 gates), CRED-5.
**Do:** delete `journal_check_test.go` and `routed_test.go` (they judge the journal and old meter settlement; spend is the model clerk's now). Rebuild `a14_test.go` and `codex_contain_test.go` on `broker/kernel/sim`, the clerk exit and the model clerk: a guest with every verb cannot surface a canary held in the sealed store, and a `private` planner cannot reach off its allowlist directly, by DNS or via a clerk. Keep `a9_test.go`, `dep2_test.go`, `owner_test.go`, `openclaw*_test.go` working with the guest plane's kernel seam (#3090).
**Guard files:** the `tools/` files above (Security accept).
**Acceptance tests:** `broker/e2e/a14_test.go::TestA14CanaryThroughTheGuestSocket` rebuilt (catches a canary in any reply, log line or clerk request), `::TestA14PrivatePlannerOffAllowlistRefused` (new; direct, DNS and via a clerk); `broker/e2e/codex_contain_test.go::TestIntegrationCodexContainment` with no old-core import.
**Size:** L. If the read shows it over one session, split A14 off into its own slice before building.

## i: a8scan scans for the sealed store's secrets

`cmd/agentos-a8scan` is A8's at-rest check on real hardware: it opens the vault with the recovery key and scans the drive for the vault data key and every secret, in every encoding and alignment.
**Scope:** `broker/cmd/agentos-a8scan/` (+test), `broker/recovery/A8-SESSION.md` (the command line only).
**Needs:** none (the sealed store, `broker/clerk/seal`, is on main).
**Requirement IDs:** A8, STO-2.
**Do:** open the sealed store with the recovery key as the unlock path does, and plant every needle from it: the store's data key, the log key and each sealed secret. Keep the self-check (stop unless every planted needle is found in the scratch blob) and the no-values output.
**Guard files:** none.
**Acceptance tests:** `broker/cmd/agentos-a8scan/main_test.go::TestFindsSealedStoreKeyInEveryEncoding` (catches a scan that only looks for the old vault key), `::TestSelfCheckStopsOnMissedNeedle`; no `vault` in `go list -deps ./cmd/agentos-a8scan`.
**Size:** S.

## Done for #2579

From `broker/`, the LANES.md importer command lists no importer of `recall`, `recalltool`, `provagent`, `photo/keep` or `events`, and none of `apply`, `follow`, `modelroute`, `route`, `e2e`, `cmd/agentos-a8scan` imports an old-core directory. `durable` importers are then #2577's (or the declined-decision rows').
