# MIG-4-exit: retire the vault process, cut into one-session slices

Work item #2571. Tier A. Written 2026-10-28 against main at ed2f1af. Each slice below is its own work item and session: m1 #3680, m2 #3681, c1 #3682, c2 #3683, c3 #3684, p #3685, d1 #3686, d2 #3687. A builder reads **What main shows**, **Shared rules** and its own section. `briefs/MIG-4-mail.md` (#3679) runs first, since it also edits `cmd/agentos-egress`.

## What main shows

**The four packages live on in one process.** `broker/vault`, `egress`, `holder` and `checker` are imported, outside each other and tests, only by `cmd/agentos-egress` (the vault process, 70 files, 24k lines, running on the image as `agentos-egress.service`), `cmd/agentos-holder`, `cmd/agentos-checker` and `recovery`, whose own importers are `cmd/agentos-egress` and tests. `cmd/agentosd` dropped its imports in #2812. So the row's real work is not the imports: it is the **sockets** that other processes still call. Each one must have a new-core owner, or be retired, before the process can go.

| Vault-process function (file) | Its callers on main | New-core owner (SPEC v1.0) | Slice |
|---|---|---|---|
| model route and API keys, keyless proxy, holders, stored grants (`server.go` model.sock, `providers.go`, `storedgrants.go`, `held.go`, `view.go`, `proxyproc.go`) | `cmd/agentosd` via `modelroute.Forward`, `modelroute.Providers`, `State` | the model clerk (CLK-7): `agentos-clerk-model` holds each API key and serves `run.ServeModel`, which nothing hosts yet | m1, m2 |
| owner's private-data answer per provider (`privatechange.go`) | `localui/providers.go` | a route label in the model clerk (PLN-3 "routes allowed private data") | m1, p |
| routing rule (`routing.go`, routing.sock) | `cmd/agentosd` (`modelroute.Spare`) | retired: HLD-4 routing rules adopt only on measured gain, and none exists; the model route holds `MaxRetries` | m2 |
| provider worker routes and Codex login (`workerroute.go`, provider.sock, route.sock; `egress/codexlogin.go`; `egress/cmd/agentos-codex-forwarder`) | `cmd/agentosd` `providerRunner` | the model clerk's plan route (#2780 b1 to b3) | #2780 b3 removes the caller; d1 deletes |
| code-generator seed: enrolment, code checks, unlock lockout, notices (`enroll.go`, `custody.go`, `checkerwire.go`, verify.sock, `noticesock.go`) | `cmd/agentosd` (`modelroute.Verifier` for the owner channel and setup's `m.Enroll`; `noticepull.go`) | CH-4's "own checker process" (CLK-1 exceptions), seed only inside the store (STO-2); the kernel admits nothing on a code today | c1, c2, c3 |
| unlock, trusted PCs, boot PIN, setup vault (`server.go` unlock.sock, `trusted.go`, `setupopen.go`) | `localui/vault.go` | `agentos-unlock` (STO-2b) for the trusted host; unknown-host unlock is #3358; trust-again is #2999; the setup vault is gone (`agentos-enroll`) | p |
| Owner Card provision and reset, rotation (`cardvault.go`, `rotation.go`) | `localui/vault.go`, `localui/rotwire.go` | `agentos-enroll -take-factors`; REC-4 is MIG-4-recovery-r (#3409, #3410) | p |
| second line: texting and calling accounts (`smsaccount.go`, `sipaccount.go`, sms.sock, sign.sock) | `localui/secondline.go`, `modem/sipline`, `cmd/agentosd/secondline.go` | a second-line clerk (CLK-8), which no row builds | Decision 2 |
| mailbox (`mailaccount.go`) | none | the mail clerk | #3679 |
| owner pins: backup target, private hosted route, compute host (`netpins.go`) | none outside the process's own CLI | the kernel's backup targets (`kernel/backuptarget.go`); declared endpoints (HW-16, HW-17) | d1 |
| recall key (`/recall-key`) | none: `modelroute.RecallKey` has no caller | gone with `recall` (#3425) | d1 (the type goes with `modelroute`) |

**Other importers still to clear** (from the LANES.md importer command): `e2e/boxe2e/codexstub` and `e2e` (#3431 and #3432, MIG-4-adapters g and h); `firstboot/card_test.go` (#2571 comment 6445257843: this row ports it); `vault/planlogin_redact_test.go` (goes with `vault`); `smsapi/imports_test.go` names `broker/vault` only as a string.

**Already done:** the exit's TLS hybrid key exchange is pinned (#2852 merged; `clerk/signin_test.go`), so the fold-in on #2571 (comment 6372267924) is closed.

## Decisions this brief needs (asked on #2571 for Decisions)

1. **Keep `broker/checker` as CH-4's checker (recommended).** D-139 lists `checker` as old core, but SPEC v1.0 keeps "the CH-4 code-generator seed ... in its own checker process" (CLK-1, exceptions) and puts every code verifier "only inside the store" (STO-2). `checker` is that process already: 1.4k lines, three peer-uid sockets, one-time approvals per exact request, a spent-step state file. Recommended: keep it, drop its holder (redeem) side, have the unlock step hand it the seed from the store, and take `broker/checker` and `cmd/agentos-checker` off `tools/old_core.txt`. The alternative is to rebuild the same thing under `broker/clerk/`, which adds code and review for no behaviour change. If Mark declines, c2 builds `broker/clerk/codecheck` from the same tests, and d2 also deletes `checker`.
2. **The second line: delete with the vault process, rebuild as a CLK-8 clerk row (recommended).** The old accounts are a vault-held password and a signing socket for the modem bridge. CLK-8 wants a clerk that sends through the `send` verb with E.164 checks, one rate budget and logged transcripts, which no old code does, so a port is a rebuild either way. It is an optional dependency (DEP-3), and keeping it on the critical path holds the whole row and MIG-4-log (#2577) behind it. Recommended: p deletes the second-line pages, `modem/sipline`'s signer client and `cmd/agentosd/secondline.go`, d1 deletes the accounts, and a new release row "CLK-8 second-line clerk" is filed with the cases from docs/migration/cases.md §7. Owners lose texting and calling to third parties until that row lands. The alternative adds two slices (the clerk, then its callers) before d1.

## Shared rules (every slice)

- Load the `agentos-builder` skill; claim the slice's issue with `state:building`.
- Delete what the slice replaces in the same PR; keep no adapter that holds an old-core type alive (#2578 rules). An old-core test is deleted, not ported, when it only drives old wiring; a test whose requirement still holds in SPEC v1.0 is rebuilt on the kernel, a clerk or a local fake (#2784 comment 6344183001).
- Keeper boundary (D-154, #2571 comment 6377267771): TLS to an origin ends in the clerk, through its injected `netguard` dialer; what a guest or the planner sends a clerk is a typed frame, and where a clerk must read a body it parses only what its check needs and records the parser in `tools/trusted_base_parsers.txt`; a rewired main links nothing from the main side.
- `cmd/agentosd` edits run one at a time in the agentosd slot (D-111), and `image/` edits in the image queue (the dispatch file's `image/build.sh` order).
- Each PR names the docs/migration/cases.md §6a, §6c and §7 ("Vault and key custody", "Egress proxy and plan route", "Holders, keeper and checker", "Model routes, vault and egress") cases it passes or retires.
- Re-run the D-111 check at claim time: the checks below are against the open PRs at 2026-10-28 13:40Z.

## m1 (#3680): the model clerk holds API keys and serves model calls

`run.ServeModel` exists and is tested but nothing hosts it, and no `model.Provider` exists on main (`cmd/agentos-clerk-model` ASSUMPTIONS MIG-4-untrusted-exit-b2b-3). INFER-wire (#3653) also needs it hosted.
**Scope:** `broker/clerk/model/` (an API-key `Provider` over the clerk exit, `broker/clerk/exit.go` used through its API), `broker/clerk/run/model.go` and new owner calls in `broker/clerk/run/` (`apikeyset`, `apikeyremove`, `apikeystate`, and the route's private label), `broker/cmd/agentos-clerk-model/` (`-model-sock`, `-planner-uid`, `-meter-sock`; the key sealed in its own slot as the plan login is), each built-in provider's inference endpoints as declaration data (CLK-3, CLK-14: no provider name in trusted-base code), their ASSUMPTIONS files, `tools/trusted_base_parsers.txt` if a body parser is added.
**Do:** serve `ServeModel` to the planner's uid and meter through the kernel's meter socket (`run.Meter`). The frame (D-154 rule 2) names the declared operation and carries its JSON body, checked against the declaration's body schema (CLK-3's single-endpoint rule); the clerk reads only what metering and its caps need. The key never leaves the process (CLK-1, CLK-4). Values the b2b-3 row lacked (the plan a call is charged to, the route's price and pool, context window and output limit) come from the kernel plan and the declaration, never from the caller.
**Needs:** nothing unmerged. D-111: no open PR touches `clerk/model`, `clerk/run` or `cmd/agentos-clerk-model`. No agentosd edit; the unit flags wait for b2b-unit (#2780).
**Requirement IDs:** CLK-7, CLK-1, CLK-3, CLK-4, PLN-3, LOG-7.
**Guard files:** `tools/trusted_base_parsers.txt` if touched (Security accept).
**Acceptance tests:** `broker/clerk/run/model_test.go::TestModelCallWithAnAPIKeyReachesOnlyTheDeclaredEndpoint` (a call is sent to the declared host and path with the sealed key injected; any other host, path or operation is refused and logged), `::TestModelReplyCarriesNoKey` (the key and its derivatives are stripped from replies and errors; positive control with a provider that echoes it), `::TestPrivateCallRefusedOnARouteNotAllowedPrivate` (PLN-3), `broker/cmd/agentos-clerk-model/main_test.go::TestServesModelCallsToThePlannerOnly` (another uid's call sends nothing).
**Size:** M.

## m2 (#3681): agentosd's model route and setup's AI step onto the model clerk

**Scope (agentosd slot):** `broker/cmd/agentosd/main.go` (drop `-egress`, `-routing`, and `-worker-routes` if #2780 b3 left it; wire the model clerk's sockets; `-owner-verify`, `-notice-socket` and the `secondLine` wiring stay for c3), the guest model route (`gcfg.Model`) and setup's provider step (`setup.go`, `capoff.go` where they call `modelroute`), agentosd's calls into `broker/modelroute/` (agentosd stops importing it; the package itself stays, since `cmd/agentos-egress` compiles against its wire types until d1 deletes both), their tests, `broker/cmd/agentosd/ASSUMPTIONS.md`.
**Do:** agentosd turns the guest's HTTP into the typed frame m1 serves (the parsing stays on the untrusted side) and calls the clerk with the run's kernel plan; setup's API-key step calls m1's owner calls. Folds MIG-4-adapters-d (#3427) if that has not merged: it edits the same `modelroute` files and `main.go` line.
**Needs:** m1; #2780 b3 (it holds the slot and removes `providerRunner`); b2b-unit (#2780) so the clerk runs on the image; #3427 or its fold.
**Requirement IDs:** PLN-5 (model access only through the model clerk), CLK-7, ONB-3 (setup's AI step).
**Guard files:** none expected; `image.yml` runs on agentosd changes.
**Acceptance tests:** `broker/cmd/agentosd/modelroute_test.go::TestGuestModelCallGoesThroughTheModelClerk` (a guest's call reaches a fake provider only through the clerk's socket and is metered on the kernel plan; catches a path that still dials model.sock), `::TestSetupAPIKeyStepStoresInTheClerk`; agentosd's model route and setup step call no `modelroute` function, and `go build ./cmd/agentos-egress` still passes (catches a deleted wire type the vault process names); `grep -c agentos-egress broker/cmd/agentosd/main.go` prints 0 for the model flags; `image.yml` green.
**Size:** M.

## c1 (#3682): the kernel admits a code approval

The kernel has no notion of an approval code: `kernel`, `kernel/key` and `owner/kernelsock` never mention CH-4. Today the owner channel's codes are checked by the vault process and redeemed by holders, both old core.
**Scope:** `broker/kernel/` (one new approval kind: a checker-signed approval of exact steps, verified against the checker's public key from the store's pins, under the same key-check library, KRN-2), `broker/kernel/key/` if the approval is a key form, `broker/owner/kernelsock/` (one owner call to submit it), `broker/kernel/ASSUMPTIONS.md`, `broker/core/core.txt` if a wiring line is needed.
**Needs:** Decision 1. D-111: #3635 holds only `kernel/proc/content_test.go` and #3642 `kernel/proc/clerkkeys.go`; neither is in scope. Kernel files are trusted core: expect a D-208-style core-growth note.
**Requirement IDs:** CH-4, CH-18 (the grid's single-use cells, if the grid answer is carried the same way), KRN-2, KEY-4.
**Guard files:** `broker/core/core.txt` if touched (Security accept).
**Acceptance tests:** `broker/kernel/codeapproval_test.go::TestCodeApprovalAdmitsOnlyItsExactSteps` (an approval admits each named step once; another step, a replay, or an approval signed by another key admits nothing), `::TestCodeApprovalNeverCoversASecretStep` (VRB-1 steps still need their own approval).
**Size:** M.

## c2 (#3683): the checker runs on the new core

**Scope:** `broker/checker/` (drop the redeem socket and holder approvals; sign approvals for c1), `broker/cmd/agentos-checker/`, `broker/cmd/agentos-unlock/` (hand the checker its seed from the store at each start, as it hands clerk keys), `broker/clerk/handoff/` (the seed's entry name), `broker/cmd/agentos-enroll/` (setup's code enrolment writes the seed into the store and hands the one display copy to the page through `/run/agentos-setup`, as it does the card factors), `tools/old_core.txt` (Decision 1), their ASSUMPTIONS files.
**Needs:** c1; Decision 1. D-111: no open PR touches these files (#3642 is `kernel/proc/clerkkeys.go`, which hands driver keys; read it, do not edit it). The unit change goes in the image queue as its own small PR if `image/` is held at claim.
**Requirement IDs:** CH-4, CLK-1 (seed in its own process), STO-2 (no verifier readable before unlock), §12.1 step 5 ("Add approval codes").
**Open point (settle on the issue before building):** setup enrols codes before the Owner Card, and `agentos-enroll -take-factors` makes the store from the card's factors, so the seed may have to wait in the root-only setup directory until the store exists. Name the order the box follows and test it.
**Guard files:** `tools/old_core.txt` (Security accept).
**Acceptance tests:** `broker/checker/checker_test.go::TestSeedComesOnlyFromTheUnlockStep` (a checker started without the hand-off verifies nothing), `::TestVerifiedCodeSignsOnlyTheNamedSteps`, `broker/cmd/agentos-enroll/main_test.go::TestCodeSeedLandsInTheStoreAndIsShownOnce`; the existing lockout and spent-step tests keep passing.
**Size:** M.

## c3 (#3684): the owner channel and setup check codes with the checker

**Scope (agentosd slot):** `broker/cmd/agentosd/main.go` (`-owner-verify` and `-notice-socket` replaced by the checker's verify socket; `m.Enroll` onto c2's enrolment), `broker/cmd/agentosd/noticepull.go` (delete; the checker's lockout reaches STATUS through the verifier's errors), the `owner.Verifier` adapter in `main.go`, `broker/owner/notice/noticesock/` (delete; agentosd is its only importer) with its entries in `broker/daemon/inference_test.go` and `broker/daemon/arc2_test.go`, and, under Decision 2, `broker/cmd/agentosd/secondline.go` with its `secondLine` wiring in `main.go` (it is built from the same verifier), their tests. `broker/modelroute/verify.go` stays: the vault process compiles against its types until d1. After c3, `go list -deps ./cmd/agentosd` names no `modelroute`.
**Needs:** c2 and its unit on the image; m2 (both edit `main.go`; m2 goes first); Decision 2 (if it is declined, the second-line clerk's caller slice replaces `secondline.go` before c3); the agentosd slot.
**Requirement IDs:** CH-4, CH-14 (a session unlocked by a code), CH-17 (keypad codes reach the same check).
**Guard files:** `tools/trusted_base_parsers.txt` (the `noticesock` line) and `broker/daemon/arc2_test.go` (Security accept).
**Acceptance tests:** `broker/cmd/agentosd/verify_test.go::TestOwnerCodeApprovesThroughTheChecker` (a texted code approves exactly the pending batch through the kernel; catches a path that still calls verify.sock), `::TestCheckerDownRefusesHighTierCodes`; `go build ./cmd/agentos-egress` still passes.
**Size:** M.

## p (#3685): the local page off the unlock socket

**Scope:** `broker/localui/vault.go`, `providers.go` (onto m1's owner calls), `secondline.go` (delete under Decision 2), the pages and routes in `pages.go` and `server.go` that only these serve, `broker/localui/rotwire.go` and the card provision and reset calls in `vault.go`, unless #3409 and #3410 already removed them, `broker/cmd/agentos-localui/main.go` flags (`-vault-sock`), `broker/modem/sipline/signer.go` (Decision 2; agentosd's second-line code is c3's), tests, `broker/localui/ASSUMPTIONS.md`.
**Do:** the trusted host unlocks at boot (`agentos-unlock`) and the setup vault is gone, so the unlock, trust, boot-PIN and setup-host pages are deleted, not ported; the unknown-host unlock page is #3358's, which this slice does not wait for, since the old page unlocks only the old vault.
**Needs:** #3679 (both edit `localui/imports_test.go`); #3624 (holds `localui/server.go`, `setup.go`, `rotwire.go`, `firstboot.go` and `cmd/agentos-localui/main.go`); #3409 and #3410 for the rotation pages; m1 for the providers page; Decision 2.
**Requirement IDs:** STO-2, PLN-3, REC-4 (the old rotation route is gone and the new one is the page's).
**Guard files:** none expected.
**Acceptance tests:** `broker/localui/imports_test.go::TestPageDialsNoVaultProcess` (no route of the page reaches `/run/agentos-egress`), `broker/localui/providers_test.go::TestPrivateAnswerChangesTheClerkRoute` (allowing needs a code, as now).
**Size:** M.

## d1 (#3686): delete the vault process and its units

**Scope:** delete `broker/cmd/agentos-egress/`, `broker/cmd/agentos-holder/`, `broker/egress/cmd/agentos-codex-forwarder/`; `image/`: `agentos-egress.service`, `agentos-egress-setup.path` and `.service`, `usr/lib/agentos/egress-setup`, the egress lines in `50-agentos.preset`, `60-agentos-tpm.rules`, `agentos-setup.conf` sysusers, `mkosi.finalize`, `build.sh`'s command list, `image/e2e/agentos-egress.conf` and its `ci_boot.sh` drop-in, `agentosd.service`'s `After`/`Wants`; `.github/workflows/image.yml` (the egress paths and the e2e egress build); `broker/core/core.txt` (`wiring cmd/agentos-egress`, `-holder`); `broker/durable/stores.txt` (the `cmd/agentos-egress` line); delete `broker/modelroute/` (after m2 and c3 its only importer is the vault process; `tools/ci_split.py` and `tools/trusted_base_parsers.txt` entries for it); `tools/ci_split.py`, `tools/trusted_base_parsers.txt`, `tools/g1_scope_g2.txt` entries for the deleted mains; #1393 closed as moot.
**Needs:** m2, c3, p, #3679, #2780 b3, #3431 (MIG-4-adapters-g: the stub off `egress`); the image queue (#3640, #3642 hold `build.sh`, `ci_boot.sh`, `mkosi.finalize`, `image.yml` now).
**Requirement IDs:** CLK-1 (no credential outside its clerk), ONB-3 (setup still reaches a frontier source in the image run).
**Guard files:** `core.txt`, `image.yml`, the `tools/` lists (Security accept).
**Acceptance tests:** the image job's e2e boot passes with no `agentos-egress` unit (`console-e2e.log` verdict line); `tests/` image unit checks find no unit naming `/run/agentos-egress`; `grep -rn agentos-egress image broker --include=*.go --include=*.service` finds only history comments; `go list ./... | grep -c broker/modelroute` prints 0.
**Size:** M.

## d2 (#3687): delete the four packages

**Scope:** delete `broker/vault/`, `broker/egress/`, `broker/holder/` (and `broker/checker/` only if Decision 1 is declined); `broker/recovery/` files whose only importers were the vault process (ask on #2865 before deleting any that MIG-4-recovery still names); `broker/firstboot/card_test.go`'s vault half, ported onto `agentos-enroll`'s factors (comment 6445257843); `tools/old_core.txt`, `tools/assumptions_legacy_ids.txt`, `tools/trusted_base_parsers.txt`, `tools/g1_scope_g2.txt`, `tools/risk_tier.py`, `tools/ci_split.py` entries; `docs/LANES.md` importer rows through the coordinator (it is a process doc).
**Needs:** d1; #3432 (MIG-4-adapters-h: `e2e` off `egress` and `vault`); #3624 (holds `firstboot/card_test.go`, `recovery/rotation_display_test.go`).
**Requirement IDs:** CLK-1; D-139 (the old core only shrinks).
**Guard files:** the `tools/` lists (Security accept).
**Acceptance tests:** `cd broker && go list ./... | grep -E 'broker/(vault|egress|holder)$'` prints nothing; `python3 tools/trace.py --ratchet` passes; `go vet ./...` and `go test ./recovery/... ./firstboot/...` pass. Then #2571 closes, and #3425 (delete `recall`) is told `vault` no longer imports it.
**Size:** M (deletion, about 21k lines with tests).

## Order

1. Now, in parallel: #3679; m1; c1 (after Decision 1).
2. c2 after c1. m2 after m1, #2780 b3 and b2b-unit. c3 after c2. These two are agentosd-slot rows: m2 joins the slot queue after #2780 b3, c3 after m2.
3. p after #3679, #3624, #3409, #3410 and m1.
4. d1 after m2, c3, p, #3679 and #3431, in the image queue.
5. d2 after d1 and #3432. Then #2577 (MIG-4-log) and #3425 lose this row as a blocker.

**Acceptance tests:** each slice names its own above; the row is done when d2's check passes.
