# P2-2w c4f s1: the claim decision and the card-confirm witness move out of the Wi-Fi page's reach

Board section: P2-2w c4f; work item #1385. From #1302 Security S-R1 (builder release 2) and, as a second item, #1407 Security S-R5 (from the issue's comments). Today the Wi-Fi page (uid agentos-localui) owns two files that decide root- and vault-side actions:

- **The claim state.** `localui-claim` (root) moves the seller's sealed `/var/lib/agentos/claim.json` into `/var/lib/agentos-localui/claim.json`; the page runs `claim.Open`/`claim.Try` on it (firstboot/start.go, firstboot/claim.go) and writes the try counts. `agentos-egress-setup.path` fires on every change to that file, and `egress-setup` copies it and runs `agentos-egress init -setup -claim <copy>` as agentos-egress, whose check (`claim.Claimed`, agentos-egress main.go `initCmd`) accepts `{"claimed":true}` with no verifier. A compromised page therefore writes `{"claimed":true}`, gets a setup vault made, and provisions its own Owner Card on an unclaimed box (HW-10, K5, egress K22).
- **The card-confirm latch.** agentos-ap (root) burns the sticker's setup network when the page-writable `/var/lib/agentos-localui/card-latch.json` says `card_confirmed:true` (`-card-latch`, `firstboot.SetupNetwork`, `firstboot.CardConfirmed`). A compromised page burns the setup network on an unconfirmed box, which moves the access point to the card's password before any card exists, leaving the owner with no way in short of reinstalling (CH-7: the burn happens at the Owner Card confirm, not before).

**Requirements:**
- HW-10: the claim sticker's code unlocks nothing, dies at first claim, and a claim on a claimed box is refused. A compromised page must not be able to mark the box claimed, reset the try count, or skip the lockout.
- HW-1 (claim K5): no secret exists before the claim, so the setup vault and its key are made only after a claim the vault process itself checked (egress K22).
- CH-7: the box burns the setup Wi-Fi password at the Owner Card confirm, so "confirmed" is decided by a process holding the card's provision, not by the page.

**Acceptance:** A1 (the booted image, through the G1 box e2e and CI's QEMU boot test). **Implementation risk:** tier A (labelled; a briefs-only diff reads tier C in `tools/risk_tier.py`). **Needs:** PR #1302 (merged), PR #2032 (merged, 24c33943), and the open PRs under Sequencing. **Gate:** lenses (security: strongest tier, with an explicit threat check of the page uid as attacker).

## Sequencing (D-111)

The build does not start while an open PR touches a file in the scope below. At the time of writing:

- #2044 touches `broker/cmd/agentos-egress/server.go` (the unlock socket's mux), `broker/cmd/agentosd/main.go` and both packages' ASSUMPTIONS.md. It also adds the vault process's `GET /committed-wifi`, which item 2 may use.
- #2015 touches `broker/cmd/agentosd/main.go` and `broker/egress/*`.
- #2039 touches `broker/localui/server.go`.
- #2032 is merged: it changed `broker/cmd/agentos-ap/agentos-ap.service` and the agentos-ap unit test, which item 2 rewrites; build on main after it.
- #2065 (`agentos-egress/providers.go`) and #2069 (`agentos-egress/keycheckguard_test.go`) touch the same directory but no file below; they do not block.
- P2-2w c4f s3 (queued, not started) sandboxes `agentos-egress-setup.service`, which this package removes. Build s1 first; s3's brief is then rewritten for whatever root step remains (the coordinator re-scopes s3 when s1 merges).

Start when #2044, #2015 and #2039 have merged or closed. Item 1's egress and page parts may start once #2044 alone has merged if the builder keeps out of `agentosd/main.go` and `localui/server.go` (below says when those are needed).

## Scope (files)

Item 1, the claim:
- `broker/claim/claim.go`, `claim_test.go`, `ASSUMPTIONS.md` (K5): whatever the vault-side claim needs (a `Store`-based API exists; keep the seal format the seller writes).
- `broker/cmd/agentos-egress/`: a new `claimroute.go` and `claimroute_test.go` for the claim routes; `server.go` gains only their registration on the unlock socket; `main.go` (`initCmd`: `-claim` goes, the state path is the vault's own); `ASSUMPTIONS.md` (K22).
- `broker/firstboot/start.go`, `claim.go`, `claim_test.go`, `start_test.go`, `ASSUMPTIONS.md`: `Begin` takes a claim client instead of a `Store` it parses.
- `broker/localui/firstboot.go`, `claim.go`, a new `claimrelay.go` and `claimrelay_test.go`, `ASSUMPTIONS.md` (L42): the page relays to the vault process. `broker/localui/server.go` only if the `BoxClaim` config cannot carry the relay unchanged (then wait for #2039).
- `broker/cmd/agentos-localui/main.go`: `-claim-state` goes.
- `broker/cmd/agentos-seller/prep.go` only if a test shows the sealed file must change (expected: unchanged, it still writes `claim.StatePath` as root).
- `broker/e2e/boxe2e/main_linux.go` and its ASSUMPTIONS.md: the claim path the G1 e2e drives.
- `broker/cmd/agentos-localui/agentos-localui.service` (no `-claim-state`, no `Requires=` on the claim move) and `agentos-localui-claim.service` (removed).
- `image/mkosi/mkosi.extra/usr/lib/agentos/localui-claim` (replaced by `egress-claim`), `egress-setup`, `boot-report` (its claim-move line names the new step), `usr/lib/systemd/system/agentos-egress.service`, `agentos-egress-setup.path` and `agentos-egress-setup.service` (removed), `agentos-boot-report.service` (`After=`), `image/e2e/agentos-e2e-seal.service` (`Before=`), `image/build.sh` (the unit install line), `image/ASSUMPTIONS.md`.
- A new `tests/test_image_claim.py`, kept apart from tests/test_image.py; `tests/test_image.py` only for lines that pin a removed unit or script.

Item 2, the confirm witness:
- `broker/cmd/agentosd/setup.go`, a new `cardwitness.go` and `cardwitness_test.go`, and `main.go` only for the witness path flag (wait for #2044 and #2015), `ASSUMPTIONS.md`.
- `broker/cmd/agentos-ap/main.go`, a new `witness_test.go`, `agentos-ap.service`, `ASSUMPTIONS.md`.
- `broker/firstboot/start.go` (`SetupNetwork`, `CardConfirmed`), `card.go` (the latch keeps page-local state only), `setupnet_test.go`, `ASSUMPTIONS.md` (F10, F15).
- `broker/cmd/agentos-egress/` only if #2044's `GET /committed-wifi` does not answer "the provisioned Owner Card is held" (then a new `cardheld.go` route on the verify socket).

**Guard files:** none (no broker package is added or linked; agentos-ap reads a JSON file with packages it already imports).

## What to build

1. **The vault process owns the claim state.** A root first-start step (`egress-claim`, run as `ExecStartPre=+` of agentos-egress.service before `egress-setup`) moves `/var/lib/agentos/claim.json` to `/var/lib/agentos-egress/claim.json`, owned by agentos-egress, once, the way `localui-claim` moves it today: root moves, never parses. Nothing the page uid can write is read by root or by the vault process for the claim afterwards.
2. **Claim over the unlock socket.** The vault process serves, on the unlock socket and under its existing peer-uid check, the claim operations the page needs: try a typed code (`claim.Try` against its own state, with the try count and lockout kept there), check a claimant token, and report the state (unclaimed, claimed, locked out with the wait). The page's `/claim` relays the typed code and keeps the claimant cookie it gets back; every claimant check goes through the vault process. The page keeps no claim file. The vault process must serve these routes before any vault exists; if it does not today, making it do so is part of this item.
3. **The setup vault follows the vault's own claim.** `init -setup` reads only the vault process's state directory (no `-claim` flag), so a file the page wrote can no longer reach it. On a successful try the vault process makes the setup vault itself, with the code `init -setup` uses, and opens it (CTRL-setup-open). `egress-setup` stays as the restart path for a crash between the claim and the vault (claimed, no `vault.keys`), runs `init -setup` as agentos-egress without copying any page file, and `agentos-egress-setup.path` and its service go. If making the vault inside the serving process fails review or test, the fallback is that a successful try exits the process for systemd to restart it through `egress-setup`; record the choice in egress ASSUMPTIONS K22.
4. **Item 2: a root-owned confirm witness.** agentosd (root) writes `/var/lib/agentos/card-confirmed.json` (0600, root) only when the page's `page_setup_finish{card:true}` arrives and the vault process confirms over the verify socket that it holds the provisioned Owner Card (#2044's `GET /committed-wifi` if its 200 means exactly that, otherwise a dedicated route). agentos-ap reads that witness and owner.json for the burn and for `CardConfirmed`, never the page latch; `-card-latch` goes from its unit. The page latch keeps only page-local UI state (Preloaded routing, F15). A reset that remakes the vault (K22, F10) never leaves a witness behind for a card the vault no longer holds: the witness is written only after the provision, and the burn it causes is the CH-7 burn.

**Integration owner:** this package owns the whole path from the seller's sealed file to the setup network's burn: seller seal, root move, page relay, vault-side try, setup vault, card provision, witness, burn. Its box e2e run is the integration test.

### Stage × outcome matrix

Each cell is a test (named under Acceptance tests); "page" means the page uid acting as an attacker with its own files and sockets.

| Stage | Success | Failure or attack | Restart in the middle |
|---|---|---|---|
| Seal and move | Sealed file lands in the vault's state dir, owner agentos-egress, 0600 | Symlink or non-file source: not moved, logged | Move is idempotent; a moved file is never moved again |
| Wrong code | Try count rises in vault state; page shows the wait | Page writes any file it owns: count and lockout unchanged | Count survives restart |
| Lockout | Further tries refused with the wait | Page cannot reset it | Lockout survives restart |
| Right code | Claimed; claimant token returned; setup vault made and opened | Second claim refused "already claimed" | Claimed, no vault: `egress-setup` makes it at the next start |
| Forged claim | n/a | Page writes `{"claimed":true}` anywhere it can: no setup vault, no `vault.keys`, no setup key | n/a |
| Card confirm | Witness written after the vault confirms the card; agentos-ap burns | Page writes `card_confirmed:true` in its latch: no witness, no burn; finish without a held card: no witness | Restart between provision and witness: finish retries and writes it; no burn before it |
| Reset (F10, K22) | Vault remade; no witness exists for a card it no longer holds | Witness present and vault remade: the case cannot arise, shown by test | Owned box (owner.json) burns regardless, as today |

## Acceptance tests

**Acceptance tests:** HW-10, HW-1 (K5, K22): `broker/cmd/agentos-egress/claimroute_test.go` (`TestClaimTryOverUnlockSock`, `TestClaimLockoutHeldByVault`, `TestInitSetupIgnoresPageState`, `TestForgedClaimMakesNoVault`), `broker/localui/claimrelay_test.go` (`TestClaimRelaysToVault`, `TestClaimantCheckedByVault`), `broker/firstboot/claim_test.go`; CH-7: `broker/cmd/agentosd/cardwitness_test.go` (`TestWitnessOnlyAfterVaultHoldsCard`), `broker/cmd/agentos-ap/witness_test.go` (`TestPageLatchDoesNotBurn`, `TestWitnessBurns`), `broker/firstboot/setupnet_test.go`; A1: `tests/test_image_claim.py` (`ClaimStateOwnerTest`, `NoPageFileReadTest`, `ApUnitTest`) and the G1 box e2e claim run (`broker/e2e/boxe2e`).

1. Over a real unlock socket, a wrong code raises the count and a right code returns a claimant token; the count and lockout live in the vault's state and survive a restart; a second claim answers "already claimed".
2. With the page's state directory holding `{"claimed":true}` and every file the page can write set to claim, `init -setup` and the serving process make no vault, no `vault.keys` and no setup key (K5's canary scan, extended to this case).
3. The page holds no claim file after first start, and its `/claim` and every claimant check call the vault process (a stub that refuses makes the page refuse).
4. agentos-ap with a page latch saying `card_confirmed:true` and no witness does not burn; with the witness it burns; with owner.json it burns as today. agentosd writes the witness only when the vault reports the card held, and never on the page's report alone.
5. The image: `egress-claim` moves the file into `/var/lib/agentos-egress` as agentos-egress; no shipped unit or script under image/ reads `/var/lib/agentos-localui/claim.json` or passes `-claim-state`, `-claim` or `-card-latch`; `agentos-egress-setup.path` is gone; agentos-ap's unit names the witness and owner.json.
6. The G1 box e2e claims a box through the page and reaches the card step, with the claim state in the vault's directory.

## Out of scope

Making agentosd's finish refuse without a provisioned card in general (L42's residual, beyond the witness here); s3's sandbox of the remaining root step; any migration of a box claimed under the old layout (no box has shipped; record that in claim ASSUMPTIONS K5); verifying the seal against a seller key.

## Estimate

About 130k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5). If the checkpoint arrives with item 1 green and item 2 not started, item 2 ships as a second PR under this brief, citing CH-7.
