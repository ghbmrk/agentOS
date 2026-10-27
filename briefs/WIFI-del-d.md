# WIFI-del-d: the claim sticker's step 1 is the enforcer's setup network, and the seller stops sealing one into the core

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3354, a release finding from WIFI-del-c (#3349, PR #3355). D-178 and SPEC §12.1 steps 1 and 4. Tier A.

## The gap

D-178: the core and the edge never turn Wi-Fi on, and the claim sticker names the **enforcer's** setup network, which opens only the enforcer's enrolment page. That page enrols the passkey, installs both certificates and hands the phone the Owner network; the claim QR is scanned only after the phone rejoins on the Owner network (§12.1 step 4).

On main, `agentos-seller prep` still draws a setup network (`claim.NewSetupNet`), seals it into the core's image at `claim.SetupNetPath` (ASSUMPTIONS A8, A9) and prints it as step 1 "Join this Wi-Fi", with step 2 reading as if the claim follows at once. The core serves no network after WIFI-del-a2 and a3, so:
- **Failure path:** an owner scans step 1's Wi-Fi QR on a preloaded box, the phone looks for a network no device serves, and setup never starts. Even with an enforcer serving it, step 2 sends the owner to the claim page from the setup network, which opens only the enforcer's page.
- The core's image carries a per-box Wi-Fi secret that nothing reads but `agentos-ap` (deleted by WIFI-del-b, #3235).

## Decisions

1. **The seller still draws the setup network, and hands it to the enforcer instead of the core.** `prep` keeps `claim.NewSetupNet` (80-bit password, drawn apart from the code) but no longer seals it into `box.raw`. It writes it, in `SetupNet.Marshal`'s JSON, to `enforcer-setup-net.json` in `Out`, 0600 through `writeNew` (refuses an existing file), beside `sticker.txt`. This is the hand-off the enforcer's preload reads (D-178: "the seller preloads the enforcer and its access point too"). One generator and one format stay. *Alternative rejected:* the seller reads a network the enforcer's preload produced (`-setup-net FILE`). That would be the cleaner ownership once the enforcer image exists, but nothing produces such a file yet, so `prep` could not run. The enforcer preload row can flip the direction later without changing the sticker.
2. **The core's image holds only the claim state.** `prep` seals one file (`claim.StatePath`). `sealDirs` drops the access point loader's directory, so `prep` accepts an image without `/var/lib/agentos/ap` (WIFI-del-b removes it). `preflight`'s "already holds a setup network" refusal and `checkSealed`'s setup-network parse go. `claim.SetupNetPath`, `firstboot`'s setup-network load and burn, and `claim.SetupNet.Rotate` stay for now: their only reader is `agentos-ap`, which WIFI-del-b (#3235) deletes, so they go with it.
3. **The sticker states the order.** Step 1 names the enforcer's setup Wi-Fi (name, password and its Wi-Fi QR, `card.WiFiQR`) and says the enforcer's page opens and gives the owner's home Wi-Fi. Step 2 says to claim once the phone is back on that Owner network. The labels "Wi-Fi password" and "Claim code" stay (CTRL-claim-ap-2, K9). `sticker.txt` names the network the same way. The builder picks the exact words; the tests pin "enforcer" in step 1 and "Owner network" in step 2, not the sentences.
4. **The last log line keeps the hand-off.** It now says to load `enforcer-setup-net.json` into the enforcer before deleting the directory, so the seller's one deletion step does not lose the network the sticker prints.

## Scope

`broker/cmd/agentos-seller`: `prep.go`, `sticker.go`, `seller_test.go`, a new `wifidel_test.go` (or the one #3355 adds) and `ASSUMPTIONS.md` (A2's "beside the state" line, A8 rewritten for the enforcer's network and the Owner-network claim, A9 rewritten for the hand-off file). No change in `broker/claim`, `broker/firstboot`, `broker/card`, `image/` or any `cmd/agentosd` file.

**Requirement IDs:** HW-10 (the claim sticker carries the enforcer's setup network, §12.1 step 1), CH-9 (the setup network opens only the enforcer's page; the claim is on the Owner network).

**Guard files:** none. Not trusted core and not a gate file (`premerge.py --needs-mark` should print `agent`; the builder confirms).

## Acceptance tests

- HW-10: `broker/cmd/agentos-seller/wifidel_test.go::TestPrepSealsNoSetupNetwork`. After `prep`, `box.raw` holds the claim state and nothing at `claim.SetupNetPath`, and `prep` succeeds on an image with `/var/lib/agentos` but no `ap` directory. It catches a core image still carrying a network no one serves.
- HW-10: `::TestEnforcerSetupNetworkIsHandedOff`. `Out` holds `enforcer-setup-net.json`, mode 0600; it parses with `claim.ParseSetupNet`; its name and password are the ones `sticker.txt` and `sticker.html` print; its password is not the claim code; `prep` never overwrites an existing hand-off file.
- HW-10, CH-9: `::TestStickerStepOneIsTheEnforcers`. In `sticker.html` and `sticker.txt`, step 1 names the enforcer and carries the network's Wi-Fi QR, and step 2 names the Owner network before the claim QR. It catches a sticker that sends the owner to the claim page from the setup network.
- Updated, not new: `TestPrepSealsOneState` (the image holds one sealed file), `TestPrepRefuses` (the "already holds a setup network" case goes; an image lacking `/var/lib/agentos` still refuses), `TestStickerLabelsItsCodes` (unchanged in intent).

## Needs, order, estimate

**Needs:** #3355 (WIFI-del-c) merged. It rewrites `claimURL` and the sticker's step 2 link in `sticker.go` and edits `seller_test.go`, the same files this row edits (D-111), and it waits on #3350 (a3). Build this row only after #3355 merges; it then builds on the page-name link as #3355 leaves it.
**Serial (D-111):** WIFI-del-b (#3235) deletes `agentos-ap` and the core's setup-network readers; it touches no seller file, so the two can run in either order. No other open PR touches `broker/cmd/agentos-seller` (checked 2026-10-27 05:00Z).
**Estimate:** about 50k tokens, one session: some 40 lines of code changed and 150 of tests. Checkpoint at 80k.

## Split-off finding (release, filed separately)

The issue's recheck holds: SPEC §3.1 lists no Wi-Fi on the Owner Card, and D-178 has only the enforcer hold the Owner network's password, but `card.Card` still makes and prints a "Box Wi-Fi" name and password (`WiFiName`, `WiFiPassword`, the rotation's Wi-Fi part) and its quick-start tells the owner to join it. Those fields reach `recovery`, `localui` and `agentos-egress`, about 40 files, so they are their own row: WIFI-del-e (#3365).

## Residual risks

- Until the enforcer's preload exists, `enforcer-setup-net.json` has no reader and the printed network is still served by nothing. This row makes the sticker, the image and the hand-off right; the network comes up when the enforcer preload row reads the file. G6 re-runs A1's setup through the enforcer (D-178).
- The hand-off file holds the setup password in the clear, as the sticker does (D-105's residual, moved to the setup network by D-178). It is 0600 in the seller's directory, which the seller deletes after printing and loading.

## Board row

```board-row
{"section": "Identity, onboarding and setup (SPEC §11-12)", "cells": ["[WIFI-del-d: the claim sticker's step 1 is the enforcer's setup network and step 2 claims on the Owner network; the seller hands the network to the enforcer in a file and stops sealing one into the core (HW-10, CH-9; D-178, release finding from WIFI-del-c).](briefs/WIFI-del-d.md)", "#3355 (WIFI-del-c) merged; same files"], "rest": " (release; primary; tier A)"}
```
