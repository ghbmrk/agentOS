# WIFI-del-e: the Owner Card carries no Wi-Fi, and its quick-start starts from the enforcer's setup network

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3365, a release finding split off WIFI-del-d (#3354). D-178, SPEC §3.1 (the card lists no Wi-Fi), §12.1 steps 1 and 4, ONB-7. Tier A.

## The gap

D-178: the core and the edge never turn Wi-Fi on, and only the enforcer holds the Owner network's password. SPEC §3.1 lists no Wi-Fi on the Owner Card. On main, `card.Generate` still draws a box Wi-Fi name and 80-bit password, both card pages print a "Box Wi-Fi" section with a Wi-Fi QR, the quick-start says "Join the Wi-Fi", the "Nothing happened?" side says to look for the box's Wi-Fi, and the first-boot display says "my Wi-Fi becomes the one on your card". The values travel to the vault (`recovery.Card`, the stored card and its `card-wifi` redactor entry), across the unlock socket (`/card/provision`, `/rotate/begin`'s `wifi_name`, `/rotate/commit`'s `wifi_password`) and out of egress's verify socket (`/rotate/wifi`, `/committed-wifi`, read by `modelroute`), whose only reader, agentosd's access point code, WIFI-del-a2 deleted.

- **Failure path:** an owner follows the card's quick-start or its "Box Wi-Fi" QR, joins nothing, and the card names a password no device uses.

## Decisions

1. **The card has no Wi-Fi.** `card.Card` loses `WiFiName` and `WiFiPassword`; `Generate` no longer draws them (so a fixed-seed card's other values shift: no test may pin values drawn after them); `Validate` drops their checks. `card.WiFiQR` stays: the seller's sticker uses it for the enforcer's setup network (WIFI-del-d, #3354).
2. **The rotation has no Wi-Fi part.** `card.Parts.WiFi`, the display's "last four of the new Wi-Fi password" check, `DisplayConfig.WiFiName` and both "my Wi-Fi switches" lines go. In `recovery`, `PartWiFi` leaves `AllParts` and the exported API (`Pending.WiFiName`, `LostCardWiFiNote`, the `DoneNotes` Wi-Fi line). An unexported `partWiFi` ("wifi") stays only so a rotation mark written before WIFI-del-a2 is still settled (WIFI-del-a2-1), and `RotationUnfinished` never reports it. `BeginRotate` refuses "wifi" as an unknown part.
3. **The vault reads old cards and writes new ones without Wi-Fi.** `EncodeCard` writes no Wi-Fi fields; `DecodeCard` still accepts a stored card that has them (its `DisallowUnknownFields` would otherwise lock a box provisioned before this row out of its own card) and drops them. `storeCard` keeps only the setup secret as a part entry; an existing `card-wifi` entry is left in place (it still redacts a value that was printed).
4. **The wires drop the fields on both ends together.** localui (`vault.go`'s provision body, `rotwire.go`'s begin answer, commit body and `partNames`) and egress (`cardvault.go`, `rotation.go`) ship in the same image, so no compatibility shim is kept. Egress's `/rotate/wifi`, `/committed-wifi`, the held network and `committedwifi.go` are deleted with `modelroute`'s `TakeRotatedWiFi`, `CommittedWiFi` and their errors: with no card Wi-Fi they have nothing to serve, and nothing reads them. This takes "the vault's unused Wi-Fi reads" off WIFI-del-b2. `broker/cmd/agentos-egress` and `broker/egress` are old core: deletions only, nothing added (`trace.py --ratchet`).
5. **The quick-start starts from the enforcer's setup network.** At most five steps (ONB-7): plug in (SIM, modem, the controller's cable to the enforcer), power on, scan the setup Wi-Fi code on the claim sticker or flasher and join the enforcer's setup network, rejoin on the Owner network the enforcer's page gives and scan the claim code, done. "Nothing happened?" no longer names a box Wi-Fi: it keeps the wait, the box page and the boot keys, and adds ONB-7's "Phone won't join: it needs WPA3". The builder picks the words; tests pin "enforcer" in the setup step, "Owner network" before the claim, and no "Box Wi-Fi".
6. **Readers that only reach the card values are updated, not redesigned.** `localui/scan.go` keeps recognising a Wi-Fi QR beside the passphrase QR (a card printed before this row has one); only its comment changes. `firstboot`, `apnet` (deleted by WIFI-del-b2) and `localui` tests drop the fields.

## Scope

- `broker/card`: `card.go`, `display.go`, `render.go`, `card_test.go`, `display_test.go`, `rotation_test.go`, `discardhook_test.go`, `wifidel_test.go`, `ASSUMPTIONS.md` (C1, C5, C17).
- `broker/recovery`: `rotate.go`, `keys.go`, `ASSUMPTIONS.md` (R9, R14, R15, WIFI-del-a2-1, the lost-card note line) and the tests that name the fields or `PartWiFi`: `a8_test.go`, `choice_test.go`, `rig_test.go`, `rotate_test.go`, `rotate_atomic_test.go`, `rotation_display_test.go`, `scan_test.go`, `wifidel_test.go`, `forgetlog_test.go`, `reencrypt_test.go` as needed.
- `broker/localui`: `rotwire.go`, `vault.go`, `scan.go` (comment), `rotwire_test.go`, `vault_test.go`, `cardsock_test.go`, `cardwire_test.go`, `claim_test.go`, `ASSUMPTIONS.md`.
- `broker/modelroute`: `verify.go`, its tests, `ASSUMPTIONS.md` (M5 and the rotated-network row).
- `broker/cmd/agentos-egress`: `cardvault.go`, `rotation.go`, `server.go`, `custody.go` (the held network's reset), `committedwifi.go` and `committedwifi_test.go` and `rotwifi_test.go` (deleted), `cardvault_test.go`, `rotation_test.go`, `rotwire_test.go`, `wifidel_test.go` (new), `ASSUMPTIONS.md` (S8-1). `broker/egress/ASSUMPTIONS.md` K35 retired.
- Tests only: `broker/firstboot` (`card_test.go`, `setupnet_test.go`, `start_test.go`, and `ASSUMPTIONS.md` F11), `broker/apnet/apnet_test.go`.
- Not touched: any `broker/cmd/agentos-seller` file (#3354 is building there), `broker/localui/wired.go` (#3382), any `broker/cmd/agentosd` file, `image/`.

**Requirement IDs:** HW-1 (the card the box generates), ONB-7 (the card is the manual), CH-9 (the core serves no Wi-Fi; only the enforcer holds the Owner network's password), REC-4 (rotation).

**Guard files:** none. No package is added. Not a gate file (`premerge.py --needs-mark` should print `agent`; the builder confirms).

## Acceptance tests

- HW-1, CH-9: `broker/card/wifidel_test.go::TestCardCarriesNoWiFi`. A generated card's full page and a rotation page of every part carry no "Box Wi-Fi", no `WIFI:` QR payload, and `Parts` has no Wi-Fi field. It catches a card that still prints a network no device serves.
- ONB-7, CH-9: `::TestQuickStartStartsFromTheEnforcer`. At most five steps; the step with the setup Wi-Fi code names the enforcer, a later step names the Owner network before the claim; no step says to join the box's Wi-Fi. The printed page carries the quick-start and "WPA3".
- REC-4: `broker/recovery/wifidel_test.go::TestRotationHasNoWiFiPart`. `AllParts` has no "wifi", `BeginRotate` refuses it as unknown, and a mark that owes it (from before WIFI-del-a2) is never reported by `RotationUnfinished` and is settled by the next rotation (extends the two a2 tests).
- HW-1: `::TestAStoredCardWithWiFiStillDecodes`. A stored card written with the old Wi-Fi fields decodes; a newly encoded one has none.
- CH-9: `broker/cmd/agentos-egress/wifidel_test.go::TestTheVaultHandsOutNoWiFi`. The verify socket refuses `/rotate/wifi` and `/committed-wifi` like any unknown route (405, not listed), and the rotation's begin answers no Wi-Fi name. It catches a vault route that would still hand out a Wi-Fi password.
- Updated, not new: the card, recovery, localui, egress and firstboot tests that set or compare the fields.

## Needs, order, estimate

**Needs:** none open. WIFI-del-c (#3355) merged. Runs beside WIFI-del-d (#3354): no shared file (the seller only calls `card.WiFiQR`, which stays). Checked 2026-10-27 13:45Z: no open PR touches these files (#3382 holds `localui/wired.go` only).
**Estimate:** about 120k tokens, one session: some 300 lines removed across about 40 files, little new code. Checkpoint at 100k.

## Residual risks

- A box provisioned before this row keeps a `card-wifi` vault entry holding a password nothing uses. It is redaction-only and is not read; it goes when the old vault is retired (D-139 step 5).
- The card still lacks SPEC §3.1's page-authority fingerprint line (CH-9). That is its own row, not this one.

## Board row

```board-row
{"section": "Identity, onboarding and setup (SPEC §11-12)", "cells": ["[WIFI-del-e: the Owner Card drops its Box Wi-Fi section, Wi-Fi password and the rotation's Wi-Fi part, the vault and its sockets stop carrying them, and the quick-start starts from the enforcer's setup network (HW-1, ONB-7, CH-9; D-178, split from WIFI-del-d).](briefs/WIFI-del-e.md)", "WIFI-del-b (#3235), #3355"], "rest": " (release; tier A)"}
```
