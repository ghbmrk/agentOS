# WIFI-del-f: the Owner Card names the local page "my Wi-Fi page", as the owner texts do

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3404, UX release finding 1 on #3402 (WIFI-del-e, comment 6444057962). CH-12, ONB-7, HW-1. Tier B.

## The gap

CH-12: owner texts use one name for the local UI, built on the Wi-Fi the owner reaches it by. SPEC and about 200 owner texts call it "the Wi-Fi page". The card says "Box page:" on its front and rotation sheet and "type it on my box page" in the passphrase note, and the card display's three 410 answers say "my box page". `TestCardCarriesNoWiFi` forbids the needle "my Wi-Fi" on every card page, so it would also block SPEC's name.

- **Failure path:** the card tells the owner to use "my box page", every text says "my Wi-Fi page", and the owner cannot tell they are the same page.

## Decisions

1. **SPEC's name.** The card labels the address "Wi-Fi page:" and the passphrase note says "my Wi-Fi page"; the display's in-effect, cancelled and confirmed answers say "my Wi-Fi page". If SPEC renames the page now that the core serves no Wi-Fi (D-178), that is an L1 question, not this row's.
2. **The no-Wi-Fi guard stays a guard.** `TestCardCarriesNoWiFi`'s "my Wi-Fi" needle narrows to "my Wi-Fi becomes" and "my Wi-Fi switches" (the first-boot lines WIFI-del-e removed), beside "Box Wi-Fi" and the rest.
3. **Quick-start step 4 is shorter** (later finding, folded in): about 20 words, still naming the Owner network before the claim.
4. **Brand casing** (coordinator ask): owner-visible "AgentOS" on the card pages and the seller's claim sticker becomes "agentOS".
5. Not touched: `broker/localui` (old core, frozen; its footer still says "Box page", retired with it), SPEC.

## Scope

- `broker/card`: `render.go`, `display.go`, `wifidel_test.go`, `card_test.go`, `ASSUMPTIONS.md` (C3, C10, C17 wording).
- `broker/cmd/agentos-seller`: `sticker.go`, `wifidel_test.go`.
- Not touched: `broker/card` files #3167 (OWN-card-ca, queued, not building) will edit beyond `render.go`; the two must not build together (D-111).

**Requirement IDs:** CH-12, ONB-7, HW-1. **Guard files:** none. Not a gate file.

## Acceptance tests

- CH-12, ONB-7: `broker/card/wifidel_test.go::TestCardNamesTheWiFiPage`. The card, rotation sheet, both displays and the display's 410 answers name "Wi-Fi page" and never "box page" (any case). It catches a card that names the page differently from the texts.
- HW-1, CH-9: `::TestCardCarriesNoWiFi` (narrowed needle) still catches a card that names a box Wi-Fi.
- HW-1: `::TestCardSaysAgentOSInLowerCase` and `broker/cmd/agentos-seller/wifidel_test.go::TestStickerSaysAgentOSInLowerCase`: no "AgentOS" on the card pages or the sticker.

## Needs, order, estimate

**Needs:** #3402 merged. Checked 2026-10-27 17:00Z: #3167 is `state:queued`, and no open PR touches `broker/card` or the seller. **Estimate:** about 40k tokens, one session.

## Board row

```board-row
{"section": "Identity, onboarding and setup (SPEC §11-12)", "cells": ["[WIFI-del-f: the Owner Card names the local page as the owner texts do (\"my Wi-Fi page\"), and the card test's no-Wi-Fi needle stops forbidding that name (CH-12, ONB-7; UX finding 1 on #3402).](briefs/WIFI-del-f.md)", "WIFI-del-e (#3365)"], "rest": " (release; tier B)"}
```
