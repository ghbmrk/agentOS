# CTRL-card-rot-ap-2-l1: rotation Wi-Fi wording and a test that a post's hand-off ends with the post

Board section: CTRL-card-rot-ap-2. Source: #1526 (PR #1520 P/UX/L3 review U-1 to U-3, L-2). Tier: A. Builder: strongest model. Usage estimate: 60k tokens. Item 1 (reconcile, P-1) is CTRL-card-rot-ap-2-s8 (#1696, PR #2044); `APLoader.Rekey` is already gone from `broker/apnet`.

**Why.** After a Wi-Fi rotation's confirm the access point switches password and the phone drops off. The confirm page said "open my box page again", but Home does not offer the done page (which shows the new code generator once), while a reload re-requests it. The done notes said "If your phone drops off" for a drop that is expected, and the failed note pointed at "Home" without naming the entry that rotates. No test kills mutant M14 (`serveCard` not clearing `rot.wifi` after a post).

## Requirements

- **CTRL-card-rot-ap-2-l1-1** (REC-4, CH-7) A Wi-Fi rotation's confirm page says: "Your phone drops off it: rejoin with this card's Wi-Fi QR code, or its name and password, then reload this page."
- **CTRL-card-rot-ap-2-l1-2** (REC-4, CH-7) The switched done note says "Your phone may drop off now: rejoin with the Wi-Fi QR code on your new card."; the failed note ends "...replace the Wi-Fi password again from Replace Owner Card parts on Home."
- **CTRL-card-rot-ap-2-l1-3** (REC-4, CH-7) A post's Wi-Fi hand-off is cleared when the post ends: after a mismatched post, a commit through `ConfirmAnswers` hands off nothing.

**Acceptance tests:** CTRL-card-rot-ap-2-l1-1 `broker/card/display_test.go::TestTheWiFiRotationPageSaysToReload`; CTRL-card-rot-ap-2-l1-2 `broker/localui/rotwifi_test.go::TestRotationOfTheWiFiPasswordSwitchesTheAccessPoint`, `broker/localui/rotwifi_test.go::TestRotationOfTheWiFiPasswordThatCannotSwitchSaysSo`; CTRL-card-rot-ap-2-l1-3 `broker/localui/rotwifi_test.go::TestAPostsWiFiHandOffEndsWithThePost`.

## Acceptance

The tests above pass and carry `REQ:` markers; the M14 mutant (drop `rot.setWiFi(nil)` from `serveCard`'s deferred reset) fails `TestAPostsWiFiHandOffEndsWithThePost`; CI green.

**Guard files:** none

## Scope

`broker/card/display.go`, `broker/card/display_test.go`, `broker/localui/rotwire.go`, `broker/localui/rotwifi_test.go`, `broker/localui/rotwire_test.go`, `briefs/CTRL-card-rot-ap-2-l1.md`.
