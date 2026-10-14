# DEV-net-f: The access point's interface joins the inbound exempt set

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (firewall, owner's onboarding path).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2, CH-7
**Acceptance:** A1 (onboarding and unlock over the box's Wi-Fi), A14.
**Dependencies:** DEV-net-e merged (3f07777).

## Finding

Found in PR #1055's tier A review (comment 6116370748), release finding R1. Checked against BOARD.md on 2026-10-12: no queued row covers it. P2-1 and P2-2w c3 do not mention `agentos_inbound`, and CTRL-spike only tests that the radio can serve an access point.

- No loader for CH-9's `agentos_ap` exists yet; only `localui.NftRules` renders it. The code that brings up the access point must add its interface to `inet agentos_inbound` set `exempt` (`netguard.InboundExemptSet`).
- Failure path: a drop in `agentos_inbound` is final. Once the access point is up and the interface is not in the set, the owner's phone cannot reach the local page, so onboarding or unlock over the box's Wi-Fi fails, closed. The owner sees a Wi-Fi network that joins but a page that never loads.

## Scope and intended change

`image/` (the access-point bring-up unit or script and its ordering against `agentos-inbound.service`), `broker/netguard/` (only if a helper to add an element is needed), `broker/localui/` (only the `agentos_ap` loader wiring), `tests/test_image.py`, ASSUMPTIONS.md of each touched package.

- At access-point bring-up, add the AP interface by name to the exempt set after `agentos-inbound.service` has loaded the table, and again if the interface is recreated. If the table is missing or the add fails, bring-up fails and the box says so; it never opens the interface by deleting the table.
- Only the AP interface is added. An uplink, tether or second NIC stays filtered (DEV-net-e 2a).
- Keep the `Requires=` and `After=` ordering so the table exists before the add. If the image uses NetworkManager for the AP, LATER `DEV-net-e l3` applies and is closed here.

Do not edit SPEC.md.

## Acceptance tests

1. On the image (netns test is enough in CI), with the table loaded and the AP interface up, a client on the AP interface reaches the local page port; the same client on a non-exempt interface does not (DEV-2, A1).
2. The AP interface is re-added after it is deleted and recreated; a failed add makes bring-up fail rather than leave the table or the interface open (CH-7).
3. A home-network host still cannot open a connection to any box port (A14 unchanged).

Synthetic interface names and documentation addresses only. Run affected Go packages with race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.

## Handoff and estimate

Predicted tier A. Initial checkpoint: 40k tokens, an estimate rather than a ceiling. If P2-1's `agentos_ap` loader has not landed, build the exempt-set add as a function with the netns test and wire it where the loader goes; do not build the loader here.
