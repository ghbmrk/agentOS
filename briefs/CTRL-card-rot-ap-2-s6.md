# CTRL-card-rot-ap-2 s6: a K row for the verify socket's POST /rotate/wifi

**Owner:** primary lane.
**Priority:** release. **Class:** release. **Implementation risk:** tier A (records ARC-1 custody of a host network secret).
**Board section:** Controller and helper system (D-102).
**Requirements:** ARC-1, REC-4
**Acceptance tests:** none: a record-only package (one ASSUMPTIONS row, no code). ARC-1, REC-4 are checked by review of `broker/egress/ASSUMPTIONS.md` K35 against `broker/cmd/agentos-egress/server.go` (the route), `rotation.go` (`wifiHold`, `takeRotatedWiFi`, the begin's clear) and `custody.go` (`lock`); the behaviour it records is already pinned by `broker/cmd/agentos-egress/rotwifi_test.go` (`TestACommittedWiFiRotationIsHeldForAgentosdOnce`, `TestAHeldWiFiNetworkLapsesAndIsDropped`, `TestTheRotatedWiFiRouteIsNarrow`). `python3 tools/doclint.py` is clean.
**Dependencies:** PR #1614 (the route), merged; #1628 / PR #2032 (CTRL-card-rot-ap-2 s5, agentos-ap denied `/run/agentos-egress`), merged as 24c3394.
**Source:** Potency/UX/L3 review of PR #1614, L3-1 (head b8323e16), issue #1629.

## Finding

PR #1614 added a vault-process route on `verify.sock`, `POST /rotate/wifi`, which hands agentosd the access point's rotated Wi-Fi password. Every other `verify.sock` route has a K row in `broker/egress/ASSUMPTIONS.md` (K7, K14, K17, K23); this one is recorded only in `broker/apnet/ASSUMPTIONS.md` N5, so a reader of the vault's custody record misses a host network secret leaving the vault process.

## Scope and intended change

`broker/egress/ASSUMPTIONS.md` (one new K row) and this brief. The row names: the route; its peer guard (socket 0666, SO_PEERCRED uid == `-broker-uid`, which the shipped unit sets to 0, so any root process that reaches `/run/agentos-egress`; agentos-ap is denied that directory, s5); the one-shot take; the 5-minute lapse (`wifiHold`, checked at the take); and that a new begin or a lock clears the permit. It cross-references N5 and K19. Number: K34 is on main's next free slot but open PR #2015 adds K34, so this row takes K35 to avoid a duplicate ID.

Not in scope: narrowing `verify.sock` to agentosd alone (N5's last residual), any code or test change.

Failure path the row guards: a later change widens the route's peer guard or drops the lapse or the clears, and no custody record of the vault process says what the route was meant to allow.

## Handoff and estimate

Initial checkpoint: 30k tokens, an estimate rather than a ceiling.
