# CTRL-card-rot-ap-2 s5: deny agentos-ap the vault's verify socket

**Owner:** primary lane.
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** ARC-1, CRED-1, REC-4
**Dependencies:** PR #1590 (#1426, P2-1 s2), merged.
**Source:** Security R2 of PR #1614 (head b8323e16), issue #1628.

## Finding

The vault process's verify socket (`/run/agentos-egress/verify.sock`, `broker/cmd/agentos-egress/server.go`) is mode 0666 and checks only peer uid == the broker uid, which the shipped unit sets to 0. agentos-ap runs as root and its unit does not deny `/run/agentos-egress`, so the loader (or a child that reaches root) can take the one-shot rotated Wi-Fi permit (`POST /rotate/wifi`) or call `/recall-key`. The access point has no reason to reach that directory.

## Scope and intended change

`broker/cmd/agentos-ap/agentos-ap.service` (add `-/run/agentos-egress` to `InaccessiblePaths`), `broker/cmd/agentos-ap/unit_test.go` (pin it), `broker/apnet/ASSUMPTIONS.md` (N5's "who takes" residual), this brief. Not in scope: narrowing the socket itself to agentosd (#1629) and any other egress file.

## Acceptance tests

1. `TestTheUnitIsBounded` fails if `-/run/agentos-egress` is dropped from agentos-ap's `InaccessiblePaths` (ARC-1, CRED-1).
2. apnet N5's "who takes" residual says the broker uid is root in the shipped unit and names agentos-ap as denied the socket, matching the unit (REC-4).

Failure path: a compromised hostapd or loader on the radio takes the rotated Wi-Fi permit and keeps a lost card's password on the air.

## Handoff and estimate

Initial checkpoint: 40k tokens, an estimate rather than a ceiling.
