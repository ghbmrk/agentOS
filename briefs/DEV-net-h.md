# DEV-net-h: The P2-1 loader never leaves a stale access-point exemption

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (firewall, home-network boundary).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2
**Acceptance:** A14 (a home-network host cannot open a connection to any box port).
**Dependencies:** DEV-net-g merged (#1075). Fold into P2-1's loader acceptance if P2-1 wires `BringUp` first.

## Finding

Found in PR #1075's tier A review (comment 6120595937), release finding R1. Invariant: A14 / DEV-2 "In".

Failure path: on a single-radio box, the loader dies or `BringDown` fails, and `wlan0` joins the home Wi-Fi while still exempt with `agentos_ap` loaded; a home host then reaches a box listener on UDP 53/67 or TCP 53. Or `BringUp(wl1)` replaces `agentos_ap` and `wlan0` stays exempt with no table: every port is open to that network.

## Row DEV-net-h

Four conditions on the P2-1 loader's use of `BringUp`/`BringDown`:

- (a) The loader runs `BringDown` (idempotent) for its AP interface at its own start, before any station join.
- (b) It never puts an interface into station mode while that interface's `BringDown` returned an error.
- (c) It never calls `BringUp` on a second interface while another is up, or `ap-exempt` refuses when `exempt` holds a non-lo element other than `<if>`.
- (d) `BringUp`/`BringDown` teardown runs on `context.WithoutCancel`.

Scope: `broker/localui/` (`apexempt.go`), the P2-1 loader, `image/` (`ap-exempt`), tests, ASSUMPTIONS.md of each touched package.

## Acceptance tests

Mark with `REQ: DEV-2`. One test per condition (a) to (d), with fault injection for the loader death and the failed `BringDown`. Synthetic interface names and documentation addresses only. Do not edit SPEC.md.

## Handoff and estimate

Predicted tier A. Run affected Go packages with race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.
