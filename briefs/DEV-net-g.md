# DEV-net-g: The access point's exempt entry must never outlive or precede its drop table

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (firewall, home-network boundary).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2
**Acceptance:** A14 (a home-network host cannot open a connection to any box port).
**Dependencies:** DEV-net-f merged (#1063, 4d1fa816). Must land before the P2-1 loader wires `BringUp`.

## Finding

Found in PR #1063's tier A review (comment 6117696547), release finding R1. Checked against BOARD.md on 2026-10-12: no queued row covers it. It is not reachable today because nothing calls `BringUp`; it becomes reachable the moment the P2-1 loader does, so this row must merge first.

Invariant: A14 / DEV-2 "In": a home-network host cannot open a connection to any box port. The exempt set must name the access point's interface only while the `agentos_ap` table is loaded and that interface is the AP.

Failure path: a single-radio box, the AP stops, `wlan0` joins the home Wi-Fi while it is still in the exempt set and `agentos_ap` is absent. Every home host then reaches every box port.

## Row DEV-net-g

Three conditions, all in the `BringUp` path from DEV-net-f:

- (a) Load the `agentos_ap` table before the interface joins the exempt set. If `ap.Start` fails, remove the interface from the set again.
- (b) Remove the interface from the set when the AP stops. The unit has no `ExecStop` today; add one, or an equivalent teardown. Correct the I12 note in the DEV-net-f ASSUMPTIONS.md, which wrongly says removal opens the drop.
- (c) Admit only the interface the loader created as the AP, not every phy80211 interface.

Scope: `broker/netguard/` (set add and remove helpers), `broker/localui/` (only the `agentos_ap` loader wiring), `image/` (AP unit `ExecStop` and ordering), `tests/test_image.py`, ASSUMPTIONS.md of each touched package.

## Acceptance tests

Mark with `REQ: DEV-2`.

1. Netns test: with the AP stopped, the interface is not in `exempt`; a client on that interface cannot reach a box port (A14).
2. `ap.Start` fails after the add (fault injection): the interface is removed from `exempt`, and `agentos_ap` is loaded or the interface stays dropped.
3. Single-radio sequence: AP up, AP stop, interface joins a documentation-address "home" network; a host there cannot open a connection to any box port.
4. A second phy80211 interface that the loader did not create as the AP is not admitted.
5. Removing the interface on stop does not open the drop: the table stays loaded and the interface is filtered like any other.

Synthetic interface names and documentation addresses only. Do not edit SPEC.md.

## Handoff and estimate

Predicted tier A. Initial checkpoint: 35k tokens, an estimate rather than a ceiling. Run affected Go packages with race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen. One package per session.
