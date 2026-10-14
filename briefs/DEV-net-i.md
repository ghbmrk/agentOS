# DEV-net-i: The access point loader's start-up cleanup covers every wireless interface

**Owner:** primary lane.
**Priority:** release. **Class:** release. **Implementation risk:** tier A (firewall, home-network boundary).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2
**Acceptance:** A14 (a home-network host cannot open a connection to any box port).
**Dependencies:** DEV-net-h merged (#1079).

## Finding

Found in PR #1079's tier A review (comments 6122381146 and 6122829533), release finding R2. Invariant: A14 / DEV-2 "In".

Failure path: a loader dies with the access point up on `wlan2` (a USB radio, a renamed radio, a changed config), so `wlan2` is in the inbound exempt set and `agentos_ap` is loaded for it. The next loader runs `APLoader.Start("wlan0")`. `BringDown(wlan0)` unloads `agentos_ap` whatever interface it holds, so `wlan2` stays exempt with no table and every box port is open to its network.

## Row DEV-net-i

After `APLoader.Start`, no interface is in the exempt set without `agentos_ap` holding it, and no `Up` can make one so. Agent-machine links, which also live in `netguard.Inbound.Exempt`, are untouched. Fix candidates from the review: `Start` takes its list from the host's `phy80211` interfaces; the teardown removes every wireless element of `exempt`; or `BringDown` unloads `agentos_ap` only when its drop line names the interface.

Scope: `broker/localui/` (`apexempt.go`, `aploader.go`, tests, `ASSUMPTIONS.md`), BOARD.md (this row and the P2-1 row's loader obligation).

## Acceptance tests

Mark with `REQ: DEV-2, DEV-net-i`. A test that `Start` with a stale exemption on an unnamed radio leaves no interface exempt without `agentos_ap`, plus fault injection for a failed tear-down of that radio and an unreadable `agentos_ap`. Synthetic interface names only. Do not edit SPEC.md.

## Handoff and estimate

Predicted tier A. Race tests for `broker/localui` and `broker/netguard`, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.
