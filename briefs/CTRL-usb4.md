# CTRL-usb4: M6 Ultra spike: USB4 networking at line rate

**Owner:** primary lane (unclaimed).
**Priority:** later (G7, A17). **Class:** later. **Implementation risk:** tier C (predicted; run tools/risk_tier.py).
**Requirements:** HW-12
**Acceptance tests:** test 1 below, scored by `spikes/CTRL-spike/check.py` (`tests/test_ctrl_spike.py`, `Usb4Tests`).
**Dependencies:** G1 passed; Mark: hardware (M6 Ultra unit and a second machine with USB4); a measured limitation USB4 solves (D-104).

## Finding

Split from CTRL-spike (briefs/CTRL-spike.md) on 2026-11-01 under D-104: USB4 networking for workstations (HW-12) serves the breadth staged after G1 (A17, G7), so it runs when it solves a measured limitation, not before the first install.

## Scope

`spikes/CTRL-spike/` (the `usb4` probe and its RESULT.md line). No product code. Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. USB4 networking carries port 2 traffic between the box and a second machine at line rate for 60 s (HW-12): `probe.py usb4 --server <peer>`, then `check.py` prints PASS.

Failure path: the spike fails on the unit and HW-12's USB4 alternative needs rework. List that on the findings.

## Handoff and estimate

One sitting with the unit; initial checkpoint 20k tokens, an estimate rather than a ceiling.
