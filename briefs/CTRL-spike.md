# CTRL-spike: M6 Ultra spikes: USB-stick boot with no key press, USB4 networking, Wi-Fi access-point mode

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier C (predicted; run tools/risk_tier.py).
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-13, HW-12, CH-7
**Acceptance:** A1.
**Dependencies:** Mark: hardware (M6 Ultra unit)

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. The merged text rests on three facts about the ordered mini PC that nobody has measured: it boots a flashed stick with no key press (HW-13), USB4 carries port 2 traffic (HW-12), and its Wi-Fi radio runs as an access point (CH-7).

## Scope and intended change

`spikes/CTRL-spike/` (scripts, results), `spikes/README.md` if it lists spikes. No product code.

Run the three spikes on the unit Mark ordered on 2026-10-11 and record per-model results. A failure is a result, not a defect: it names the text that needs rework.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. The box boots a flashed USB stick with no key press (HW-13).
2. USB4 networking carries port 2 traffic between the box and a second machine at line rate for 60 s (HW-12).
3. The radio serves an access point a phone joins and keeps for 10 minutes (CH-7).

Failure path: Any of the three fails on the ordered unit and the dependent text (HW-6 recipes, HW-12 USB4 alternative, CH-7) needs rework. List that on the findings; do not edit SPEC.md.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 40k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
