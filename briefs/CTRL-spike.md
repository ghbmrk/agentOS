# CTRL-spike: M6 Ultra spike: USB-stick boot with no key press

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier C (predicted; run tools/risk_tier.py).
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-13
**Acceptance:** A1.
**Dependencies:** Mark: hardware (M6 Ultra unit)

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. The merged text rests on facts about the ordered mini PC that nobody has measured. This row keeps the one A1 rests on: it boots a flashed stick with no key press (HW-13). USB4 networking (HW-12) moved to row CTRL-usb4 ([brief](CTRL-usb4.md)), after G1 (A17, D-104). The Wi-Fi access-point spike (CH-7) is retired: the core never turns Wi-Fi on (D-178).

## Scope and intended change

`spikes/CTRL-spike/` (scripts, results), `spikes/README.md` if it lists spikes. No product code.

Run the spike on the unit Mark ordered on 2026-10-11 and record per-model results. A failure is a result, not a defect: it names the text that needs rework.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. The box boots a flashed USB stick with no key press (HW-13).

Failure path: the spike fails on the ordered unit and the dependent text (HW-6 recipes) needs rework. List that on the findings; do not edit SPEC.md.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 40k tokens, an estimate rather than a ceiling. If it will not finish under 150k, say so on the row's issue.
