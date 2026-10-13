# CTRL-text: Drive-era text and A8 reworked for the internal-SSD controller; risk 26 and §8.1 step 5 wording

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier B (predicted; run tools/risk_tier.py).
**Board section:** Controller and helper system (D-102).
**Requirements:** A8, HW-8, HW-8a, HW-6, ONB-7, REC-4
**Acceptance:** A8.
**Dependencies:** —

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. Stale drive wording remains in HW-8 ('AgentOS Drive'), HW-8a, §3.1 item 3, §3.3 and HW-6 (integrated key), risk 1, A8, ONB-7 (the card as quick-start manual) and REC-4 ('kits'). A8 still moves a drive to an unknown PC.

## Scope and intended change

An L1 spec-diff PR to `SPEC.md` (Mark approves, D-069/D-077), `decisions/D-102.md`, DECISIONS.md. No code.

Rewrite A8 to run against the internal-SSD controller and a moved-SSD host; replace the drive wording named above; fix §17 risk 26 ('stop a tampered image') to match CTRL-uki; reword §8.1 step 5 'tear off the recovery sheet' for an owner who saved the card; align D-102.md with the D-044 row ('narrowed by D-102') and state whether HW-11's short-lived mTLS keys are memory-only. SPEC.md changes only through this PR.

Do not edit SPEC.md except through the L1 spec-diff PR this row is; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A8 passes against the internal-SSD controller and a moved-SSD host, and fails if the controller step is skipped.
2. `rg 'AgentOS Drive' SPEC.md` finds none outside the history rows.
3. doclint and trace stay green.

Failure path: A8 runs against drive-only steps that no longer exist and passes without exercising the controller.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 40k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
