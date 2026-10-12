# CTRL-claim: Claim flow for a preloaded box: a one-time sticker code, one claim, no secret before it

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-10, HW-1
**Acceptance:** A1.
**Dependencies:** CTRL-card

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. HW-10 says a seller ships only a claim sticker that unlocks nothing and dies at the first claim. No code implements the claim, the 'already claimed' refusal, or the rule that no secret exists before the claim.

## Scope and intended change

`broker/claim/` (new), `broker/localui/` claim screen, the first-boot path, tests, ASSUMPTIONS.md.

At first boot the box holds a claim code (printed on the sticker by the seller flow, or derived from a seller-written value; it unlocks nothing). The first phone to present it claims the box; the code is then burned. Later attempts get 'already claimed' and the owner reinstalls. Secrets (HW-1) are generated only after the claim. Rate-limit and journal attempts.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A second claim on a claimed box is refused with 'already claimed'.
2. Before the claim, a scan of the disk finds no vault key, card text or approval-code seed (canary).
3. A wrong code is refused and counted; N wrong codes lock the claim screen until the box is restarted by the owner.

Failure path: The sticker unlocks data, or a second phone claims the box.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
