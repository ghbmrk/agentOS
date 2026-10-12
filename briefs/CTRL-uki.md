# CTRL-uki: Preloaded self-check rooted in signed code, so a seller's modified initrd cannot pass its own check

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-10, HW-5a
**Acceptance:** A1.
**Dependencies:** CTRL-claim, P2-1

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. On a preloaded box the 'verifies its own image' check runs from seller-writable code and Secure Boot does not cover the initrd (PR #1054 L3 release finding). Risk 26 in SPEC §17 says the check 'stops a tampered image', which this does not support.

## Scope and intended change

`image/` (boot chain: signed unified kernel image or equivalent), the first-boot verifier, `tools/hostcheck.py` stand-in, tests, ASSUMPTIONS.md.

Choose one and record it in ASSUMPTIONS.md: (a) boot a signed UKI whose measured contents include the verifier, with the vault and claim secrets bound to that measurement; or (b) at claim, re-flash from the signed release and discard the seller's image. Either way the check is rooted in code the project signed.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A box whose initrd or kernel command line was modified refuses to claim and generates no secret (modified image fixture, synthetic).
2. A box with the signed image claims normally.
3. Secrets generated at first boot are unreachable from a differently signed boot path (extends the CRED-8 boot-path test).

Failure path: A modified initrd passes its own check and sends out the secrets generated at first boot.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 100k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
