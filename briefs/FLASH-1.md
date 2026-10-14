# FLASH-1: Signed flasher for Windows, Mac and Linux: verify the signature, write the stick, show the pairing QR

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-10, HW-13, UPD-1, DEP-2
**Acceptance:** A1.
**Dependencies:** CTRL-claim

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. HW-10 names a signed flasher for the download path; none exists. The pairing QR is how the owner's phone pairs on that path (§8.1 step 4).

## Scope and intended change

`flasher/` (new, one small cross-platform program or one per OS), release signing in `.github/workflows/` only if the release workflow needs a step, tests, ASSUMPTIONS.md. Reuse an existing writer (for example Raspberry Pi Imager's or balenaEtcher's engine) unless the PR says why not.

The flasher downloads or opens the release image, verifies the project signature and the image hash before writing, writes the stick, and shows a one-time pairing QR whose secret pairs only the first phone. Model weights are not on the stick (signed manifest, HW-10).

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A tampered image or a wrong signature is refused and nothing is written.
2. A good image is written and its read-back hash matches.
3. The QR pairs one phone once; a second scan is refused.

Failure path: An unsigned or altered image is written to a stick, or the QR pairs a second phone.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 100k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
