# CTRL-card: First-boot Owner Card: the box generates it, the phone shows it, the display copy is erased

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-1, REC-4, ONB-7
**Acceptance:** A1.
**Dependencies:** P2-2

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. The merged HW-1 makes first boot generate every Owner Card, shows it on the phone to print or save, asks for one passphrase word and one recovery-key group, and erases the display copy. Today the card is produced as a pair with the drive.

## Scope and intended change

`broker/ownercard/` or its successor under `broker/localui/`, the first-boot path in `broker/firstboot/`, tests, ASSUMPTIONS.md.

Generate card contents on the box at first boot; serve them to the paired phone once; verify the confirm step (one passphrase word, one recovery-key group); then erase the display copy, so no card text remains in the page state, on disk or in logs. Recovery-key rotation (REC-4) uses the same flow. Warn about screenshots; offer print first.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. After the confirm step, no card text remains on the box's disk or in logs (synthetic canary words in the passphrase and recovery key; scan the whole image partition and the journal).
2. Without a correct confirm, the display copy stays and the box does not finish setup.
3. Two boots of the same image produce different cards (the image holds no per-owner secret, HW-1).

Failure path: The card persists after confirmation, or a seller-known value appears in it.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
