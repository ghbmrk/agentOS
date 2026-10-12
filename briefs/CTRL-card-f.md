# CTRL-card follow-ups: wire the Owner Card, move rotation onto it, keep the passphrase out of dumps and swap

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A for each row (broker/card, first boot, image).
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-1, REC-4, ONB-7
**Acceptance:** A1 (HW-1 acceptance tests 1 and 2).
**Dependencies:** CTRL-card merged (ddb25b0, #1060).

## Finding

Found in PR #1060's tier A review (comment 6117322003, verdict accept, head 94cc904) and on its Findings line. The three release findings make this one brief, with one BOARD row each (OPERATING §2). Checked against BOARD.md on 2026-10-12: no queued row covers any of them. CTRL-claim assumes the card is shown at first boot but does not wire it.

The three rows are independent except that CTRL-card-rot and CTRL-card-wire both touch `broker/card` callers; build wire first, or rebase.

## Row CTRL-card-wire

Wire `firstboot.CardStep` and `card.Display.Handler` into the localui setup page and agentosd first boot, with the finish path calling `Hold()`.

- Failure path: a real first boot never shows the card and never holds setup, so HW-1 acceptance test 2 passes only in unit tests.
- Condition 1: mount the display inside localui's server, behind its Host check (`localui/server.go`, anti DNS rebinding) and the pairing check. Never a separate listener.
- Condition 2 (F10): the provisioner resets a half-made vault after a restart between provisioning and saving the latch, so a restart in that window ends with a clean first boot and a new card, not a vault the owner cannot open.

Scope: `broker/firstboot/`, `broker/localui/` (setup page and mount only), `broker/cmd/agentosd/` (first-boot call site), tests, ASSUMPTIONS.md of each touched package.

Tests (mark with `REQ: HW-1, ONB-7`):
1. Over localui's real server, a request with a foreign `Host` header gets the Host-check refusal on the card routes (no card text in the body).
2. A first boot through agentosd's setup path shows the card, and without a correct confirm `Hold()` returns `ErrCardPending` and the box does not finish setup.
3. Kill the provisioner between provision and latch save (fault injection); the next boot finds no half-made vault and shows a new card.

## Row CTRL-card-rot

Move `recovery.Pending`'s rotation display onto `card.Display`, so recovery-key rotation (REC-4) uses the same confirm-then-erase.

- Failure path: a rotation keeps the old display with no confirm-then-erase, so the new recovery key stays in page state after the owner has it.
- Scope: `broker/recovery/` (rotation display only), `broker/localui/` (rotation page), `broker/card/` only if `Display` needs a rotation constructor option, tests, ASSUMPTIONS.md.

Tests (mark with `REQ: REC-4, HW-1`):
1. Rotation shows a fresh recovery key; a wrong confirm keeps the display and the old key stays valid.
2. After a correct confirm, the display is erased (same checks as `TestDisplayConfirmThenErase`) and a partition scan with the A8 `recovery.Scanner` finds no key text.
3. The old `Pending` display path is gone (a grep or import test fails if it returns).

## Row IMG-nodump (security S1)

The image disables core dumps and keeps swap off or encrypted, with a check in `tests/test_image.py`.

- Failure path: agentosd or localui crashes, or swaps out a heap page, after the card was generated. The passphrase string, which cannot be zeroed in Go (card ASSUMPTIONS C13), lands in `/var/lib/systemd/coredump` or a swap partition. That breaks HW-1 acceptance test 1 and A1 on a real box.
- Change: systemd-coredump `Storage=none` plus `LimitCORE=0` for the card-holding service (and a `kernel.core_pattern` that discards), and no swap device or swap file, or swap only on an encrypted device keyed per boot. `finish_image.py` or `mkosi.finalize` fails the build if either is missing.
- Scope: `image/` (mkosi extra files, units, finalize), `tests/test_image.py`, image ASSUMPTIONS.md.

Tests (mark with `REQ: HW-1`):
1. The image tree carries `Storage=none` and the unit sets `LimitCORE=0`; removing either fails `tests/test_image.py`.
2. The image tree has no swap entry in fstab, no swap unit, and no swap partition in `mkosi.repart`, or the swap is on a `cryptsetup` device with a random key; a plain swap fails the check.

Synthetic values only. Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Handoff and estimate

Initial checkpoint: wire 60k tokens, rotation 40k, image 25k, each an estimate rather than a ceiling. One package per session; run Go packages with race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen for each PR. The `later` items from #1060 (U1, U2, wording) stay in LATER.md and are not part of this brief.
