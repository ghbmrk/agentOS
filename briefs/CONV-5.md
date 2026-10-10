# CONV-5: Triage and build against the 24 uncovered requirement IDs

Board section: Harness and operating model. Decision: D-086. Tier: per child row (`tools/risk_tier.py`). This package is the triage; builds are child rows. Builder for triage: Sonnet (PILOT-S). Usage estimate: 50k tokens.

**Why.** TRACE.md shows 135/159 IDs covered. The 24 uncovered (HW-3, HW-4, HW-6, HW-7, CRED-2, CRED-11, ONB-2, ONB-9, CAP-2, CAP-7, CAP-11, CAP-12, CAP-13, ADP-5, ADP-6, ADP-8, ADP-13, ADP-14, ADP-15, ADP-16, OSS-12, RES-5, UPD-7, UPD-9) decide when the first release can ship, yet no list says what blocks each.

## Requirements

- **CONV-5-1** `docs/conv-5-uncovered.md` classes each ID: **buildable now**, **stand-in** (testable against `tools/hostcheck_standin.sh`, the S1 test kit, or a VM fixture before real hardware), **environment-blocked** (needs a network host or account; name it), **hardware-blocked** (name the item), or **spec-blocked** (waits on CONV-4; name the D-row).
- **CONV-5-2** Each buildable or stand-in ID gets one queued BOARD row (or names the existing row) with acceptance test, failure path and tier.
- **CONV-5-3** Each environment- or hardware-blocked ID is added to docs/MARK-QUEUE.md under the action that unblocks it.

## Acceptance

All 24 IDs appear once; `python3 tools/doclint.py` passes; a fresh L3 checks five classifications against SPEC.md.

## Scope

`docs/conv-5-uncovered.md` (new, add to README documents table), `BOARD.md`, `docs/MARK-QUEUE.md`, `README.md`.
