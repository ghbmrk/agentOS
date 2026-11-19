# MOR-setup-isolate: keep the staged page authority across an isolate

**Source:** issue #5858, release items 1 and 2 from the L3 review of #5844 (MOR-setup-hold, #5836), comment 6897170147. Risk tier A. **Requirements:** HW-1, CH-9 (the fingerprint the printed Owner Card carries is the authority enrollment stores), HW-8 (an orderly shutdown before enrollment still clears MOR).

## Problem

Since MOR-setup-hold, `agentos-keeper-pageca.service` removes the staged page-CA pair and certificate in `ExecStopPost`. `RefuseManualStop=yes` refuses a direct stop, but not an isolate: `systemctl isolate rescue.target` (or `emergency`, or `default` from either) stops every unit the new target does not pull in. Back in multi-user, the next confirm pulls pageca in again through enrollment's `Wants=` and stages a new authority, so the card already printed carries a fingerprint enrollment never stores. Separately, the unit header's "A rerun publishes a pair a crash left" is stale: a failed start runs `ExecStopPost`, so a rerun always stages a fresh pair.

## Decision

The issue offered two options: the owner page detects a changed certificate and asks for a reprint, or accept and document. A third removes the failure path instead of reporting it: `IgnoreOnIsolate=yes` on the pageca unit, so an isolate leaves it active and its pair in place. Shutdown is unaffected: poweroff, reboot, halt and kexec stop units through `Conflicts=shutdown.target` (default dependencies, which the unit keeps), not through isolation, so the pair still goes before agentos-mor's clear (HW-8, `tests/test_image_mor.py::test_the_staged_page_authority_goes_at_stop`). The unit holds no process (oneshot, `RemainAfterExit=yes`), so staying active in rescue or emergency keeps only two root-only tmpfs files that rescue or emergency would not otherwise touch. This needs no owner-page change and no new state.

The remaining stop paths are then shutdown and a unit that stops pageca through a dependency (`Conflicts=` naming it, or pageca holding `BindsTo=`, `PartOf=`, `Requires=` or `Requisite=`). The test pins that no image unit has one.

## Scope

`image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-keeper-pageca.service` (the setting and the header comment), `tests/test_image_mor.py` (the test), this brief. Out of scope: `image/ASSUMPTIONS.md` (open PR #5932 touches it, D-111; the assumption is recorded in the unit header and here), the owner page, #5843 (MOR-setup-factors).

## Acceptance tests

**Acceptance tests:** HW-1, CH-9: `tests/test_image_mor.py::MorUnitTest::test_an_isolate_keeps_the_staged_page_authority`, which fails if pageca loses `IgnoreOnIsolate=yes` or default dependencies, or if any image unit gains a dependency that stops pageca besides shutdown. HW-8: the existing `test_the_staged_page_authority_goes_at_stop` still passes. Item 2 is a comment only: none.

## Assumptions

1. systemd's isolate skips units with `IgnoreOnIsolate=yes` (systemd.unit(5); `transaction_add_isolate_jobs` in systemd's `src/core/transaction.c`), and shutdown stops them through their `Conflicts=shutdown.target`. If systemd changes either, the card-fingerprint guarantee or the MOR clear breaks; the test pins only the unit text, so a systemd upgrade that changes the semantics needs a box run (boxe2e) to catch.

## Checkpoint

Small: about 40k tokens; an estimate, not a ceiling.
