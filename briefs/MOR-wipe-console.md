# MOR-wipe-console: keep agentos-keeper-wipe's errors off the console

**Source:** issue #6042, release item from MOR-setup-factors' UX verdict (#5991, carried by #6044). Risk tier A (image unit). **Requirements:** HW-8 (owner effort: recovery).

## Problem

`agentos-keeper-wipe.service` had `StandardError=journal+console`. If its `find` fails at shutdown, a line prints on the box console that the owner cannot act on; MOR then stays set (fail-safe), so the line is noise without a remedy.

## Decision

`StandardError=journal`; no `StandardOutput=` (the default, journal). The journal keeps the error for diagnosis.

## Scope

`image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-keeper-wipe.service`, `tests/test_image_mor.py`, this brief. Built on #6044's head (D-320 rule 3).

## Acceptance tests

**Acceptance tests:** HW-8: `tests/test_image_mor.py::MorUnitTest::test_every_held_file_goes_at_stop` pins `StandardError=journal` and no `StandardOutput=` on the wipe unit (fails on `journal+console`).

## Assumptions

1. systemd.exec(5): `StandardError=journal` sends stderr to the journal only, and the default `StandardOutput=` is the journal (`DefaultStandardOutput=journal`), so nothing from the unit reaches the console.

## Checkpoint

Small: about 30k tokens; an estimate, not a ceiling.
