# MOR-setup-factors: empty the held /run directories at shutdown

**Source:** issue #5843, release item from MOR-setup-hold (#5836). Risk tier A. **Requirements:** HW-8 (MOR may be left set only after a power cut or forced reset).

## Problem

`agentos-keeper-setup@.service` writes the Owner Card's two factors to `/run/agentos-setup` at the confirm; `agentos-keeper-enroll.service` removes them only on success and keeps them for a retry on failure (brief OWN-card-flow, "Enrollment fails"). The first edge's capture in `/run/agentos-link-capture` is kept the same way. Neither has a stop that removes it, so an orderly shutdown after the confirm and before a successful enrollment finds a `holdDirs` entry non-empty, `agentos-mor clear` refuses, MOR stays set, and the firmware wipes memory at the next start, which HW-8 does not disclose for an orderly end.

## Decision

Option (1) of the issue: a new keeper unit, `agentos-keeper-wipe.service`, oneshot with `RemainAfterExit=yes` and no process, whose `ExecStop` empties both `/run` holdDirs entries (`find ... -xdev -mindepth 1 -delete`, which also takes a hidden temporary a writer killed mid-write left; it follows no symlink). Emptying the directories, rather than listing files, makes the invariant the clear's own: whatever any unit writes there is gone. A reboot already discards these files (tmpfs) and starts the card over, so removing them at an orderly shutdown loses nothing the next boot had kept. Option (2), disclosing the case in `tools/hostcheck_hw8.json`, needs a spec decision and is not taken.

Ordering: default dependencies (After=sysinit.target), so it stops before `agentos-mor.service`'s clear. `Before=` pageca, enroll and link-capture, and `agentos-keeper-setup@.service` names it in `After=` (a `Before=` cannot name a template's instances; the socket cannot be ordered after it without a cycle through `sockets.target`), so each writer stops first. `WantedBy=` those writers as well as `multi-user.target`, so a writer started in another target pulls it in. `IgnoreOnIsolate=yes` and `RefuseManualStop=yes`: an isolate or manual stop would otherwise remove the staged page authority under a printed card (the #5858 failure, fixed for pageca by open #5941).

## Scope

`image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-keeper-wipe.service` (new), `agentos-keeper-setup@.service` (`After=`), `system-preset/50-agentos.preset`, `image/mkosi/mkosi.finalize` (`KEEPER_UNITS`), `tests/test_image_mor.py`, `tests/test_image_keeper.py` and `tests/test_image.py` (the keeper and device lists), this brief. Out of scope: `image/ASSUMPTIONS.md` P2-1-mor-1's wording (open #5932 touches that file, D-111; the assumptions are recorded here and in the unit header, and P2-1-mor-1 stays true as written), pageca's own `ExecStopPost` (kept; redundant with this stop), `agentos-mor` itself.

## Acceptance tests

**Acceptance tests:** HW-8: `tests/test_image_mor.py::MorUnitTest::test_every_held_file_goes_at_stop` (fails without the unit): the stop empties exactly `MOR_LISTED`; the unit keeps default dependencies, has no condition, no stop dependency and no drop-in, and is enabled; every unit whose text names a `/run` holdDirs path is found and ordered before it at stop; no unit names `/dev/shm`. `test_every_other_unit_stops_first` still passes.

## Assumptions

1. systemd stops units in reverse start order, so a unit `Before=` another stops after it; a oneshot with `RemainAfterExit=yes` and only `ExecStop=` is valid (systemd.service(5)) and is stopped at shutdown through `Conflicts=shutdown.target`. `systemd-analyze verify` (255) accepts the unit. The test pins the unit text, not a box run.
2. A writer that is not a unit file (a script run by hand on the box) is out of reach of this test; none exists in the image.

## Checkpoint

Small: about 60k tokens; an estimate, not a ceiling.
