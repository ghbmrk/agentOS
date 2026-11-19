# IMG-offline-verity-follow: the verity row's cells and scope; import_sweep fails on EIO

Board section: Devices, hardware and image (SPEC §13-14). Work item #5988, release findings 1 and 2 from the L3 and Potency reviews of PR #5945 (row #4825) at head b8f67f6f.

**Problem, checked on main 8cdc64ef:**
1. `image/ASSUMPTIONS.md` row IMG-offline-verity-1 has 2 cells where the table has 4 (no "Spec basis", no "If it changes"), and claims more than the code checks: `offline_systemd.built_tree` takes the root hash from the boot entry in the same OUT directory as `usr.raw` and `usr-verity.raw`, so a step that rewrites all three together still passes.
2. `image/import_sweep.py` `is_elf` turns every `OSError` into "not ELF". A /usr block dm-verity refuses reads as EIO, so an ELF file whose first block was rewritten after `finish_image` is skipped, not failed, which contradicts the row's claim that such a block fails the check.

**Requirements:** UPD-1a (an IMG record states what the check proves), EVL-5 (the sweep reads the built tree, and a clean result is not a scan that read less).

1. The row has all four cells: Spec basis UPD-1a; If it changes names a runner without `dm-verity` or `cryptsetup-bin` and a renamed image, hash tree or entry. Its text states that the anchor is the entry's `usrhash=` as found in OUT, what that proves, and what it rests on (no `image.yml` step writes OUT between the build and the checks).
2. `is_elf` returns False only when the file is gone (`FileNotFoundError`); any other `OSError` ends the run with `import sweep: cannot read PATH: REASON`.

**Scope:** `image/import_sweep.py`, `tests/test_image_import_sweep.py`, `image/ASSUMPTIONS.md`, this brief.

**Acceptance tests:**
- EVL-5: `tests/test_image_import_sweep.py::ReadErrorTest::test_eio_fails_the_run_naming_the_file`. EIO on open exits naming the path and the error. Catches the swallowed EIO.
- EVL-5: `ReadErrorTest::test_eio_in_the_walk_fails_the_tree`. EIO on one file of a walked tree fails `run_tree`. Catches a fix in `is_elf` that a caller swallows.
- EVL-5: `ReadErrorTest::test_vanished_short_and_plain_files_are_not_elf`. A vanished file, a 2-byte file and a script are not ELF; a 4-byte magic is. Catches an over-wide failure.
- UPD-1a: `grep "^| IMG-offline-verity-1" image/ASSUMPTIONS.md | awk -F'|' '{print NF}'` prints 6.

**Guard files:** none.

**Dependencies:** none. Open PR #5964 edits `image/import_sweep.py` at lines 277-345 only (the [cipher] reader); this row edits `is_elf` (line 151). #5980, #5985 and #6040 append other rows to `image/ASSUMPTIONS.md`.

**Tier / gate:** tier A (`tools/risk_tier.py` prints A for `image/import_sweep.py`). L3 on the strongest model, plus the lens screen and, as a tier-A PR, a separate Security accept (`premerge.py --needs-mark` prints `agent`: no gate file).

**Usage estimate:** one session, about 40k.
