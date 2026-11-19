# REV-PROOF-corpus-b: a systemd differential test for the image tree check's unit rules

Board section: Process and tooling. Work item #4916, split from #4910 (REV-PROOF-corpus), whose part a merged as #4917. Mark approved it ("Okay do this", cmsg_01R91wiieBzMSvPKFsAJVvuKRqEUAB62BA47C18Um22nWj). #4907 has merged, so the reference diffs already run the image's own systemd through `image_tool()` and `AGENTOS_REFERENCE_ROOT`.

**Problem:** several of `image/mkosi/mkosi.finalize`'s unit rules model how systemd reads a unit tree, and each was proved only by hand-written cases. In #4264, two reviewed heads passed their own tests and still misread systemd. At 45a3b20fc4, Security found that the check read only the clerk's own slice and not every parent's `IPAddressAllow=`, and that it took a socket's `Service=` literally even when that value held a specifier. At 104e10d140, it refused every specifier where systemd's reading names a safe unit, and it missed `user@` instances. Today, `SystemdDiffTest` compares only file lists (`cat-config`) with systemd.

**Requirements:** DEV-2, CH-9 (the tree check's claims about the image), with REV-PROOF's aim that a rule which models another program is checked against that program.

1. For each rule below, build synthetic unit trees in a scratch root and compare the rule's verdict with what the image's own systemd reports. Use `image_tool(self, "systemd-analyze")`, never the runner's copy. Which subcommand serves as the oracle (`cat-config`, `unit-files`, `unit-paths`, `verify --root`, or `--man=no --generators=no` variants) is the builder's choice for each rule, and is recorded in the class docstring.
   - The ancestry of a slice's `IPAddressAllow=`, through `parent_slices` and `slice_dropins`, which feeds `clerk_key_violations`.
   - A socket's `Service=`, including specifiers (`may_name`, `specifier_reaches`).
   - Empty or invalid assignments that reset a setting (`ini_all`, `ini_last`, and the 257.13 non-reset of `Sockets=`, `OnFailure=` and `OnSuccess=` noted near `UNLOCK_UNITS`).
   - `Sockets=`, `[Install] Alias=` and links in unit directories.
   - `User=`, `Group=` and `DynamicUser=` across drop-ins (`clerk_user_violations`, `KEEPER_USERS`).
2. Where the reference systemd cannot answer a case offline, skip it with a named reason. The class inherits `MustRun`, so under `AGENTOS_REQUIRE_REFERENCE_TOOLS=1` a skip fails, as the other reference diffs do.
3. Add the class to `ReferenceDiffsRanTest`'s tuple.

**Scope:** `tests/test_image_unit_diff.py` (new: corpus, oracle calls, tests), `tests/test_image.py` (only the import of the new class and the `ReferenceDiffsRanTest` tuple line), this brief. No edit to `image/mkosi/mkosi.finalize`. If the differential finds that a rule disagrees with systemd on main, that is a finding. Class it as a blocker if it is an exploit path, and otherwise as a release row. The fix does not go in this PR.

**Acceptance tests:**
- DEV-2: `tests/test_image_unit_diff.py::UnitDiffTest::test_rules_agree_with_systemd`, one subtest per tree, passes on main. Catches a rule whose model of systemd drifts.
- DEV-2: `tests/test_image_unit_diff.py::UnitDiffTest::test_differential_catches_first_round_shapes`. It loads the tree check with each of #4264's pre-fix shapes put back as a patched function (only the clerk's own slice read, `Service=` read literally, `user@` instances not refused), and each must disagree with systemd on at least one tree. Catches a corpus too thin to have caught #4264. In the PR body, also record a one-off run against `git show 45a3b20fc4:image/mkosi/mkosi.finalize`.
- `tests/test_image.py::ReferenceDiffsRanTest` lists the new class. Catches a differential that skips silently.

**Guard files:** none.

**Dependencies:** none open. Open PRs #5980, #5985 and #5991 edit `tests/test_image.py`. Under D-320 (#5956, open) that does not block the build: this PR changes two lines there and rebases if needed.

**Tier / gate:** `tools/risk_tier.py` prints C, because the PR touches only `tests/`. The row is labelled tier A because what it proves are `image/` rules, so L3 runs on the strongest model, as #4916 asks. `premerge.py --needs-mark` decides whether a Security accept is owed.

**Usage estimate:** one session, about 90k.
