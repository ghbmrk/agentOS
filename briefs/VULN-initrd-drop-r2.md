# VULN-initrd-drop-r2: The initrd drop's tests catch its mutants, and its messages name what to edit

Board section: release items of VULN-initrd-drop (#5051, #4927). SPEC EVL-5. Issue #5054.

**Sources:** the release findings on #5051: L3 6703942154 (1), Potency 6703943243 (1-3), UX 6703944154 (1-3).

**Requirement IDs** (the builder writes the failing test first):
- **EVL-5** (SPEC): the initrd's known-vulnerability scan sees the initrd's packages as purged.
- **R2-1** (Potency 1): a test runs initrd mode on a tree that holds every INITRD_FILES path, with INITRD_FILES unpatched, and checks each path is gone. Catches `files = ()` and a path dropped from INITRD_FILES.
- **R2-2** (Potency 2): a test pins the INITRD_DROP package set, not only its sources. Catches `login.defs` or `p11-kit-modules` removed from INITRD_DROP.
- **R2-3** (Potency 3): the no-`$BUILDROOT` test asserts on the `$BUILDROOT` guard's own message, not on any exit.
- **R2-4** (UX 1): in initrd mode every problem line starts `initrd:`, and a stale-list line names the list to edit in that mode: INITRD_FILES, or PERL_TOOLS as filtered to the initrd's packages.
- **R2-5** (L3 1, UX 2): an argument that is neither an existing directory nor mkosi's `final` is refused with a message naming it; more than one argument is refused. `final` and no argument still select initrd mode on `$BUILDROOT`.
- **R2-6** (UX 3): the `VULN-initrd-drop` row of `image/ASSUMPTIONS.md` says what shows if mkosi stops following the postinst link: vulncheck's "no initrd holds … rebuild it" line, which then misleads, since a rebuild does not fix it.

**Design constraints:** no change to what is purged or checked; only the argument handling, message text and tests change.

**Acceptance tests:**
- R2-1: `tests/test_image_drop.py::InitrdTest::test_the_initrd_files_go`.
- R2-2: `tests/test_image_drop.py::InitrdTest::test_every_source_the_issue_names_goes` (package set pinned).
- R2-3, R2-5: `tests/test_image_drop.py::InitrdTest::test_a_tree_argument_is_the_main_tree_and_nothing_is_refused`, `::test_an_argument_that_is_not_a_tree_is_refused`.
- R2-4: `tests/test_image_drop.py::InitrdTest::test_initrd_problems_say_initrd_and_name_its_lists`.
- R2-6: reviewed text (no test).

**Scope:** `image/mkosi/drop.py`, `tests/test_image_drop.py`, the `VULN-initrd-drop` row of `image/ASSUMPTIONS.md`; this brief.

**Gate:** tier A (`tools/risk_tier.py` on `image/mkosi/drop.py`): L3 on the strongest model, Security if `premerge.py --needs-mark` prints `mark`, UX for the changed messages.

**Estimate:** under 60k tokens.
