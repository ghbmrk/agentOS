# ASSUMPTIONS-ID: assumption row IDs that do not collide

Board section: Harness and operating model.

Extends ASSUMPTIONS-MERGE. The union merge keeps both appended rows but not their numbers: #2164, #1992 and #2209 each took the next `tools/ASSUMPTIONS.md` number, and #2015 did the same in `broker/egress` and `broker/journal`, so each cost a re-merge, a delta review and a new Mark tap.

Fix: a new row's ID is keyed by its package, `<PACKAGE-ID>-<suffix>` (`ASSUMPTIONS-ID-1`). Package IDs are unique per PR, so parallel PRs never pick the same ID and no merge needs renumbering. `tools/assumptions_ids.py` holds the rule; `tools/doclint.py` (already run by CI) calls it and fails any row that is neither package-scoped nor listed in `tools/assumptions_legacy_ids.txt`, a snapshot of today's bare IDs that only shrinks. Existing IDs are not renumbered, so no citation changes. The duplicate-ID check stays as the backstop.

**Needs:** none

**Acceptance tests:** `tests/test_doclint.py` (ASSUMPTIONS-ID-1 bare new ID rejected, legacy and scoped accepted; ASSUMPTIONS-ID-2 every bare ID on main is in the legacy list; ASSUMPTIONS-ID-3 parallel packages merge without a duplicate).

## Scope

`tools/assumptions_ids.py`, `tools/assumptions_legacy_ids.txt`, `tools/doclint.py`, `tests/test_doclint.py`, this brief. Tier C. In-flight PRs that append a bare row (#2164, #1992) must rename it to `<PACKAGE-ID>-<n>` once after merging main.
