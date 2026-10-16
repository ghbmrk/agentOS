# ASSUMPTIONS-MERGE: ASSUMPTIONS.md rows stop conflicting

Board section: Harness and operating model.

Two PRs that each append a row to the same `ASSUMPTIONS.md` conflict on the table's last line, and doclint then fails on a duplicate row number. Fix: `.gitattributes` marks `ASSUMPTIONS.md` files `merge=union`, so a local `git merge` keeps both appended rows; doclint's duplicate-ID check stays the backstop and the builder renumbers. GitHub's server-side merge and "Update branch" do not read `.gitattributes`, so the union rule covers the merges agents run locally only.

**Needs:** none

**Acceptance tests:** `tests/test_doclint.py` (a union merge of two appended rows, then the duplicate-ID check).

## Scope

New `.gitattributes`; `tests/test_doclint.py`. Tier C.
