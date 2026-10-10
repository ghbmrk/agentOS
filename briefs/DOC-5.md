# DOC-5: doclint catches BOARD and LATER contradictions

Board section: Owner-benefit review (2026-10-09). Finding from the 2026-10-09 owner-benefit review (point 4): LATER.md:6 said P2-1 "has no board row" while BOARD had one, and BOARD said "in review (#41)" after #41 merged. The coordinator fixed both by hand in the records PR that opened this row. These checks stop it from recurring for the cases a PR gate can see. DOC-6 covers the case it cannot (merge state).

**Tier:** C (`tools/doclint.py`, tests). Sonnet-class builder. About 30k tokens.

**Needs:** nothing.

## Today

`tools/doclint.py` (DOC-2) checks BOARD state cells against `metrics.STATES`, brief links, the README docs table, OPERATING § references, review `Record:` lines, duplicate ASSUMPTIONS IDs and the brief token cap. `lint(root)` concatenates seven generator checks. It reads LATER.md for nothing.

LATER.md has three tables keyed by first-cell ID: `| ID | Needed for | Note |` (Release), `| ID | Why it can wait |` (Later) and `| ID | Component | Why |` (Reuse candidates). About 79 of its IDs are also BOARD IDs. **That overlap is by design** (LATER classes open BOARD rows), so sharing an ID is not an error.

## Requirements (local IDs)

- **DOC-5a, a LATER row whose BOARD row is merged or dropped.** For each first-cell ID in the Release and Later tables that is also a BOARD ID, an error if the BOARD state is `merged` or `dropped` (LATER's own summary says rows since merged are removed). IDs with a suffix LATER uses for findings (`<ID> l1`, `<ID> f1`, `<ID> c3 r3`) are matched on their own first cell only, so they are not checked against the parent.
- **DOC-5b, "no board row" claims.** An error when LATER.md prose or a table cell says an ID "has no board row" (or "no row of its own") and BOARD has that ID. The same check applies to BOARD.md's own prose paragraphs.
- **DOC-5c, duplicate BOARD IDs.** An error when two BOARD rows share a first-cell ID (one exists at 9b4bf8a; the builder finds it and fixes it in this PR, or the coordinator does if it needs a judgment call).
- **DOC-5d, blocked-on a merged row.** A warning-class error when a row's state says `blocked on <ID>` and `<ID>`'s BOARD state is `merged`. Report it as an error; doclint has no warnings, and the fix is a one-word edit.

## Tests (`tests/test_doclint.py`, written first, using the `GOOD` fixture pattern)

One failing and one passing case per requirement. Add the overlap case: a LATER row sharing an open BOARD ID passes. Add the suffix case: `X-1 l1` in LATER with `X-1` merged passes.

## Scope

`tools/doclint.py`, `tests/test_doclint.py`, and BOARD.md and LATER.md only for the errors the new checks find at the branch point (each fix listed in the PR).

## Not in scope

Merge state from GitHub (DOC-6). Rewriting LATER's audit.
