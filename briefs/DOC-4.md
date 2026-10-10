# DOC-4: Per-file review records; no shared run tables

Almost every PR appended a row to the numbered run tables in `reviews/<lens>/README.md` (and often to LATER.md and BOARD.md), so each merge conflicted every other open PR, and two PRs could pick the same run number. Remove that shared-append point with the smallest change that keeps the information.

**Needs:** DOC-1, DOC-2

**Scope:** `reviews/*/README.md`, the `Record:` line of existing `reviews/*/2026-10-08-*.md`, `tools/doclint.py`, `tests/test_doclint.py`, `docs/OPERATING.md` §4 step 3, `LATER.md` summary line, `broker/update/ASSUMPTIONS.md`, this brief and its BOARD row.

## Design

- The run index is the record files themselves: `reviews/<lens>/YYYY-MM-DD-*.md`, in filename order. Lens READMEs keep the closed weekly runs (frozen rows, unchanged) and drop every row that later PRs appended.
- Each record opens (after its title) with one line: `Record: PR #N · package ID · head SHA`. A bundle lists several (`PRs #1 #2`, `packages A, B`, `heads x, y`); a record with no PR says `PR none`. This carries what the table did (PR, package, head); `main <sha>` may follow.
- `tools/doclint.py` fails a record dated 2026-10-09 or later in `reviews/{ux,potency,security,combined,arbitration}/` without that line. Older files are exempt, so PRs already open with a 2026-10-08 record are not broken; the existing 2026-10-08 files get the line here.
- Duplicate row IDs in any `ASSUMPTIONS.md` fail doclint. `broker/update/ASSUMPTIONS.md` has two U11 rows; the later one (staged releases) becomes U15 (U12 to U14 are taken). No other file cites it.
- LATER.md summary: counts were stale (Later says 57, table has 61) and any PR touching either table made them stale again, so they are removed rather than corrected.
- BOARD.md and LATER.md rows stay as they are. Rows already land in a package's own phase table or at one table end, and sorting or splitting them into per-section or per-file form would be a larger restructure than the saving justifies; recorded in the PR.

## Requirements (tooling; no SPEC IDs)

1. Record check: line present, with a PR (`#N` or `none`), a package, and a hex head SHA of 7 to 40 characters.
2. Record check ignores READMEs, pre-cutoff files, and other directories.
3. Duplicate ID in an ASSUMPTIONS.md table fails, naming file, ID and both line numbers.

**Estimate:** under 60k tokens.
