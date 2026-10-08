# Combined lens pass (tier B)

Tier B PRs get one combined Security, Potency and UX pass in the batched lens screen (docs/OPERATING.md §4). Each verdict is `YYYY-MM-DD-pr<N>.md` in the L3 format, with one section per lens, each applying that lens's README. Conflicts between the lenses are settled under `reviews/arbitration/README.md`.

## Records

Per-PR and per-bundle records are the files `YYYY-MM-DD-*.md` in this directory, in filename order, so there is no run number to pick. Each opens with a `Record:` line giving PR, package and head SHA; `tools/doclint.py` checks it on files dated 2026-10-09 or later. Nothing is appended to this README, so open PRs do not conflict on it (DOC-4, docs/OPERATING.md §4).
