# MET-1: Metrics measure matching periods; held drafts and open PRs per lane

Board section: Owner-benefit review (2026-10-09). Finding from the 2026-10-09 owner-benefit review (point 6): METRICS.md reads "Data as of 2026-10-05 01:03 UTC", so its "12% (3/26)" first-pass rate is four days old, and its usage-per-requirement ratio divides one usage reading by a requirement count taken at a different time.

**Tier:** C (no workflow edit since the 2026-10-12 narrowing); run `tools/risk_tier.py` and follow what it prints. About 30k tokens.

**Narrowed 2026-10-12 (waste review).** CONV-0 (#632) made `metrics.yml` run daily, so MET-1c is done. MET-1d (a no-per-PR-usage statement) is dropped as low value. WIP-1's follow-up is folded in as MET-1e.

**Needs:** CONV-0 (merged).

## Today (`tools/metrics.py`)

- Weeks start at the plan reset (Sunday 06:00 local, `week_start`). That is already aligned.
- `reqs` (l.273-275) is TRACE's covered count at the last snapshot before the week's **end**, minus the count before its start.
- `usage_all` (l.277-279) is the **highest** reading inside the week, taken at whatever time Mark last recorded one. For the current week the two figures cover different spans: requirements up to now, usage up to the last ledger reading. `usage_per_req` (l.312) divides them.
- `metrics.yml` runs weekly (Sunday 09:30 UTC) plus on demand, so mid-week the file is up to six days stale.
- Usage is not metered per package (METRICS.md, LEDGER B-6). Any per-PR or per-package usage figure is an allocation, not a measurement.

## Requirements (local IDs)

- **MET-1a, matched windows.** For each week, `usage_per_req` uses the requirement count at the time of the usage reading it divides by: covered at the last TRACE snapshot at or before that reading, minus covered before the week start. The table shows the reading's timestamp beside the ratio.
- **MET-1b, staleness is visible.** Each row whose newest input (reading, trace or board snapshot) is more than 36h older than "Data as of" shows the age. The current week is labelled with the reading time, not "(to date)".
- **MET-1c, refreshed daily.** Done by CONV-0; no change.
- **MET-1e, held drafts count (D-098).** `held_drafts` (l.141) and `stale_prs` (l.314) stop excluding CODEX-1 held drafts: a held draft is stale like any open PR. The table shows open PRs per lane (docs/LANES.md) against the cap of about 10.

## Tests (`tests/test_metrics.py`, written first)

- A week where the usage reading is on day 2 and a TRACE snapshot on day 5: the ratio uses the day-2 count.
- The staleness label appears when the newest input is older than 36h, and not otherwise.
- A held draft untouched for 48h is listed as stale; open PRs are counted per lane.
- The existing cases still pass, with expected values updated where MET-1a changes them (list each in the PR).

## Scope

`tools/metrics.py`, `tests/test_metrics.py`, and METRICS.md only through the tool's own output (never by hand).
