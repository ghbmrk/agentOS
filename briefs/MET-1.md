# MET-1: Metrics measure matching periods and stay current

Board section: Owner-benefit review (2026-10-09). Finding from the 2026-10-09 owner-benefit review (point 6): METRICS.md reads "Data as of 2026-10-05 01:03 UTC", so its "12% (3/26)" first-pass rate is four days old, and its usage-per-requirement ratio divides one usage reading by a requirement count taken at a different time.

**Tier:** C at 9b4bf8a. Once RT-1 merges, the `metrics.yml` cron edit makes the change A, so run `tools/risk_tier.py` and follow what it prints (the Sonnet pilot then hands off). About 40k tokens.

**Needs:** nothing.

## Today (`tools/metrics.py`)

- Weeks start at the plan reset (Sunday 06:00 local, `week_start`). That is already aligned.
- `reqs` (l.273-275) is TRACE's covered count at the last snapshot before the week's **end**, minus the count before its start.
- `usage_all` (l.277-279) is the **highest** reading inside the week, taken at whatever time Mark last recorded one. For the current week the two figures cover different spans: requirements up to now, usage up to the last ledger reading. `usage_per_req` (l.312) divides them.
- `metrics.yml` runs weekly (Sunday 09:30 UTC) plus on demand, so mid-week the file is up to six days stale.
- Usage is not metered per package (METRICS.md, LEDGER B-6). Any per-PR or per-package usage figure is an allocation, not a measurement.

## Requirements (local IDs)

- **MET-1a, matched windows.** For each week, `usage_per_req` uses the requirement count at the time of the usage reading it divides by: covered at the last TRACE snapshot at or before that reading, minus covered before the week start. The table shows the reading's timestamp beside the ratio.
- **MET-1b, staleness is visible.** Each row whose newest input (reading, trace or board snapshot) is more than 36h older than "Data as of" shows the age. The current week is labelled with the reading time, not "(to date)".
- **MET-1c, refreshed daily.** `metrics.yml` runs daily (one cron line). The commit job is unchanged.
- **MET-1d, no per-PR usage.** METRICS.md states that usage is per week only, and the tool emits no per-PR or per-package usage figure. Per-package cost stays the brief's estimate against the session counter, reported in the PR's Budget section.

## Tests (`tests/test_metrics.py`, written first)

- A week where the usage reading is on day 2 and a TRACE snapshot on day 5: the ratio uses the day-2 count.
- The staleness label appears when the newest input is older than 36h, and not otherwise.
- The existing cases still pass, with expected values updated where MET-1a changes them (list each in the PR).

## Scope

`tools/metrics.py`, `tests/test_metrics.py`, `.github/workflows/metrics.yml` (cron line only), and METRICS.md only through the tool's own output (never by hand).
