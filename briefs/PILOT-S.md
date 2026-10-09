# PILOT-S: Sonnet builder pilot

Pilot: tier B and C builder sessions run on Sonnet 5.5 from 2026-10-08 through the 2026-10-13 reset; tier A stays on the strongest model (DECISIONS D-048, D-060; docs/OPERATING.md §5 has the procedure).

**Measures:** first-pass L3 accept, L3 rounds per merged PR and `Defect:` lines within 7 days of merge, for PRs merged in the pilot against those merged the week before 2026-10-08, counted by hand from each PR's `Builder model:` line; usage per merged PR from METRICS.md, the 2026-10-11 week against the 2026-10-04 week.

**Decision rule:** keep Sonnet for tier B/C if no measure is worse; otherwise revert.

**Done:** a DECISIONS row keeping or reverting, with the figures.

**Needs:** the 2026-10-13 reset
