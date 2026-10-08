# LEDGER

Manual usage readings from Mark's usage screen: the only hand-kept input to METRICS.md (`tools/metrics.py` reads the tables below; keep their headers). Figures from the outside cost routine that drive a decision are copied here with a date. The budget rules themselves are CLAUDE.md §Budget, with reasons in docs/OPERATING.md §1 and §5.
Unit: WAU = one week's plan allowance.

## Calibration readings (from Mark's usage screen)

| Date (local) | Session window | Weekly, all models | Weekly, Fable only | Note |
|---|---|---|---|---|
| 2026-10-04 10:58 | 44% (resets in 51 min) | 14% | 11% | Week reset 06:00; mostly design work in the project thread |
| 2026-10-04 19:50 | 22% (resets in 1 h 59 min) | 23% | 11% | +9 points since 10:58: spikes' review fixes, lens reviews, arbitration, spec PRs, PR reviews, P0X, P1-1/2/5; Fable flat |

## Weekly burn

| Week starting | Envelope | Harness used (est.) | Mark's own use | Notes |
|---|---|---|---|---|
| 2026-10-04 | ~100% at reset (Mark, 23:55) | 23% measured on day one (19:50 Sunday; week reset 06:00 Sunday); ≈ 160% if sustained. Pace: ~14%/day, spread evenly so the limit isn't hit early; day one is ahead, so the next days run lighter (PLAN.md §4B) | included in the 23% | P0 start; P0 exit prep (spec v0.12) included. S3 (cloud): ~0.22 M tokens by session counter, incl. review fixes; WAU share awaits Mark's screenshot (B-6). S4: ~0.5 M tokens of context (est., unmetered), incl. review fixes; see its RESULT.md. S7: ~0.25 M tokens of context (est., unmetered); see its RESULT.md |

## Phase allocation (share of total)

| Phase | Share | Spent |
|---|---|---|
| P0 | 10% | ≤ 0.23 WAU measured (19:50 reading; includes the design session and early P1) |
| P1 | 25% | — |
| P2 | 30% | — |
| P3 | 20% | — |
| P4 | 5% | — |
| Reserve | 10% | — |
