## Package
<!-- BOARD.md ID, one line on what this does, and the requirement IDs it covers (CI's trace check shows their tests) -->

## Risk tier
<!-- A, B or C from `python3 tools/risk_tier.py --git origin/main HEAD` (docs/OPERATING.md §3); CI also prints it in the step summary -->

## Findings
<!-- Every finding raised on this package, one line each: blocker (fixed here) / release (new work-item issue, `class:release`) / later (new issue, `class:later`). "None" if none. Answer each review finding with a line `Finding <blocker|release|later>: <fixed|wrong|intentional|didn't-matter>` in a PR conversation comment, not an inline review-thread reply (METRICS.md counts only conversation comments as review noise). -->

## Before / After
Before:

After:

## Defect
<!-- If this fixes a defect in code that was already merged, add one line per package, e.g. `Defect: P1-3` (counted in METRICS.md). Otherwise delete this section. -->

## Reuse
<!-- Components reused; for anything new, why reuse didn't fit -->
