# CODEX-1: Intake of Codex drafts for implementation

Board section: Harness and operating model.

**Decision (Mark, 2026-10-09):** Codex has no lane; it writes drafts for other teams to implement. Drafts with useful work stay open. This records package turns the useful drafts into briefs and BOARD rows and lists the rest here so nothing is lost. No runtime change; tier C.

## Accepted for implementation (rows queued in this PR)

| Row | Source draft | Tier | Builder |
|---|---|---|---|
| CI-SOAK-f1 | #255 | A | strongest |
| H8 | #273 | A | strongest |
| UX4-1, UX4-2 | #417 | A | strongest |
| UX3-1, UX3-6, UX3-7 | #405 | A | strongest |
| W5-Da | #263, #266, #267 | B | Sonnet (pilot) |
| S8-W1a | #262 | C | Sonnet (pilot) |
| H6 | #258 | C | Sonnet (pilot) |

The UX review documents and synthetic evidence from #405 and #417 are imported as they stand, because the briefs cite them. The remaining UX3/UX4 briefs stay in those drafts.

## Held (draft stays open; promote by writing its row)

| Item | Draft | Why held / next step |
|---|---|---|
| UX3-2..5, UX3-8..12 | #405 | Proposed release; promote one at a time once UX3-1/6/7 land. UX3-4 also gates UX4-1 acceptance 6 |
| UX4-3..6 | #417 | UX4-3/4 need an L1 design gate; UX4-5 needs UX3-1; UX4-6 is an acceptance extension |
| ARCH1-1, ARCH1-2 | #447 | Architecture proposals; L1 decides before any brief |
| POT-P3a, POT-P5, POT-P6 | #387, #390, #388 | Need H6; #387's broker job fails `TestNoThirdPersonSelfReference` (daemon.go:162) |
| INT-A | #261 | Needs H6 evidence |
| W7-A | #264 | Needs H6; W7 is blocked (LATER.md) |
| W5-Db (digest sources, D4–D8), W5-Dc (owner outbox, D12–D28) | #263→#435 stack | Follow W5-Da; D29–D67 (pacing-lease self-hardening) wait for a defect that needs them |
| SUB-2, SUB-3 | own drafts | Parked on CAP-14 / #328 |
| S5-R | #259 | claude2's lane (docs/LANES.md); handed to them |
| H4, H5, H7 | own drafts | Codex workflow tooling; not needed by this repo's lanes |

## Process findings on the drafts (class: release, here)

Rows were self-added rather than claimed; bases ran 50–205 commits behind main; the W5-D PRs label themselves tier B where `risk_tier.py` prints A for their owner/daemon parts; older drafts link no L3 verdict. Builders of the rows above start from current main and run their own fresh L3.

**Needs:** —
