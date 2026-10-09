# CONV-4: One batched spec diff, then scope freeze

Board section: Harness and operating model. Decision: D-086; spec diffs pending in D-067 (partly superseded), D-079, D-080, D-081, D-082, D-083. Tier B (SPEC.md). Builder: strongest model (L1 work); Mark approves.

**Why.** Six decisions name spec changes that have not landed, so briefs and tests target a moving SPEC.md, and each new requirement adds rows.

## Requirements

- **CONV-4-1** One L1 spec-diff PR applies every still-active spec change named in D-079 to D-083, and the part of D-067 no later row supersedes. Each SPEC.md hunk cites its D-row.
- **CONV-4-2** The PR lists each requirement ID added, changed or removed, and the BOARD rows and tests each affects; changed IDs' tests are listed for update in a follow-up row, not edited here.
- **CONV-4-3** SPEC.md gains one line under its scope section: after this diff, a new release requirement needs Mark's explicit promotion; review findings cannot add one.
- **CONV-4-4** `python3 tools/trace.py` runs clean (do not commit TRACE.md).

## Acceptance

Mark approves the PR (MARK-QUEUE Q2). A fresh L3 confirms each hunk matches its D-row and no other text changed.

## Scope

`SPEC.md`, `DECISIONS.md` (status of the D-rows applied), `docs/MARK-QUEUE.md`.
