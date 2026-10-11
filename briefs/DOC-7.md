# DOC-7: LATER records sweep (docs and tooling rows)

Done at the coordinator's request on 2026-10-09, **a deviation from D-048** (LATER rows are held until the first release). The PR does not merge until the owner confirms the exception. No SPEC IDs; the requirement IDs below are this brief's own.

**Needs:** DOC-2, DOC-4

**Scope:** `LATER.md`, `tools/doclint.py`, `tests/test_doclint.py`, `docs/OPERATING.md` §2 and §4 step 1, `reviews/{security,potency}/README.md`, `briefs/OSS-10w2.md` (one line), this brief and its BOARD row.

## Rows and acceptance

| Row | Action | Check |
|---|---|---|
| DOC-2 f1 | doclint: Decision cell over 300 characters must link `decisions/D-NNN.md`; links resolve | DOC7-1 |
| W3-forget-b f1 | doclint flags `**State:**` in briefs; the one existing line (OSS-10w2) removed | DOC7-2 |
| DOC-4 f1 | Record accepts `PR none · package none · main <sha>` | DOC7-3 |
| DOC-4 f2, f3, f7, f8 | dated names in lens dirs; Record line directly under the title; lens dirs found on disk, tracked files only in git; "lowercase hex" message | DOC7-3, DOC7-4 |
| DOC-4 f5, f6 | "Requested reviews" pointer in the security and potency READMEs; one-command run index in OPERATING §4 step 1 | doclint passes |
| OSS-6s-a f4 | OPERATING §2 line: Findings names the LATER rows a PR removes | doclint passes |
| APPLY-dup | already fixed: `broker/apply/ASSUMPTIONS.md` has A1–A8 once each (DOC-4 duplicate-ID check); row removed | DOC7-5 |
| CRED-5 f6 | no second D-061 in DECISIONS.md or `decisions/`; row removed | DOC7-5 |
| P2-2a f1 | merged per BOARD (#329); row removed | — |

Left in LATER.md: DOC-3 f1 (inferred rows not recorded, shallow history), DOC-3 f2 (waits on the license), DOC-4 f4 (open PR #430 appends U16 to the same file). New later row DOC-7 f1: D-062 exceeds 300 characters unlinked, so doclint exempts it.

## Requirements

1. DOC7-1: decision length/link check. 2. DOC7-2: `**State:**` flag. 3. DOC7-3: Record forms. 4. DOC7-4: lens directory handling. 5. DOC7-5: the repository passes `tools/doclint.py`.

**Estimate:** under 60k tokens.
