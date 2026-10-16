# CONV-2 re-audit: stale queued and building rows (first pass)

Brief: [CONV-2](../briefs/CONV-2.md), tracked under issue #752. Snapshot: origin/main 69d8bdf3, 2026-10-16.

## Scope deviation (spec/brief gap)

The brief says to edit BOARD.md and LATER.md. Neither can be edited by a PR now: BOARD.md is generated from `work-item` issues (`tools/board.py`, `board.py check --repo` fails a hand edit) and LATER.md is retired (`board.py archive`; history in [LATER-HISTORY](LATER-HISTORY.md)). A row's state is its issue's `state:*` label and "later" is `class:later`. So the audit's outputs are label changes and closes on issues, not file edits. This file is the inventory; the label changes are listed under "Proposed issue changes" and are not yet applied (see Status). Class: **release** (CONV-2 brief needs its mechanics rewritten before the remaining sections are audited).

## Counts

| | queued | building | in review | escalated |
|---|---|---|---|---|
| BOARD.md at 69d8bdf3 (start) | 450 | 64 | 62 | 1 |
| End (this PR) | 450 | 64 | 62 | 1 |

Nothing changed on the board in this PR. If the proposed closes below are applied, 32 rows leave queued or building.

## What was audited

CONV-2-3 and the coordinator's priority (work already on main but still `queued` or `building`): 74 issues, namely the 46 open `state:building` issues without a PR, plus 36 `state:queued` issues whose ID matches a merged PR title, minus the ones whose PR is open or already closed. Each was checked by a read-only reviewer against origin/main (code, tests, merged PR). Verdicts are model output; DONE rows cite a merged PR or a named test.

Not audited: the release test (CONV-2-1/2) and the G1/G2 test (CONV-2-5) over the other ~380 queued rows, section by section. That needs a follow-up per BOARD section.

## Proposed issue changes (apply: close as completed, relabel `state:merged`)

Evidence is a merged PR or a test on main.

| Issue | Row | Evidence |
|---|---|---|
| 1778 | CI-FLAKE-SETTLE | #1797 (coordinator named) |
| 1818 | FIRST-PASS | #1822, #1825 |
| 1817 | CI-PATHS | #1823 |
| 1816 | RECORDS-INLINE | #1824 |
| 1741 | VAULT-slot-decided-2 | #1821 |
| 1714 | G1-e2e-phone | #1865 |
| 1764 | CI-FLAKE-UPLINK | #1827 |
| 1789 | OWNER-codeunique-tests | #1795 |
| 1357 | P2-2w c4e3 s1 | #1584 |
| 1135 | RECALL-prov | #1046 |
| 1131 | A14-r1 | #1651 |
| 1101 | SIM-split-b | #1057, #1061 |
| 937 | SR2-3j | #396 |
| 862 | P3-4b-3r-env-r8 | #651 |
| 813 | CRED-5f-mr-page | #1577 |
| 785 | SR3-mail-w | #643, #655 |
| 1110, 969, 946, 923, 1117, 822, 1136, 1109, 939, 793, 1129, 882, 761, 938, 897, 782 | EGRESS-rot-1, W3-forget-b1-7, CH-21a, P2-2w d2, IMG-nodump, P1-4-flake-soakcap, RECALL-prov-L1, MAIL-gen, SR2-3k, RT-1, P1-4-killfail, RECALL-canary-2, SIM-sd, SR2-3m, OSS-6s-a-f, SR3-6-f3 | named tests and code on main; PR number not recovered (shallow history) |

Already closed: 769 SIM-core, 1779 CI-FLAKE-MODEMAT (#1804).

Left for a human because they carry `gate:mark` or the evidence is thin: 753 CONV-3 (docs/conv-3-triage.md is on main; CONV-3-3/4 unverified), 754 CONV-4, 751 CONV-0, 928 P2-2w c, 1106 SIM-split-fix (egress Vault removal from the 2026-10-13 amendment unverified).

## Left as they are

- **Partial** (part done, remainder real; keep queued or building): 1780, 1300, 1691, 953, 954, 966, 965, 962, 919, 1113, 1016, 945, 1014, 959, 1264, 829, 893, 773, 955, 832, 1421, 980, 818, 1701.
- **Not done**: 1261, 1036, 1622, 820, 1262, 1898, 1037, 1039, 1040, 752 (this row).
- **Live PR**: 1844, 1803, 1457, 1420, 1347, 1339, 1340, 990, 1268 (open #1845 fixes the same defect), 755 (open #1902, L3 check decides).
- Frozen rows keep their state and FRZ line. No row is deleted and no tier-A broker finding moves to later.

## Next

One follow-up per BOARD section for CONV-2-1/2/5, each applying the release and G1/G2 tests and listing rows kept, moved to later, reset to queued and frozen, once the brief's mechanics are rewritten for issue labels.
