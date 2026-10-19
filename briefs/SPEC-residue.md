# SPEC-residue: portable-drive and digest leftovers

Tier B (SPEC text). Builder: Sonnet 5.5; keeps HW-8a, reworded as a host-PC internal-disk opt-in (L3 fix-list and trace check, PR #2325). Usage estimate: 40k tokens. Needs Mark's approval of the SPEC diff (L1 spec-diff PR). Issue #1690.

**Why.** D-102 made the controller a mini PC with an internal SSD and a USB stick only a flasher or recovery stick; D-097/DIG-RM removed the digest. Mark approved the cleanup 2026-10-14 18:01Z (cmsg_01R63S2yrPkq32thy8WQCuvDBG8j9So4uCVzPNt14ZmBL5).

## Requirements
- Remove portable-drive text: §0 table row, HW-6, HW-8/HW-8a drive wording, CRED-8 drive wording, §8.1 step 5 "not my PC" switch, ONB-7, §8.2, A1 host-disk hashing and BitLocker, A8 rescoped to replacement-controller restore, README line 3.
- CH-3's unlock window is 7 days, matching CH-14.
- DEV-10 `CONNECT` prompts expire after 24 hours.
- Digest leftovers: already removed on main by DIG-RM; verify none remain.

## Acceptance
**Acceptance tests:** none: text-only SPEC change; checks are `python3 tools/doclint.py` and a fresh L3 wording review. Failure path: a surviving drive-move sentence contradicts HW-9, or a requirement ID loses its test row.

## Scope
`SPEC.md`, `README.md`, this brief.
