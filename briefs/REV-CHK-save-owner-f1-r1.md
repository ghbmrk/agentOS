# REV-CHK-save-owner-f1-r1: log ErrUnsynced at the owner and setup-record save sites

Work item #5047. Release finding of the UX lens on #5043 (comment 6703268580, point 1). Written 2026-11-14 against main at 743d64d.

## The failure

#5043 made `owner` `codes.commit` and `localsrv` `saved` count `privfile.ErrUnsynced` (the rename landed, the directory sync failed) as saved, so memory equals the file. Neither logs it, while `question` `persist` does. If a crash then loses the unsynced rename, the restart holds the old state after the owner read "Unlocked until …" or the page said setup finished, and agentosd's log has no line tying the two.

## Scope (files)

- `broker/owner/codes.go`: `commit` logs an `ErrUnsynced` save through a package hook `logf` (default `log.Printf`).
- `broker/localsrv/setup.go`: `saved` logs an `ErrUnsynced` save through a package hook `logf`. `saved` is the one helper for every setup-record save (finish, enrolled, owed), so `setupproviders.go` needs no change.
- Tests: `broker/owner/savecrash_test.go`, `broker/localsrv/savecrash_test.go` (the existing unsynced tests gain the log assertions).

Not touched: `broker/owner/ASSUMPTIONS.md` (open PR #5734 edits it, D-111); its REV-CHK-save-owner bound stays true as written. `tools/risk_tier.py` unchanged.

## Requirement IDs

CH-18 (owner state), ONB-3, ONB-6 (setup record). No new requirement.

## Acceptance tests

- `broker/owner`: `TestOwnerStateSaveUnsyncedKeepsMemoryEqualToTheFile`: one unsynced code-generator save calls `logf` once with the error, and the owner's reply does not carry the error's path canary.
- `broker/localsrv`: `TestFinishUnsyncedKeepsMemoryEqualToTheRecord` and `TestEnrolledAndOwedUnsyncedKeepMemoryEqualToTheRecord`: each unsynced save (finish, enrolled, owed) calls `logf` once with the error; the ops answer nil, so no page text carries it.
- Mutation: removing either `logf` call fails the matching tests.

**Size:** XS. **Tier:** A (owner, localsrv). **Model:** Opus 5.5.
