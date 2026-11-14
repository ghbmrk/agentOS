# GUEST-bridge-tree-dead-fu: drop the guest plane's managed_tree exemption (#5621, item 4)

Items 1-3 of #5621 merged in #5640. This brief covers item 4 only: remove the dead `managed_tree` special case from `broker/guest` (`TreeTool`, `MaxTreeAnswer`, `writeTree`, its branch in `mcp.go`, `treebound_test.go`, `TestTheManagedTreeIsNeverFolded`, the `TreeTool` clause in `bigTools`, and the G15/G19/G21 text in `broker/guest/ASSUMPTIONS.md`). agentosd no longer serves `managed_tree` (`broker/cmd/agentosd/tools_test.go`), and the bridge no longer calls it (#5611), so the branch is unreachable.

## Why it is split

The removal deletes lines from guest's non-test files and deletes test declarations and a test file. mutgate then has no added non-test line to target, and a deleted test declaration makes it run every test, so the target is every covered line of `broker/guest` (`tools/mutgate.py`, "Target lines"). On #5611's head df2d35f that surfaced 129 old statement-deletion survivors (mutgate job 132081393112 of run 43448235668). Every one must be killed or shown equivalent before the removal can pass, the same pattern as #5323-#5326 and #5410.

The removal is not reshaped to dodge the widening (for example by rewriting the two-case `switch` left behind so the diff adds a non-test line): that would narrow the targets to the added line and skip exactly the check that deleted tests leave no line unchecked.

## Rows, in order

Line numbers are at df2d35f; non-test guest files are unchanged from there to main 743d64d, so they hold on main. Re-read the current mutgate output before editing.

| Row | Survivors | Notes |
|---|---|---|
| GUEST-mut-store (#5747) | `store.go`: 78, 130, 131, 136, 137, 155, 158, 178, 179, 181, 189, 190, 203, 245, 270, 286, 309, 310, 312, 313, 315, 316, 322, 326, 329, 340 | Direct store tests only, no HTTP rig, so the targets stay in store.go. First PR of this brief. |
| GUEST-mut-plane (#5748) | `plane.go`: 170, 185, 186, 191, 192, 206, 210, 227, 229, 232, 239, 243, 258, 259, 286, 288, 312, 313, 352, 363, 398, 410, 415, 416, 417, 442, 574, 586, 595, 608, 609, 610, 629, 636, 637, 638, 639, 654, 655, 680, 685, 692 | Any rig test covers plane.go, so this row goes before owner and dispatch. |
| GUEST-mut-owner (#5749) | `owner.go`: 107, 112, 113, 127, 143, 146, 164, 203, 208, 209, 228, 236, 237, 240, 241, 266, 291, 302, 305, 308, 314, 328, 341, 351, 352, 358, 359, 361, 363, 365, 368, 371, 390 | After plane. |
| GUEST-mut-dispatch (#5750) | `mcp.go`: 87, 89, 92, 128, 162, 221, 227, 228; `goal.go`: 25, 26, 29, 30, 42, 43, 66; `plan.go`: 126, 146, 155, 165, 168, 173, 214, 297, 298; `compact.go`: 16, 17; `store.go`: 79 | After plane. compact.go:16-17 and store.go:79 look equivalent (see below). |
| GUEST-bridge-tree-dead-fu (#5621) | none of its own | The removal, last. Its PR body repeats every `Mutant-equivalent:` line the four rows used, since its target is the whole package. A ready patch: `/mnt/project-files/guest-tree-exempt/item4-removal.patch` (Claude project share; regenerate it if main moved). |

## Rules for each kill row

- Tests only, as plain `Test` funcs in an EXISTING `_test.go` file of `broker/guest`, appended after a test whose coverage reaches no other row's survivors. No new import, no new file, no helper outside a test func: any of those makes mutgate run every test, so the target becomes the whole package (`test_functions`, `changed_tests` in `tools/mutgate.py`). Comment lines before an appended func count as part of the test above them.
- No change to a non-test file: that narrows the targets to the changed lines and checks nothing.
- For each listed line, a test that fails when its statement is deleted. Where no test can tell, a `Mutant-equivalent: broker/guest/<file>.go:<line> <reason>` line in the PR body; a gap waiver is never allowed.
- New gremlins mutants on the new target lines (boundaries, negations) are killed in the same PR.

## Acceptance tests

- GUEST-mut-store: `broker/guest/links_test.go::TestForgettingAnUnknownGoalWritesNothing` (store.go:130-131: forgetting an unknown goal writes the file), `::TestAGoalRefreshWithinAMinuteIsNotWritten` (136-137, and the `< time.Minute` boundary: a refresh is written), `::TestAFailedInboxWriteKeepsThePreviousMessages` (155, 158, 322: a failed set loses or invents messages, or leaves its temporary file), `::TestAcceptReplacesTheMessagesInOneWrite` (178-190: accept keeps, drops or fails to restore the inbox), `::TestDoneRemembersTheLastReplies` (203 and its boundary: done grows without bound or forgets early), `::TestRoomInTheOutboxEndsTheRefusal` (245, 270: a refusal outlives a retire or forget), `::TestTheStoreClosesItsFiles` (315, 329, 340: a write or read leaks a file descriptor).
- The other kill rows: `mutgate.py delete guest` reports no unwaived survivor in their lines; each row's brief section in its issue names its tests.
- The removal: `go test ./broker/guest/...` passes without the deleted tests, `grep -rn 'TreeTool\|MaxTreeAnswer\|writeTree' broker/` is empty, and the mutgate job passes with the whole-package target.

## Scope

`broker/guest/*_test.go` (kill rows); `broker/guest/mcp.go`, `broker/guest/tools_test.go`, `broker/guest/treebound_test.go`, `broker/guest/ASSUMPTIONS.md` (removal); this brief. Tier A (broker/guest).

**Guard files:** none.

## Dependencies

None outside `broker/guest`. The four kill rows serialise on `broker/guest` (D-111) except GUEST-mut-store, whose tests touch only store.go.

## Usage estimate

About 80k tokens per kill row, 40k for the removal.
