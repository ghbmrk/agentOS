# W3-forget-b2c-f1-r2: A forget told done before a restore is not told done again after it

Board section: Integration: wiring merged packages into the box. Follows W3-forget-b2c-f1-r1 (ASSUMPTIONS R5 in `broker/cmd/agentosd`); SPEC CAP-3. Issue #973.

**Sources:**
- UX 2 on #610 (comment 6082681852, release): a retry-path forget that finished and was told done before the restore is told done again when a backup restores its log entry; R5 accepts it today. "A done marker in the forget log (`broker/recovery`, outside r1's scope) would stop the restore owing it."
- `broker/cmd/agentosd/ASSUMPTIONS.md` R5, "Later" column: log a done marker in the forget log so the restore can tell the two apart.
- LATER W3-forget-b2c-f1 l14 is the same class; this package closes the retry-path case it names.

**Requirement IDs** (the builder writes the failing test first):
- **CAP-3** (SPEC): a forgotten task stays forgotten across a restore; the marker never stops a goal being tombstoned or purged.
- **UX-182-3** (UX lens on #182): a done text owed is sent once; a missing one is still the worse harm than a repeat.
- **R2A** (marker after the text): once an item 1 forget's done text has sent (`done`, or `tellLater` after a failed send) and its forget is in the log (`Logged`), agentosd appends a done marker for its goal to the forget log. Not for item 2 (`Agent`), not for `owedLostKey`, never before the text sends. A failed marker append is logged and changes nothing else. Tests: a retrying forget's done text, a done text sent only after a failed send, and an at-once done text each append one marker after the text; an unlogged forget, an item 2 forget and the lost-owed text append none.
- **R2B** (restore owes nothing for a marked goal): `openLearning`'s restored-forget loop still tombstones every goal the restored log names, but owes no done text for a goal the log holds a done marker for, and drops the restored learn dir's own owe of such a goal when it has not tombstoned it. A marker entry is not itself a forget: it adds no restored goal for the digest and no take-back. Tests: R1A's case with a marker after the entry tells nothing after the restore and the goal is tombstoned and purged; without the marker R1A still tells once.
- **R2C** (the marker is a log entry): `recovery.ForgetEntry` gains `Done` (`done`, omitted when false), chained, MAC'd and anchored like any entry, so a marker no key made fails the restore as forged and a log with no marker reads and verifies as before. The restore's confirmation question dates the last forget, not a marker (`newQuestion`). Tests: an appended marker verifies and round-trips; flipping `done` on an entry is forged; a question over a log whose last entry is a marker answers the forget's day.

**Design constraints:**
- The marker follows the text, never precedes it: a crash between the two repeats the text (lesser harm); the reverse would lose it.
- Every logged item 1 done text gets a marker, not only retry-shaped ones: the log entry's shape is not kept in the owed record, and a forget is a rare, owner-approved action, so one more anchored append per forget (one more TPM counter increment) is cheap.
- No new owner-facing text.

**Not in this package:** the vault process's wiring of `AppendForget` to agentosd (W3-forget-b1-5; `forgetLog` stays nil in production until then); a restored owe for a goal the backup had already tombstoned (told again today; same class, LATER l14); item 2's markers.

**Tests (write first, each with a `REQ:` marker):** R2A–R2C as above; the existing forget, owed, restore and confirm tests still pass; `-race` over the new tests.

**Acceptance tests:**
- R2A: `broker/cmd/agentosd/forget_done_marker_test.go::TestForgetDoneAtOnceIsMarked`, `::TestForgetDoneAfterRetryIsMarked`, `::TestForgetDoneMarkedOnlyOnceItSends`, `::TestForgetDoneMarkerOnlyForLoggedItem1`. Catches a marker before the text, or for item 2 or the lost-owed text.
- R2B, CAP-3, UX-182-3: `broker/cmd/agentosd/forget_done_marker_test.go::TestForgetRestoredWithDoneMarkerIsNotToldAgain`, `::TestForgetRestoredMarkerDropsTheBackupsOwe`. Catches a told forget told again, or a marked goal not tombstoned or purged.
- R2C: `broker/recovery/forgetdone_test.go::TestForgetLogDoneMarkerIsAnAuthenticatedEntry`, `::TestTheQuestionDatesTheLastForgetNotItsMarker`. Catches an unauthenticated marker and a question dated by a marker.

**Scope:** `broker/recovery/forgetlog.go` (`ForgetEntry`), `broker/recovery/confirm.go` (`newQuestion`'s pivot), `broker/recovery/forgetlog_test.go` or a new recovery test file, `broker/recovery/ASSUMPTIONS.md`; `broker/cmd/agentosd/forget.go` (`forgetLogger`, `done`, `tellLater`, a marker helper), `broker/cmd/agentosd/learn.go` (`restoredForget`, the restored-forget loop and `restoredGoals`), the forget log fakes in `forgetlog_test.go` and `forget_restore_test.go` (one method each), a new test file `broker/cmd/agentosd/forget_done_marker_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md` (R5); this brief. Not `broker/core/core.txt`.

**Gate:** tier A (`python3 tools/risk_tier.py` prints A for `broker/recovery/forgetlog.go`): L3 on the strongest model with a threat check, Security. UX only if a text changes (none planned).

**Threat check to answer in the PR:** can a marker suppress a done text that was never sent; can anyone without the log key add or flip a marker; can a marker stop a goal being tombstoned or purged from the digest across a restore; does a log holding a marker break an older reader (downgrade)?

**PR:** Findings line as OPERATING §2. Builder model: strongest (tier A).

**Estimate:** under 90k tokens (checkpoint 70k).
