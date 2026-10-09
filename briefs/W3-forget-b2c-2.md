# W3-forget-b2c-2: Item 2's texts are owed until they send

Board section: Integration: wiring merged packages into the box. Follows W3-forget-b2c (#427) and W3-forget-b3 (#425); SPEC CAP-3, CH-12.

**Sources:** L3 on #425, second PR with this kind of finding (UX-182-3 / CH-12): item 2's texts go out with `f.inform`, which sends and forgets, so a text lost to a down modem or a restart is never sent. W3-forget-b3 fixed that for item 1 only.

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): the owner is told when item 2 (the agent machine taken back) is done; a promised text is not lost to a send failure or a restart.
- **UX-182-3**: a text promised ("I … will text you when it's done") is sent after a restart, once the take-back has finished.
- **CH-12** (SPEC): every text that reports a wait says what the owner can do or that nothing is needed; owed texts keep their wording (UX screen only if a text changes, and none should).
- **CH-12-lint** (this package): a check that no done text in `ownerForget` reaches `inform` directly. See Work 4.

**Needs:** W3-forget-b2c (#427) and W3-forget-b3 (#425), both merged; **W3-forget-b4 merged first** (see Order).

**Work:**
1. **Which texts.** In `agentBack` and `carryAgent` (`forget.go`), the take-back texts that end the work or promise a later one: `forgetAgentDone` (two sites), `forgetAgentNotYet`, `forgetAgentNoAgent`, `forgetAgentNotTaken`, `forgetAgentNotOpen`, `forgetAgentWhenOpen`. The builder decides, with a sentence each in the PR, which are *done* (owed until sent, cleared on send) and which only *promise* a done text (sent once and not owed, because the done text that follows is what is owed). Recommendation: owe `forgetAgentDone` only, from the moment the take-back is recorded, and send the promises through `say`, logging a failed send; the done text is the one the owner is waiting for.
2. **Owed state.** Reuse `forgetOwed`; the key is the item 2 goal ID (`grants.ForgetAgentGoal(id)`), the entry an `owedForget` with a new `Agent` flag (or `Back`-style field) so `finishOwed` knows the entry is item 2's. No new file, no task words. The entry is saved before the take-back is recorded (`takeBack`), as item 1's is before its tombstone, and cleared only after the send reports success (`done`/`paid`).
3. **Restart.** `finishOwed` today checks `f.forgotten(g)` (item 1's tombstone), which does not hold for an item 2 goal. For an agent entry it checks `a.work.Handled(since)` (recorded by recall, the same test `resumeAgent` uses) and texts `forgetAgentDone` once, else drops it untold when recall never recorded it. An agent entry for a take-back not yet recorded stays owed for `resumeAgent`, which tells it when it runs. The restore path (`resumeRestored`) sends nothing today; it is **not** changed here (W3-forget-b2c-f1 owns that).
4. **No direct inform.** Add a Go test that parses `forget.go` (`go/ast`) and fails if any call `f.inform(x)` has `x` naming a done text (`forgetDone`, `forgetDoneRest`/`doneLater` results, `forgetAgentDone`, `forgetOwedLost`); done texts go only through `done`/`say`. Pin it with a mutant: change one site back to `f.inform` and the test fails.

**Not in this package:** bounding the in-boot retry or its STATUS line (W3-forget-b2c-f1); the `ErrNotOpen` test guard (f2); the restore-while-owed privacy point (f3); the local Wi-Fi page (W3-forget-b3r); any change to item 1's owed logic.

**Tests (write first, each with a `REQ:` marker):**
- A send failure on item 2's done text leaves it owed on disk, and a later send clears it (as W3-forget-b3's tests do for item 1).
- A restart after the take-back is recorded and before the text sent texts `forgetAgentDone` once.
- A restart where recall never recorded the take-back drops the entry untold, and `resumeAgent` still tells it when it runs.
- The owed entry is on disk at the moment the done text is sent (the b4 test pattern, for item 2).
- The owed file holds goal IDs, times and counts only (synthetic canary in a task body never appears).
- The no-direct-inform check (Work 4) and its mutant.
- `-race` over the new tests with `Text` and `resumeAgent` running.

**Scope:** `broker/cmd/agentosd/forget.go` (`agentBack`, `carryAgent`, `finishOwed`, the owed entry type), `broker/cmd/agentosd/learn.go` only if `finishOwed` needs its inputs wired there, their tests (`forget_agent_test.go`, `forget_owed_test.go`, a new lint test), and `broker/cmd/agentosd/ASSUMPTIONS.md`. Nothing else. It must not touch the methods W3-forget-b3r adds to `forget.go`.

**Order and parallelism:** not parallel with W3-forget-b4. Both edit `forget.go` and the owed tests in `broker/cmd/agentosd`, so parallel branches conflict, and b2c-2 relies on b4's save-first rule and order test. Run b4, then b2c-2 (start it after b4 merges). W3-forget-b3r adds only new methods and can run beside either. The b2c-f1..f3 rows also edit this area; none starts before b2c-2 merges.

**Gate:** tier A (`broker/cmd/agentosd`, and it touches a deletion path): L3 on the strongest model with a threat check, UX lens (texts), Security re-sign (OPERATING §3-4).

**Threat check to answer in the PR:** can the owner be told "taken back" when recall did not record it; does any owed file, log or text hold task words; what a replayed or tampered owed entry can do (only a repeated or missing text).

**PR:** carries `Defect: W3-forget-b2c`. Findings line as OPERATING §2. Builder model: strongest (tier A).

**Estimate:** under 110k tokens (checkpoint 110k).
