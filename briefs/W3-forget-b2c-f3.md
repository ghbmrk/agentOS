# W3-forget-b2c-f3: An item 1 forget still retrying survives a restore

Board section: Integration: wiring merged packages into the box. Follows W3-forget-b2c (#427) and W3-forget-b2c-2 (#541); SPEC CAP-3. First of three packages that edit `broker/cmd/agentosd/forget.go` in turn (see Order).

**Sources:** L3 on #427, release 3 (a backup restored while a forget is owed drops it; reclassed from LATER l2 because forgotten content coming back after a restore is a privacy row). Security 4a on #427 (`reviews/security/2026-10-08-pr427.md`, blocker 1) closed this for **item 2** at 4caed6d: every approved take-back is in the forget log before the owner is told, done or owed (ASSUMPTIONS 5). **Item 1** still logs only when the forget is done.

**The gap (inference from main c0eb06e; the builder confirms it with the first failing test):**
- `Execute` (forget.go:467) owes the done text, tombstones the goal (`f.forget`), and on success calls `logForget` (forget.go:491). When the tombstone holds but a later save fails, it starts `retry`, which calls `logForget` only once the forget finishes (forget.go:536).
- While `retry` runs, the forget is in `forgotten.json` and `forget-owed.json` in the learn dir, and not in the forget log. The owner has been told `forgetNotSaved` ("I keep trying and will text you when it's done") or nothing yet.
- A restore of a backup taken before the forget puts back the learn dir's files from the backup (ASSUMPTIONS F7; `readRestoredForgets`, learn.go:110, 171). The restored `forgotten.json` lacks the goal and the forget log has no entry for it, so the replay never forgets it. The forgotten task's learned content comes back, while the owner holds a promise. This is CAP-3 ("Deletion requests propagate: the record and everything derived from it leave recall at once").
- Latent in production today: `forgetLog` stays nil until W3-forget-b1-5 wires it, and the restore command arrives with W3-forget-b1-6. The fix closes the path before those land, as #427 did for item 2.

If the first test cannot reproduce the gap (the restore keeps the live `forgotten.json`, say), stop, write that in the PR as a brief-gap, and mark the row `escalated`.

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): quoted above; a forget the owner approved does not come back after a restore.
- **F3-1** (this package): every item 1 forget whose tombstone held is in the forget log before the owner gets any text about it (`forgetNotSaved`, a done text) and before `retry` starts. Test: a fake forget log records the append; a forget whose first save fails has its entry at the moment `retry` is started and at the moment `forgetNotSaved` is sent.
- **F3-2** (this package): one goal is appended at most once per `Execute` and its `retry`, and the entry the done text's `Logged` flag reports is the one that holds. If the agent is taken back without asking (`agentBackWithoutAsking`), the take-back's own entry (`agent=true`, its `since`) is still appended, as today. Test: count `Append` calls per goal over the done path, the retry path and the not-tombstoned path.
- **F3-3** (this package): a forget restored from the log while it was still retrying is forgotten by the start-up replay. Test: a learn dir whose `forgotten.json` and owed file lack the goal plus a restored log entry for it opens with the goal tombstoned (`l.forgotten.has`) and its learned items undone. learn.go:171 already tombstones restored entries, so this test is expected to pass with no `learn.go` change; it pins the end-to-end path that F3-1 feeds. The failing test for the package is F3-1's.
- **CH-12** (SPEC): texts keep their wording. The done text's tail (`forgetLogged` vs `forgetBackups`) follows the `Logged` flag as now; with the entry written earlier, a forget finished by `retry` now reports `Logged` true when its early append held. No new text.

**Design constraints:**
- Append before the owner is told and before `retry`; appending before `f.forget` is allowed. An entry appended for a goal whose tombstone then fails (`errNotTombstoned`) makes a restore forget a task the owner was told "not done" for. The owner asked for that forget, and SHOULD 4 on #182 already lets a later save write that tombstone, so this is the accepted direction (over-forgetting, never under). Record it in ASSUMPTIONS.md, or append only after the tombstone holds; the builder picks and says which in the PR.
- A failed append is logged and leaves `Logged` false, so the done text keeps the backup caveat (existing rule). It does not stop the forget. `retry` may append again on a later pass while `Logged` is false (as S2 on #425 does for the owed save).
- No change to the forget log's format or to `broker/recovery`.

**Not in this package:** the done text after a restore replays a forget (the replay finishes it silently; record in ASSUMPTIONS.md, raise as a finding with its class); item 2's restore path and its done text (W3-forget-b2c-f1); recall's done-or-owed signal (W3-forget-reach); F7's doubled "forgotten now" texts (LATER); the CH-12-lint upgrade (f1).

**Tests (write first, each with a `REQ:` marker):** F3-1 at both moments; F3-2's append counts; F3-3's restored open; the existing done-path tail test still passes; `-race` over the new tests with `retry` running. Use a synthetic canary in a task body and check the forget log fake holds goal IDs and times only.

**Scope:** `broker/cmd/agentosd/forget.go` (`Execute`, `retry`, `logForget` only), `broker/cmd/agentosd/learn.go` only if F3-3 fails and needs a change in the restored-entry loop (learn.go:171), their tests (`forget_owed_test.go`, `forgetowed_test.go`, `learn_test.go`, or a new `forget_restore_test.go`), and `broker/cmd/agentosd/ASSUMPTIONS.md`. Nothing else. Do not touch `agentBack`, `carryAgent`, `agentDone`, `resumeAgent`, `resumeRestored` or `finishOwed`.

**Order and parallelism:** the three forget.go packages run one at a time: **f3, then W3-forget-reach, then W3-forget-b2c-f1** (which folds f2). f3 has no dependency on the `Reach` signal (item 1 does not judge a take-back), so it goes first: it is the smallest and closes a CAP-3 path. W3-forget-reach may start its `broker/recalltool` work while f3 is open, but edits nothing under `broker/cmd/agentosd` until f3 has merged. Needs: W3-forget-b2c-2 merged (d63322a).

**Gate:** tier A (`python3 tools/risk_tier.py broker/cmd/agentosd/forget.go broker/cmd/agentosd/learn.go` prints A): L3 on the strongest model with a threat check, Security re-sign at the final head (OPERATING §3-4). Lenses: Security only; no owner text changes, so no UX screen unless one does.

**Threat check to answer in the PR:** for each crash point in `Execute` and `retry` (before the append, between the append and the tombstone, during `retry`), does a restore of an older backup bring the task back? What does an entry appended for a forget that never tombstoned do after a restore? Does any log entry hold task words?

**PR:** carries `Defect: W3-forget-b2c`. Findings line as OPERATING §2. Builder model: strongest (tier A).

**Estimate:** under 70k tokens (checkpoint 70k). If F3-3 needs more than the restored-entry loop in `learn.go`, stop and escalate rather than widen.
