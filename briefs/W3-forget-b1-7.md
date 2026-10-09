# W3-forget-b1-7: Text the owner a held restore

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b1 (briefs/W3-forget-b1.md); SPEC CAP-3, A8, CH-12.

**Goal:** a restore the forget log's check held is no longer silent. Today agentosd calls `log.Fatal` on `forget-log.json.pending` (`restoreHold`, `broker/cmd/agentosd/main.go:405`), and b1-4's `heldText`/`answerHeld` (`broker/cmd/agentosd/restoreconfirm.go`) are called only from tests. After this package, agentosd started on a held restore runs a held mode: owner channel only, the case's text sent to the owner, the owner's reply answered, and the full start once released.

**Requirement IDs:** CAP-3 and A8, as in W3-forget-b1; security C3's "a failed check keeps the restore pending and tells the owner"; CH-12 (the texts); CH-1 (texts reach the broker from the modem, so the held mode needs only the modem link); CH-15 (the held text is unsolicited and counts against pacing). Tests carry `REQ: CAP-3, A8, CH-12` (add CH-15 to the pacing test).

**Sources:** BOARD row W3-forget-b1-7; #409 Security R4 (placed here by W3-forget-b1-6); #409 UX U2 (the held box is silent toward the owner) and U6 (recurring kind); #436 L3 (only authenticated owner replies reach `answerHeld`, serialized) and UX points 1–2 (`reviews/ux/2026-10-08-pr436.md`); `reviews/ux/README.md` "Recurring kinds".

## Requirements (each with a test)

1. **Held mode replaces the fatal exit.** When the marker exists, agentosd brings up only what the owner channel needs: the modem link (`modemlink.New`, as at `main.go:557`) and the owner check. It opens no learning plane, recall, agent or replay machine, tool op or page op beyond what `setupMode` (`main.go:457`) already serves. Test: start with a marker present; assert no machine is opened, the learn dir's files are unchanged except the marker and question, and the owner socket accepts a text. A marker that does not read still holds and still texts (fallback notice, as `restoreHold` does now).
2. **The owner is told.** On entering held mode agentosd sends one text:
   - `forget-log-unanchored` and `forget-log-missing` with a readable question: `heldText` (header, question, choices);
   - `forget-log-rolled-back`, `forget-log-forged`, or no readable question: the marker's `PendingNotice` line, whose steps are the ones recovery wrote.
   One text per start, sent through the outbox so a down line retries as other owner texts do (`TestOwnerTextsGoOutThroughTheOutbox` precedent); it counts against CH-15 pacing. Test per case, plus one for an unreadable question.
3. **Only the owner answers, one reply at a time** (#436 L3). Only texts that pass the owner check (`IsOwner`, as `daemon.go:197`) reach `answerHeld`; any other sender gets nothing and is logged by number class only, never content. Replies run under one mutex, so two concurrent replies give at most one release and one written log. Tests: a non-owner text with the right letter leaves the marker in place; two concurrent right answers release once and the log on disk is the question's log.
4. **Release starts the box.** When `answerHeld` reports released, agentosd sends `heldReleased`, leaves held mode, and continues into the normal start in the same process (as `setupMode` returns into `main`), re-running `restoreHold`, which now passes. A wrong answer or a closed question keeps held mode and replies with `wrongText`; a non-choice re-asks (`askText`). Test: answer correctly, then assert the full start's first step runs and the marker is gone; answer wrongly, then assert held mode persists across a restart and repeats `wrongText`, never a fresh question.
5. **Header says "this PC"** (#436 UX point 1). `heldUnanchored` becomes "Restore on hold: this PC can't check your forget list." The header test from b1-4 is updated to pin it.
6. **No-newer-backup wrong answer names a retry** (#436 UX point 2). When `Newer` is empty, `wrongText` ends with a named way forward that works. Ruled (coordinator, 2026-10-09, on #503): the text ends with "If you picked by mistake, restore this backup again to answer again.", which names the existing retry path (a fresh restore writes a fresh question). Keep it in one constant; the UX lens may reword it. The requirement 7 check must accept it.
7. **CH-12 recurring-kind check** (#409 U6; `reviews/ux/README.md`). Add a test that walks every held-mode text (each header, `heldWrong`, `heldNoNewer` or its replacement, `heldReleased`, and every `PendingNotice` the marker can carry) and fails when a text names a step this box cannot carry out. The checker rests on a table, kept beside the test, of step phrases and the condition under which each works (e.g. "restore a newer backup" only when `Newer` is non-empty or the text is the generic no-newer line; "restore on your original PC" only for unanchored; "wait for an update" only where an update is the fix). Each text is also checked to be GSM-7 and at most three segments. List the check in `reviews/ux/README.md` under the recurring kind, as replaced by this test. Scope: held-mode texts only; widening it to every owner text is a later row (LATER line).
8. **Restored take-backs run before any agent machine opens** (#409 Security R4, placed here by W3-forget-b1-6). On the start after release, the learning plane's replay of the restored log (`readRestoredForgets`, `learn.go:110`) finishes, and its take-backs are applied, before the first agent or replay machine opens; if the replay fails, no machine opens (the learning plane's failure must not open recall over unforgotten content). Test: release with a log holding a canary forget, then assert the take-back is recorded before the fake machine opener is first called, and a replay error leaves the opener uncalled.

## Acceptance criteria
- Every numbered requirement has a passing test in `broker/cmd/agentosd/` and CI is green.
- `go test ./cmd/agentosd -run 'Held|Restore'` passes; no test imports `recovery` from agentosd (`TestOnlyTheVaultProcessImportsRecovery` still passes).
- No log line or test fixture carries forgotten content or a real number; canaries only.

## Open questions (flag in the PR; do not decide silently)
1. **Retry wording when no newer backup exists. Ruled by the coordinator, 2026-10-09 on #503: option A** (requirement 6). A wrong answer closes the question; restoring the same backup again writes a fresh question with the same choices (the decoys are deterministic), so a retry exists today, unannounced.
   - (A, recommended) Append "If you picked by mistake, restore this backup again to answer again." (UX point 2). It names a step that works. Its cost: it makes visible that each restore buys one more guess among at most six choices. That cost exists today without the line, since D-065's picker is a check on the owner's memory, not a barrier against someone holding the recovery key.
   - (B) No retry line. Keeps today's behaviour and fails the CH-12 "what the owner can do" rule for an owner who mis-tapped.
   - (C) Bound retries (e.g. a count kept in the vault). That is a design change to D-065; it would be a new row, not this package.
2. **Missing-case question wording** (#436 UX point 3, "Since this backup on <date>, …"). Ruled by the coordinator, 2026-10-09: taken up after b1-6 (LATER `W3-forget-b1-4 l9`). Not carried by this row. Recommendation: leave the b1-4 question unchanged here and let the UX lens raise it as a spec-diff proposal if wanted; the b1-6 change to the missing case (carrying an authentic copy) changes what that question asks about, so wording after b1-6 is the better time.

## Assumptions to record (`broker/cmd/agentosd/ASSUMPTIONS.md`)
- Held mode needs no vault: the question and marker are files in the learn dir (b1-4 Q6), and the owner check uses the configured owner number, not a vault-held secret.
- A box with no owner number yet (setup not finished) cannot be in a held restore (a restore needs a provisioned box); if both hold, setup runs first, then held mode.
- One text per start is enough: a box restarting in a loop is rate-limited by CH-15, not by this package.
- `answerHeld`'s write order (log, marker removal, question removal) is crash-safe as b1-4 recorded; held mode adds no new write.

**Needs:** W3-forget-b1; W3-forget-b1-4 (merged, #436).

**Gate:** tier A (agentosd's restore hold is the security C3 path; strongest model under the Sonnet pilot); explicit threat check: a non-owner or replayed reply, two concurrent replies, a crash between release and start, a machine opening before take-backs. UX lens signs off the texts (requirements 5–7).

**Scope:**
- `broker/cmd/agentosd/main.go` (the hold call site only), `learn.go` (`restoreHold`), `restoreconfirm.go`, and a new `heldmode.go`;
- their tests in `broker/cmd/agentosd/`;
- `broker/cmd/agentosd/ASSUMPTIONS.md`;
- `reviews/ux/README.md` (the recurring-kind line only);
- `LATER.md` (one line: widen the CH-12 check to every owner text).

**Estimate:** under 100k tokens, strongest model (tier A). Checkpoint at 70k: requirements 1–4 green. If requirement 8 proves to need a restructuring of the start order beyond the hold path, split it out as a release row rather than widening the package.
