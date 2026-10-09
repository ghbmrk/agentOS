# SR3-mail-f: mail organize keeps what the gate approved (SR3-2-f1, SR3-5-f1)

Release findings on `broker/mail` from Security on #428 (SR3-2, point 1, [note](../reviews/security/2026-10-08-pr428.md)) and Security 4a on #424 (SR3-5, S1 and S2, [note](../reviews/security/2026-10-09-pr424.md)), filed as BOARD rows SR3-2-f1 and SR3-5-f1. Both must land before unattended mail organize is wired. Anchors: AT4, ADP-2, ADP-9, OP-3, OP-2/OP-4, A4, A13, A15.

**Why one package.** Both rows change the organize path's gate hook, `Adapter.Escalate` and its helpers in `broker/mail/guard.go`, which run at authorize and again at the dispatch recheck. Both also need the same harness: a journal wired to `Config` and a mailtest server whose folder changes between the recheck and `Execute`. Every tier-A PR costs a full L3 plus Security cycle, so one PR saves one cycle. Together they are about 300 lines of code and tests. Split only at the checkpoint below: if one of the two is still red there, ship the other and move the red one to its own brief.

**Requirements** (local IDs, under the parent rows' SPEC anchors):

- **SR3-2-f1a (durable daily bound):** `reserve()` counts organize places from the journal's `Engine.InUse` (SR3-2: authorized intents of any age, InFlight and OutcomeUnknown of any age, Succeeded dispatched within 24 h), not from `Engine.AuthorizedSince`.
  - Replace `Config.Authorized` with an `InUse func(action string, since time.Time) []journal.Use` hook. agentosd wires it to `Engine.InUse(account, action, since)`.
  - A nil `InUse` hook keeps today's rule: `reserve()` returns `askEach`, so every organize is asked (guard.go:546-548, matching the gate's rule for a missing guard at gate.go:723-727). It never holds, because `Held` becomes a deny at gate.go:714-716.
  - `a.reserved` may stay only to cover intents that `Escalate` has placed but the journal has not yet recorded as authorized. It must never be the only thing counting a place past `Authorize`.
- **SR3-2-f1b (restart and stale queue):** a restart (a new `Adapter` on the same journal) does not reset the count. A queue authorized more than 24 h ago and released by RESUME counts in full until it is dispatched, and its dispatches count for 24 h after that. The 200/2000 bound (`DailyLimit`/`DailyCeiling`, ASSUMPTIONS M8) therefore holds over any 24 h window of dispatches. The over-limit path asks, as today.
  - On main the same adapter already asks the 201st: each dispatch recheck runs `Escalate`, whose `reserve()` puts the intent in `a.reserved` (gate.go:710, guard.go:545-582). The hole needs both a restart and authorizations older than 24 h; `AuthorizedSince(now-24h)` counts anything newer (engine.go:605-618). The tests below therefore always build a new `Adapter` after the dispatches.
- **SR3-5-f1a (pin what was judged):** the adapter cannot see the owner's decision (the gate makes it), so the pin records what `Escalate` judged, not what the owner said. Lifecycle:
  - **Write.** Every `Escalate` call for an organize intent writes the pin under the intent ID: the planned message `Ref` (folder, UID validity, UID) and whether that call returned the alert escalation (`e.Verb == verb.ChangeAccount`, guard.go:471). Each call adds its judgement to the ones made since the last `Execute`; none overwrites another, because a concurrent dispatch's recheck that the gate refuses still calls `Escalate` (L3 on #579, point 1). If the message changed between authorize and recheck, the two judgements disagree.
  - **Check.** `Execute` re-plans as today. If there is no judgement, or any two judgements differ in `Ref` or alert bit, or the re-planned `Ref` differs from the one they agree on, or the re-planned plan hides an alert and their alert bit is false, it returns `NotApplied` with evidence `"changed since approval"` and calls neither `SetFlags` nor `Move`.
  - **Consume.** `Execute` deletes the intent's judgements whatever its result, so a later attempt of the same intent needs a fresh dispatch recheck. A pin is never read across intents or reused by a second attempt.
  - Pins live in memory; a restart drops them (SR3-5-f1b covers what happens then).
- **SR3-5-f1b (reconcile does not launder):**
  - `Reconcile` returns `Unknown`, not `Succeeded`, when the re-planned message is an alert that the plan hides and no pin records the alert escalation.
  - When a pin exists, `Reconcile` judges the pinned `Ref`, not the current Message-ID lookup.
  - A pin lost on restart leads to `Reconcile` (the journal's rule for an in-flight attempt), so it fails toward `Unknown`, never toward a fresh `Execute`.
- **SR3-5-f1c (validity-0 undo):** `undoOne` refuses a flag-only change (`c.To == ""`) whose `Change.Validity` is 0. Today the identity check at `undo.go:81` is skipped when validity is 0, so a same-ID message in a rebuilt folder has its flags restored. Leave moves unchanged: a move's undo is checked against the destination folder, so record why that is enough in ASSUMPTIONS.

**Design choice for the builder.** The recommendation is the in-memory pin keyed by intent ID: no agent-facing contract change, and it fails closed. The alternative is to carry `validity` and `uid` in the intent's params at declare time (`declare.go`). That pins across restarts, but it changes the agent contract and the OP-1 fingerprint, and it puts mailbox identifiers in the journal. If the builder takes the alternative, say why in the PR and in ASSUMPTIONS.

**Failing-test-first controls.** Show each row failing at main and cite the message in the PR, then show it passing at the head. Rows marked control pass on main and must keep passing; their job is to fail under the named mutant. Build the harness on `mailtest.Start` with a real `journal.Engine` over a `MemStore` and the gate's `inUse` path, not on `harness_test.go`'s nil hook.

| ID | Test | Why it fails on main |
|---|---|---|
| SR3-2-f1a (stale queue, full) | T0: authorize 200 organize intents under STOP. T0+36h: RESUME and dispatch all 200 (each through the dispatch recheck). Then build a **new `Adapter`** on the same config and engine, and authorize one more at T0+36.5h: it is asked, not passed. Mutant: restore the old `Authorized` hook, and the test fails. | The new adapter's `reserved` is empty and `AuthorizedSince(T0+12.5h)` sees none of the 200, so the 201st passes (`ask=false`, as the L3 probe on main showed). |
| SR3-2-f1b (partial, the bound's edge) | T0: authorize 150 under STOP. T0+25h: dispatch all 150. **New `Adapter`**. T0+25.5h: authorize 60 more: the first 50 pass and the 51st and later are asked. | Same cause: the new adapter counts 0 of the 150, so all 60 pass. What f1b adds over f1a: the count is exact at the edge (in-use places plus new ones reach exactly `DailyLimit`), not just non-zero. |
| SR3-2-f1 control (nil hook) | Leave `InUse` nil: every organize is asked with `"past 2000 today"`, never held or passed. | Passes on main too (`askEach`); it must keep passing. |
| SR3-2-f1 control (same adapter) | The f1a timeline without the new `Adapter`: the 201st is asked. | Passes on main too; it must keep passing. |
| SR3-5-f1a | Approve a newsletter archive at the recheck. Then, with `mailtest`, `Remove` it and `Deliver` a security alert with the same Message-ID in INBOX. `Execute` returns `NotApplied` and the alert stays in INBOX, unflagged. Mutant: delete the pin comparison, and the test fails. | `Execute` re-plans by Message-ID and hides the alert, returning `Succeeded` with `Alert:false`. |
| SR3-5-f1a nopin | `Execute` on an adapter that never ran `Escalate` for the intent returns `NotApplied`. | No pin exists, so it runs. |
| SR3-5-f1a recheck (control) | Authorize a newsletter archive (judgement: newsletter, no alert). Swap in a same-ID alert **before** the recheck: the recheck's `Escalate` returns `ChangeAccount` and adds the alert's `Ref` and alert bit. The judgements disagree, so `Execute` returns `NotApplied` and the alert stays in INBOX. Race: through the real gate and journal, D1's recheck, D1's commit, `swap()`, a refused D2 recheck that began before D1's commit, then D1's `Execute`: `NotApplied`, the alert unhidden. Mutant: overwrite-without-agreement (the last judgement replaces the others) fails the race test. Amended in #579 after L3 point 1. A recheck that cannot plan adds a poisoned judgement, never removes any: D1 passes, the message is removed, D2's recheck fails to plan, a same-ID alert arrives, D3's recheck is refused, and D1's `Execute` is `NotApplied` (mutant: drop the judgements on a planning error). Agreement covers each half: same alert bit with different `Ref`s, and the same `Ref` judged non-alert then alert once a same-ID alert twin arrives (mutants: drop the `Ref` or alert-bit comparison). Amended in #579 after Security re-sign B1/B2 and delta L3 point 1. With a single judgement, a same-ID message swapped in before `Execute` is refused, both an alert for the approved alert and a non-alert for the judged newsletter (mutant: drop `Execute`'s `Ref` check). Amended in #579 after round 3 (Security re-sign B1, delta L3 point 1). | The control passes on main (no pin is read); the race test fails there and under the overwrite mutant (D1 hides the alert). |
| SR3-5-f1a consume | After one `Execute`, a second `Execute` of the same intent without a new recheck returns `NotApplied`. | Second `Execute` runs. |
| SR3-5-f1b | Same swap as SR3-5-f1a, then `Reconcile` on a fresh adapter where the move already happened: the result is `Unknown`. | `Reconcile` sees the state matching the plan and returns `Succeeded`, `Reconciled:true`. |
| SR3-5-f1c | `Undo` of a flag-only `Change` with `Validity: 0`, whose Message-ID now names another message in the folder: `Skipped` is 1 and the flags are unchanged. | The validity-0 branch skips the identity check and restores the flags. |

**Controls that must keep passing.** Everything in `organize_test.go`, `identity_test.go`, `gate_test.go` and `fuzz_test.go`, including:
- SR3-5's UID-validity checks on `Execute` and `Undo`.
- The alert clause that labels alerts but leaves them in the inbox.
- The over-ask of SR3-2. `broker/grants/scopebound_test.go` is untouched.

**Threat check for the reviewer.**
- Can any path make `Execute` hide a message other than the one `Escalate` judged last? Check that the recheck overwrites the pin, that `Execute` consumes it, and that no pin outlives its attempt.
- Can a restart turn an unpinned intent into an `Execute`, rather than a `Reconcile`?
- Is there any way to make `reserve()` count fewer places than `InUse` reports, through pruning, a time skew between `Now` and the journal clock, or the `since` boundary?
- Does a nil hook anywhere pass instead of asking?

**Out of scope.**
- Wiring unattended mail organize in agentosd: BOARD row SR3-mail-w, which lists this package's rows in its Needs.
- LATER `SR3-5 u2` and `SR3-5 p1`.
- CONDSTORE (ASSUMPTIONS M9).

**Scope:**
- `broker/mail/{mail.go, guard.go, exec.go, undo.go}`, new or extended `broker/mail/*_test.go`, and `broker/mail/mailtest/mailtest.go` only if a test needs a new hook.
- `broker/mail/ASSUMPTIONS.md`: M8 (now counted via InUse), a row for the pin (SR3-5-f1a/b) and a row for validity-0 undo (SR3-5-f1c).
- agentosd's mail `Config` construction only if it already exists on main. If it does not, say so on the Findings line.
- `briefs/SR3-mail-f.md` (Delivery notes only), and `BOARD.md` rows SR3-2-f1 and SR3-5-f1.

**Needs:** SR3-2 (merged, #428 75a97c7) and SR3-5 (merged, #424 e43ae52).

**Done:**
- CI is green.
- SR3-2-f1a/b and SR3-5-f1a/b/c are each covered by a passing test.
- Every red-at-main message is quoted in the PR.
- Risk tier A.

## Delivery

- **Builder model:** strongest model (risk tier A: `broker/mail` is a mail adapter path). One package per session, tests first. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR.
- **Review:** L3 on the strongest model with the threat check above, then the lens stages and a separate Security section (OPERATING §3–4).
- **Estimate/checkpoint:** about 110k tokens; this is a checkpoint, not a ceiling (OPERATING §5). At the checkpoint, ship whichever row is green if the other is still red (see "Why one package").

### Delivery notes

- `Config.Authorized` is replaced by `Config.InUse` (`journal.Engine.InUse`); `broker/journal` is unchanged. `broker/vm/gvisor/corpus_test.go` is outside the declared scope and changed only to compile against the new field.
- The test harness's `run` now calls `Escalate` before `Execute`, as the gate's dispatch recheck does; `TestQueuedActionAfterRestartAcrossAReset` gains that recheck for its second attempt.
- Pins are in memory (ASSUMPTIONS M16); delete and report-spam are not pinned (release finding). Undo of a validity-0 flag change is skipped (M17).
