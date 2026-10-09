# SR3-mail-f: mail organize keeps what the gate approved (SR3-2-f1, SR3-5-f1)

Release findings on `broker/mail` from Security on #428 (SR3-2, point 1, [note](../reviews/security/2026-10-08-pr428.md)) and Security 4a on #424 (SR3-5, S1 and S2, [note](../reviews/security/2026-10-09-pr424.md)), filed as BOARD rows SR3-2-f1 and SR3-5-f1. Both must land before unattended mail organize is wired. Anchors: AT4, ADP-2, ADP-9, OP-3, OP-2/OP-4, A4, A13, A15.

**Why one package.** Both rows change the organize path's gate hook, `Adapter.Escalate` and its helpers in `broker/mail/guard.go`, which run at authorize and again at the dispatch recheck. Both also need the same harness: a journal wired to `Config` and a mailtest server whose folder changes between the recheck and `Execute`. Every tier-A PR costs a full L3 plus Security cycle, so one PR saves one cycle. Together they are about 300 lines of code and tests. Split only at the checkpoint below: if one of the two is still red there, ship the other and move the red one to its own brief.

**Requirements** (local IDs, under the parent rows' SPEC anchors):

- **SR3-2-f1a (durable daily bound):** `reserve()` counts organize places from the journal's `Engine.InUse` (SR3-2: authorized intents of any age, InFlight and OutcomeUnknown of any age, Succeeded dispatched within 24 h), not from `Engine.AuthorizedSince`.
  - Replace `Config.Authorized` with an `InUse func(action string, since time.Time) []journal.Use` hook. agentosd wires it to `Engine.InUse(account, action, since)`.
  - Either hook left nil fails closed: `Escalate` holds every organize with the reason "mail bound not wired". Today a nil `Authorized` counts nothing.
  - `a.reserved` may stay only to cover intents that `Escalate` has approved but the journal has not yet recorded as authorized. It must never be the only thing counting a place past `Authorize`.
- **SR3-2-f1b (restart and stale queue):** a restart (a new `Adapter` on the same journal) does not reset the count. A queue authorized more than 24 h ago and released by RESUME counts in full until it is dispatched, and its dispatches count for 24 h after that. The 200/2000 bound (`DailyLimit`/`DailyCeiling`, ASSUMPTIONS M8) therefore holds over any 24 h window of dispatches. The over-limit path asks, as today.
- **SR3-5-f1a (pin what was approved):**
  - When `Escalate` passes an organize without asking, or the owner approves the ask, it pins the plan it judged: the message `Ref` (folder, UID validity, UID) and the alert bit.
  - `Execute` re-plans as today. If the re-planned `Ref` or alert bit differs from the pin, or there is no pin, it returns `NotApplied` with evidence `"changed since approval"` and calls neither `SetFlags` nor `Move`.
  - A hide (`pl.hides`) of an alert message is never executed unless the pin records that the alert was escalated and approved.
- **SR3-5-f1b (reconcile does not launder):**
  - `Reconcile` returns `Unknown`, not `Succeeded`, when the re-planned message is an alert that the plan hides and no pin says it was approved.
  - When a pin exists, `Reconcile` judges the pinned `Ref`, not the current Message-ID lookup.
  - A pin lost on restart leads to `Reconcile` (the journal's rule for an in-flight attempt), so it fails toward `Unknown`, never toward a fresh `Execute`.
- **SR3-5-f1c (validity-0 undo):** `undoOne` refuses a flag-only change (`c.To == ""`) whose `Change.Validity` is 0. Today the identity check at `undo.go:81` is skipped when validity is 0, so a same-ID message in a rebuilt folder has its flags restored. Leave moves unchanged: a move's undo is checked against the destination folder, so record why that is enough in ASSUMPTIONS.

**Design choice for the builder.** The recommendation is the in-memory pin keyed by intent ID: no agent-facing contract change, and it fails closed. The alternative is to carry `validity` and `uid` in the intent's params at declare time (`declare.go`). That pins across restarts, but it changes the agent contract and the OP-1 fingerprint, and it puts mailbox identifiers in the journal. If the builder takes the alternative, say why in the PR and in ASSUMPTIONS.

**Failing-test-first controls.** Show each one failing at main and cite the message in the PR, then show it passing at the head. Build the harness on `mailtest.Start` with a real `journal.Engine` over a `MemStore` and the gate's `inUse` path, not on `harness_test.go`'s nil hook.

| ID | Test | Why it fails on main |
|---|---|---|
| SR3-2-f1a | Authorize 200 organize intents on day 1 under STOP. RESUME at day 2.5 and dispatch all 200. Authorize one more inside the same 24 h: it is asked, not passed. | `reserve()` counts `AuthorizedSince(day 1.5)`, which sees none of the 200, so the 201st passes. |
| SR3-2-f1b | Dispatch 150 within an hour. Build a new `Adapter` over the same engine and authorize 60 more: the 51st and later are asked. Mutant: restore the old `Authorized` hook, and the test fails. | The new adapter's `reserved` map is empty and `AuthorizedSince` sees only the window, so all 60 pass once the 150 left its window. Name the exact window in the test. |
| SR3-2-f1a nil | Leave the `InUse` hook nil: every organize is held with "mail bound not wired". | A nil hook counts zero. |
| SR3-5-f1a | Approve a newsletter archive at the recheck. Then, with `mailtest`, `Remove` it and `Deliver` a security alert with the same Message-ID in INBOX. `Execute` returns `NotApplied` and the alert stays in INBOX, unflagged. Mutant: delete the pin comparison, and the test fails. | `Execute` re-plans by Message-ID and hides the alert, returning `Succeeded` with `Alert:false`. |
| SR3-5-f1a nopin | `Execute` on an adapter that never ran `Escalate` for the intent returns `NotApplied`. | No pin exists, so it runs. |
| SR3-5-f1b | Same swap as SR3-5-f1a, then `Reconcile` on a fresh adapter where the move already happened: the result is `Unknown`. | `Reconcile` sees the state matching the plan and returns `Succeeded`, `Reconciled:true`. |
| SR3-5-f1c | `Undo` of a flag-only `Change` with `Validity: 0`, whose Message-ID now names another message in the folder: `Skipped` is 1 and the flags are unchanged. | The validity-0 branch skips the identity check and restores the flags. |

**Controls that must keep passing.** Everything in `organize_test.go`, `identity_test.go`, `gate_test.go` and `fuzz_test.go`, including:
- SR3-5's UID-validity checks on `Execute` and `Undo`.
- The alert clause that labels alerts but leaves them in the inbox.
- The over-ask of SR3-2. `broker/grants/scopebound_test.go` is untouched.

**Threat check for the reviewer.**
- Can any path make `Execute` hide a message other than the one `Escalate` judged? Check pin lookup by intent ID versus attempt, and a pin left over from an earlier attempt.
- Can a restart turn an unpinned intent into an `Execute`, rather than a `Reconcile`?
- Is there any way to make `reserve()` count fewer places than `InUse` reports, through pruning, a time skew between `Now` and the journal clock, or the `since` boundary?
- Does a nil hook anywhere still pass?

**Out of scope.**
- Wiring unattended mail organize in agentosd. No BOARD row owns that wiring yet, so this package cannot add itself to that row's Needs; that row must list `SR3-2-f1, SR3-5-f1` when it is written.
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
