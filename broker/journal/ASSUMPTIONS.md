# Journal and intent engine: assumptions

Built against SPEC v0.11 §9 (OP-1 to OP-7) before v0.12 was approved. These are
the readings of the spec this package relies on. Each one is a place a later
spec version could force a change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| A1 | Intents carry an `account` field. The §9 intent sketch has no account, but OP-4 fences "that account", so the engine needs one. Broker-state changes use account `broker`. An effect that spans several accounts fences only the one it names; the broker should split such effects into one intent per account. | OP-4 | Rename or derive it from `executor` + `grant_ref`, or allow a set of accounts. Small. |
| A2 | The fence after a restart covers only intents left unresolved at that restart. During normal running, an `outcome_unknown` intent blocks its own retry (OP-2), and any intent with the **same effect** (same account, action, params, recipients, visibility, executor) under a different ID, but not unrelated intents on the same account. A held duplicate stays `authorized`, `Dispatch` returns a `HeldError` naming the intent it waits behind, and `Waiting()` lists every held intent with its blockers, so the broker can show the owner a waiting retry rather than lose it. | OP-4 says "Restart = replay ... before new dispatch on that account"; OP-2 | A stricter rule (any unknown fences its account) is a few lines in `dispatchable`. It costs potency: one lost acknowledgment would stall every other task on that account until reconciled. |
| A3 | A failed recheck before dispatch ends the intent as `denied` (phase `dispatch`). A caller who wants to try again submits a new intent. | OP-3 | Could instead return to `authorized` and wait. Small. |
| A4 | STOP holds authorized-but-undispatched intents rather than cancelling them. RESUME releases them. STOP is journaled, so it survives a restart. Held intents still pass the OP-3 recheck before they run, so a stale approval (expired CH-10 code) after a long STOP fails there; checking approval freshness is the Policy's job. | OP-6, CH-11 ("RESUME restarts"), CH-10 | If STOP must cancel held work, add a `cancelled` state. Small. |
| A5 | Goal quality is a verdict (`good` / `wrong`) with a source and note, recordable on any intent at any time and replaceable by a later verdict. | OP-7 | A richer grading model (scores, graders per CHG-1) would extend `Quality`. |
| A6 | Recipients are compared in order for OP-1. The same recipients in a different order count as different parameters, which is the conservative reading of "exact params/recipients". | §9, OP-1 | Sort before fingerprinting. Small. |
| A7 | Authentication of the origin, of RESUME, and of owner-supplied evidence (`Resolve`) is the broker's job. The engine records the source string it is given. | CH-10, CH-11 | None here; the broker skeleton (P1-2) does it. |
| A8 | Intent params carry vault references, never secret values, and executors never return secrets as evidence. As defence in depth, a mandatory `Redactor` (supplied by the broker: CRED-7 vault values plus CH-19 secret patterns) runs over every free-text field before it is journaled, and `Open` refuses a nil one. Identifiers are not redacted. The redacted form is what the engine keeps and replays, so an executor never sees a value the redactor removed. | CRED-1, CRED-7, CH-19 | None expected. |
| A9 | Authority-narrowing broker-state intents (`meta.grant.revoke`, `meta.grant.pause`, `meta.budget.lower`, and the change pipeline's `meta.change.revert` and `meta.change.policy.off`, on account `broker`) are exempt from STOP holds and restart fences, so pausing or revoking always works. They still pass the policy check and are journaled. | ADP-9, OP-6 | Add actions to the narrowing list as new pause/revoke commands appear. |
| A10 | `Policy.Check` runs outside the engine lock. A decision is committed only if no journal record was written during the check; otherwise the check runs again (up to 16 times, then `ErrBusy`). Policy inputs that change outside the engine must be read inside `Check`. | OP-3, CH-2 | None expected. |
| A11 | A complete record with a bad checksum stops `Open` (`ErrCorrupt`). There is no automatic recovery: dropping a durable `dispatched` record could duplicate an effect. P1-2 must still answer STOP and STATUS without the journal in that case (CH-2, restricted mode), and a recovery path (quarantine the tail, fence every account) is future work. | DEP-1, CH-2 | Add a recovery open. Medium. |
| A12 | **Erasure (CAP-3).** `Erase` removes an intent's parameters, preconditions, executor evidence and cancel details, in memory and in the file: an `erased` record, then the journal is rewritten (tmp file, locked, renamed) so no live copy remains; `Open` finishes a rewrite a crash cut short. Kept for the audit trail (OP-5): who asked, account, action, recipients, executor, decisions, results, and the idempotency fingerprints. Only finished intents are erased; a pending one is denied first, an authorized one fails its recheck first, so nothing runs on erased parameters; one in flight or unresolved is held and erased once it settles. The caller is recall's deletion reach: the intents a fork lineage submitted from the time it was given a deleted record. Old copies in backups and freed disk blocks are outside this. | CAP-3, OP-5 | — |

Expected in v0.12 from spike S4: **OP-8**, metering model egress per agent machine.
It needs nothing new from this package: raising a limit is a budget-change
intent (`ActionBudgetChange`, OP-5), which the engine already handles.

## Design notes

- **Write-ahead.** The `dispatched` record is fsynced before the executor runs.
  A crash can therefore make the journal over-report what may have happened
  (replayed as `outcome_unknown`), never under-report it.
- **Torn writes.** Only a final segment without a newline is treated as torn and
  dropped; its `Append` never returned, so nothing acted on it. A complete line
  with a bad checksum is corruption and `Open` fails closed, because silently
  dropping a durable `dispatched` record could let an effect run twice.
- **One transition function.** Live operation and replay share `validate` and
  `apply`, and the live engine applies each record as decoded from the line it
  wrote, so replay reproduces exactly the state the live engine had. The
  property test checks this every fifth step.
- **No external dependencies.** Go standard library only (DEP-1). Property tests
  are seeded random workloads with crash injection, not a third-party framework.
- **Durability of the file itself.** `OpenFile` fsyncs the parent directory, so a
  newly created journal's directory entry survives a crash, and takes an
  exclusive `flock`, so two engines cannot write one journal.
- **Size limits.** Intents over 64 KiB are rejected; free text over 4 KiB is cut
  and tagged with a SHA-256 of the whole.
- **Not yet here:** journal compaction (records are kept in memory and the
  file grows without bound), and a hash chain for tamper evidence. Both can be
  added without changing the record format's meaning.

## Notes for P1-2 (broker skeleton)

From the PR #18 review:
- Put the journal on the encrypted volume. It holds private recipients and
  params (CRED-8).
- Authenticate `Resolve` callers (A7).
- RESUME's confirmation should list the held intents. The outcome-unknown
  question to the owner should make clear that answering NO retries it.
