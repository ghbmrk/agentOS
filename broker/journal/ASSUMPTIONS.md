# Journal and intent engine: assumptions

Built against SPEC v0.11 §9 (OP-1 to OP-7) before v0.12 was approved. These are
the readings of the spec this package relies on. Each one is a place a later
spec version could force a change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| A1 | Intents carry an `account` field. The §9 intent sketch has no account, but OP-4 fences "that account", so the engine needs one. Broker-state changes use account `broker`. | OP-4 | Rename or derive it from `executor` + `grant_ref`. Small. |
| A2 | The fence after a restart covers only intents left unresolved at that restart. During normal running, an `outcome_unknown` intent blocks its own retry (OP-2) but not other intents on the same account. | OP-4 says "Restart = replay ... before new dispatch on that account" | A stricter rule (any unknown fences its account) is a few lines in `Dispatch`. It costs potency: one lost acknowledgment would stall every other task on that account until reconciled. |
| A3 | A failed recheck before dispatch ends the intent as `denied` (phase `dispatch`). A caller who wants to try again submits a new intent. | OP-3 | Could instead return to `authorized` and wait. Small. |
| A4 | STOP holds authorized-but-undispatched intents rather than cancelling them. RESUME releases them. STOP is journaled, so it survives a restart. | OP-6, CH-11 ("RESUME restarts") | If STOP must cancel held work, add a `cancelled` state. Small. |
| A5 | Goal quality is a verdict (`good` / `wrong`) with a source and note, recordable on any intent at any time and replaceable by a later verdict. | OP-7 | A richer grading model (scores, graders per CHG-1) would extend `Quality`. |
| A6 | Recipients are compared in order for OP-1. The same recipients in a different order count as different parameters, which is the conservative reading of "exact params/recipients". | §9, OP-1 | Sort before fingerprinting. Small. |
| A7 | Authentication of the origin, of RESUME, and of owner-supplied evidence (`Resolve`) is the broker's job. The engine records the source string it is given. | CH-10, CH-11 | None here; the broker skeleton (P1-2) does it. |

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
  `apply`, so replay reproduces exactly the state the live engine had. The
  property test checks this after every step.
- **No external dependencies.** Go standard library only (DEP-1). Property tests
  are seeded random workloads with crash injection, not a third-party framework.
- **Not yet here:** journal compaction, and a hash chain for tamper evidence.
  Both can be added without changing the record format's meaning.
