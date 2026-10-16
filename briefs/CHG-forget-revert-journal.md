# CHG-forget-revert-journal: the forget and settings reverts are journal intents (OP-11)

Board row: issue #1962. Source: release finding from the state-machine audit (audits/2026-10-16-state-machines.md, SM-AD-2) and C36's open item. Class: release. Tier: A (`broker/change/`). Row #1965 follows; not built here. Builder: strongest model. Usage estimate: 90k tokens, checkpoint at 70k.

**Why (facts, verified at main ed63bec).** Every adoption transition is a change intent except two undos: a forget (`ForgetGoal` through `forgetAdoptionsLocked`, `WhyForgotten`) and the owner's settings replacing the adopted state (`Superseded`, `WhySettings`). Their only record is the adoption body in Content (`tailRevert` in `adoption_journal.go`), and replay reads them back from it. If the body is lost, rolled back, or older than the revert, the adoption replays as active: a forgotten adoption comes back, and a settings-superseded one is treated as still running. `reforgetLocked` repairs only goals in `p.gone` (forgotten since this start), and nothing repairs a settings revert. That is a lifecycle kept beside the journal, which OP-11 forbids.

## Requirement (from SPEC.md)

- **OP-11** "No component keeps its own durable lifecycle, receipts or recovery rule beside the journal."
- **SM-AD-2** (audit): every adoption transition, revert included, is a journal intent; replay reads none of the lifecycle from the body.

Package IDs:
- **FRJ-1** A forget that undoes an adoption journals a broker-account intent `chg:<id>:revert:<n>:forgotten` that succeeds.
- **FRJ-2** `Superseded` journals `chg:<id>:revert:<n>:settings` for each adoption it undoes.
- **FRJ-3** Replay takes these reverts from the journal alone: neither body nor state JSON holds `reverted`, and a body restored to its bytes before the revert (or a body that is lost and then restored) still replays as reverted. A crash between the revert's state save and its journal record replays as reverted and journals the record at the next `Attach`. A body saved by an earlier build with the revert in it, and no intent, is journaled once at `Attach`.
- **FRJ-4** `Check` admits a `forgotten` or `settings` revert only as a record of an effect the pipeline already applied (`Applied` holds its ID), from the owner origin with `meta.change.revert`; any other is denied.

**Acceptance tests** (`broker/change/forget_revert_journal_test.go`):
- FRJ-1: `TestForgetRevertIsJournaled`.
- FRJ-2: `TestSettingsRevertIsJournaled`.
- FRJ-3: `TestForgetRevertSurvivesARestoredBody`, `TestSettingsRevertSurvivesARestoredBody`, `TestOwedRevertJournaledAfterACrash`, `TestBodyRevertFromAnEarlierBuildIsJournaled`.
- FRJ-4: `TestForgedForgetRevertIsDenied`.

## Design (recommendation)

1. **An outbox in the saved state.** The journal calls `Check` and `Execute` under `p.mu`, so `ForgetGoal` and `Superseded` cannot run an intent while they hold it, and both must keep their effect atomic with their state save. So, under the lock and in the same save as the effect, each adoption they newly undo gets an intent ID `chg:<id>:revert:n<seq>:<why>` (a fresh `Seq`), `Applied[ID] = true` and an entry in the state's new `Unjournaled` list. After the lock is released, `flushOwed` runs each owed ID through `run` (owner origin, `meta.change.revert`, params derived from the ID only, so a retry has the same fingerprint) and drops it from `Unjournaled` once it succeeds. `Execute` answers it from `Applied` ("already applied"). `Attach` flushes after replay. A failed flush is logged and stays owed; the next forget, settings revert or `Attach` retries it, and `Submit`'s idempotence makes a retry after a crash safe.
2. **Replay.** Journal reverts apply through the existing revert case. Then each still-owed ID applies to an adoption that is still active. `tailRevert` goes: the body no longer keeps `reverted`. A body from an earlier build that still holds a forget or settings revert, on an adoption the journal leaves active, is owed once (migration) and saved.
3. **Check.** A `forgotten` or `settings` revert passes only with `Applied[ID]`, before the active-adoption check (the adoption is already undone by then). Rejected alternative: journal first, then the effect from `Execute`. It needs `ForgetGoal` and `Superseded` to give up their lock between steps and splits the forget's privacy scrub across a crash.

## Scope

`broker/change/adoption_journal.go`, `broker/change/effect.go`, `broker/change/suite.go`, `broker/change/digest.go`, `broker/change/pipeline.go`, `broker/change/forget_revert_journal_test.go` (new), `broker/change/ASSUMPTIONS.md`, `briefs/CHG-forget-revert-journal.md`. **Guard files:** none.

## Out of scope

Row #1965. Garbage-collecting orphan bodies (C37). Edits that an older restored body still holds for a forgotten goal: privacy for those stays with `reforgetLocked` and the daemon's forget replay (C23).

## Done

CI green; FRJ-1..4 covered by tests carrying `REQ: OP-11, SM-AD-2` and their ID.
