# P3-3-erase: An erase that fails part-way is never reported done on retry

Board section: Phase 3: compounding.

Release, tier A. Three paths reported success on retry while deleted content stayed on disk (external review, verified against the code in the Questions thread; Mark approved the fix 2026-10-11):

- (a) `events.Bus.Forget`: the forgotten events left `live` before `log.Rewrite`; when the rewrite failed, a retry found no hit and `stale == 0` and returned nil. Forgotten events now count in `stale` until a compact succeeds. Test: `TestForgetRetryAfterFailedRewrite`.
- (b) `journal.Engine.Erase`: `RecErased` is committed before `rewriteErased`, whose read and encode errors returned without breaking the engine, so a retry skipped the intent and returned nil. Every `rewriteErased` failure now sets `e.broken`; Open finishes the erase. Test: `TestEraseReadFailureIsNotRetriedAsSuccess`.
- (c) `events.Open` ignored a torn seen line, and the next `Append` joined onto it, losing that ID; after compaction and restart the event was delivered again. Open now rewrites the seen store to its complete lines. Test: `TestTornSeenLineDoesNotLoseNextID`.

Requirement: CAP-3 (deletion propagates; no copy remains), CAP-4 (an event is delivered once).

**Needs:** P3-3, P3-3b
