# Shared digest policy

Configure one Policy with the actual approval/question grants.Gate, the actual
engine, an atomic trusted clock/health callback (clock.Guard.Now is compatible),
repeatable quiet-hours and resource/authority checks, and an explicit aging
threshold. Use `Check` as daily.Gate and `Recheck` as daily.Recheck in the contained
host. Clock and grants.Config.Now must use the same qualified time basis.

Check verifies STOP/time/quiet/expiry, checks resources on an isolated batch,
then freshly observes STOP/time/quiet/expiry again before reserving exactly one
slot with Gate.Reserve. Recheck repeats this process without any reservation and
accepts the persisted Sending batch after Begin. It runs immediately before the
owner call so policy cannot remain stale across blocked Begin persistence. A
final refusal settles proven NotSent; failed settlement still quarantines.
Cancellation is observed after callbacks and the final clock read before owner
transport. This does not eliminate the passage of time after a decision.

The slot shares the approval/question budget and priority rule; there is no
separate digest counter. Before AgedAfter, approval batches go first. Once aged,
it competes in the existing at-most-once-per-hour aged-question fairness lane
when approvals wait. Aging never exceeds the hourly limit or marks a digest
urgent. Owner-defined urgent exceptions remain in their existing routes. All
non-policy authority and resource constraints belong in Eligible/host health;
policy success is not an owner outcome or authentication proof.

Quiet/clock/resource/cancellation refusals before reservation spend nothing.
Every successful reservation is conservatively counted even if Begin later
fails, STOP cancels the attempt or pre-call policy becomes ineligible. Recheck
never refunds or reserves. Host/controller containment is required; calling
Recheck alone cannot authorize a send or bypass source validation/forget.

This adapter uses the actual Gate's accounting mode. Nil PacingStore retains
legacy volatile pacing. Configuring the Gate's optional durable store preserves
shared reservations and aged priority across ordinary reopen, as described in
broker/grants/PACING.md; there is still no separate digest ledger. Restore,
deleted-state continuity, protected single-writer custody, clocks and storage-
fault urgent/reissue availability require independent qualification.

Health returns fixed ErrRecovery when the common Gate is quarantined, while
ordinary exhaustion returns ErrPaced from Check and leaves Health healthy.
Check distinguishes a failed reservation from exhaustion. Both Check and
read-only Recheck observe accounting recovery before and after callback work,
so a failed question reservation during durable Begin prevents the subsequent
digest handoff. Recheck consumes no slot and cannot repair the Gate. Bind
Policy.Health as dailyhost.Config.PolicyHealth as well as Check/Recheck: the
host then refuses activation/step on accounting failure and displays fixed
recovery status without leaking store paths or callback errors. Host health is
optional for existing callers; omitting the binding is not qualified durable
host integration. Health does no storage I/O itself but can wait for the Gate
mutex while an existing synchronous reservation save finishes. Daily progress can still be
held by quiet hours, urgent traffic, exhaustion or authority/resource failures;
this is not an unconditional-delivery assertion or an urgent bypass.

Tests use the real question Book and common Gate to prove question/digest budget
sharing, concurrent Gate reservations, pre-reservation refusal, read-only phase
and an actual FileStore Begin replacement crossing into quiet hours. Transport
is not called on that refusal; reopened queue retains the exact Ready attempt
and the spent slot is not refunded. No grants or daemon default, urgent-class,
hardware/carrier/owner-visibility or migration qualification is changed.

Additional tests reopen the real shared FileStore with actual question Books,
cut a question reservation before/after persistence during real queue Begin,
and verify zero owner calls, proven-NotSent Ready state, unchanged attempt ID,
spent digest slot and the exact persisted question debt on recovery.
