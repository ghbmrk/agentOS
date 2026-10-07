# Opt-in daily workflow

`New` builds one private collector and containment controller around the supplied
queue and heartbeat. It starts held, creates no timer and registers no daemon
service. A trusted host invokes `Step` at a bounded cadence and explicitly calls
`Activate` only after normal authority, source health and deployment checks.

Each step repairs incomplete queue/source acknowledgments, flushes transactional
producer entries, and asks the heartbeat to plan its configured local day. Before
the due minute, it collects nothing. Once due, the heartbeat's authentic current
identity selects exactly one queue association, including after source Ack and
process reopen. The first step aggregates configured source snapshots; later
steps retry that same Ready batch. Later activity waits for the next daily
identity. `Current` reconstructs an issued receipt from the original private
ledger without issuing, acknowledging or storing another schedule checkpoint.

Accepted means transport acceptance only. Unknown/Sending is returned as a
recovery condition and never retried. Missing acknowledged association, duplicate
association or conflicting hash is refused; resetting a queue alone cannot mint
another same-day notification. Cancelled/expired/exhausted batches remain visible
errors. Old-day pending heartbeat and incomplete acknowledgment recovery still
block as defined by the underlying source/collector. There is no automatic
backlog discard, stale alive-line rewrite, forget completion or ambiguous retry.

STOP must pass through `WrapEngine`: it revokes collection and transport scopes
before delegating to the real engine without waiting for I/O. Every hold cancels
the active step. Queued callers from the old admission epoch cannot revive on a
later activation. Engine Resume leaves daily work held. `Quiesce` holds and waits
for the entire collection/send scope before calling an invalidation callback;
a deadline before admission skips mutation and retains the hold. All actual
source invalidation paths must use this coordinator. Direct source/collector,
queue/send or unwrapped engine calls violate the composition contract.

Only one workflow may own these stores. Stores must be separately protected,
encrypted, single-writer and consistently backed up; paired rollback/migration
needs explicit review. Storage uncertainty requires reopening verified objects.
The configured source registry is closed, reserves `daily-heartbeat`, and requires
read-only, repeatable validators. Sources/flush/clock/policy/transport callbacks
must be trusted broker components with bounded latency and cancellation handling.
Synchronous store calls cannot be interrupted. The host must use an atomic clock
health observation and the same time basis for heartbeat and workflow.

`Flush` must check producer health and transfer transactional outbox entries
before snapshots are collected. It is required even if a deployment deliberately
supplies a no-op because it has no transactional producers. `Gate` must enforce
fresh STOP, quiet hours, the shared notification budget, priority, resource and
authority policy; it runs once per attempted dispatch. This package does not
implement a second pacing budget or refund reservations after proven non-send.
TTL is explicit, positive and at most 48 hours; heartbeat eligibility independently
refuses an old-day alive line immediately before transport. Complete digest text
must fit unchanged; oversize digests remain held by the existing renderer rather
than silently losing lines.

Tests exercise real file reopen, all queue Save boundaries (admission, source
bitmap, Begin and Finish) on both sides of replacement, policy deferral, same-day
activity retention, ambiguity, missing association, blocked collection STOP,
quiescence timeout and wrapped engine Resume. These local fixtures do not qualify
hardware power loss, complete forget, owner visibility or production policy.
Independent broker/security review and upstream integration holds remain before
activation. No daemon defaults are changed.
