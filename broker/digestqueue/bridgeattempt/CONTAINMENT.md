# W5-D27 explicit digest dispatch containment

NewController owns one existing Attempt and starts held. A trusted broker caller
explicitly releases it after reviewing current policy. Every send still validates
sources and the mandatory Gate immediately before durable Begin. The controller
implements scope cancellation and serialization, not pacing, quiet hours, budget,
priority, disclosure authority or full forget reach. No daemon caller enables it.

Hold immediately cancels the current scope and wakes admission waiters. It takes
only the short state lock, never waiting for a source, policy callback, owner,
queue persistence or invalidation. Admission uses a replaced hold-channel epoch:
an old waiter cannot become a fresh send merely because Hold was followed quickly
by Release. Release refuses while a dispatch or invalidation callback remains live.
The mandatory policy runs outside the state lock and is checked for liveness both
before and after its callback; callbacks need bounded synchronous latency.

WrapEngine places Hold before the existing control.Engine.Stop, so the owner
channel's text/local STOP fast paths can cancel dispatch without waiting behind
it. Engine Resume preserves its existing authority and deliberately does not
release digest dispatch. Stopped reports the underlying engine's factual state,
not the notification hold. Every STOP path must use the wrapped engine. Direct
calls to the underlying engine or a separately constructed Attempt bypass this
optional composition and are not qualified. Dispatch holds are volatile: startup
starts held again, and queue reopen retains ambiguous sending attempts as Unknown.

Quiesce holds admission, cancels dispatch, waits through queue finish persistence,
and then calls one trusted invalidator exclusively. A deadline while waiting skips
the callback and leaves dispatch held. Concurrent invalidators and Release during
mutation are refused. Callback success does not prove encrypted copies, backups,
transport/carrier state or every dependent source was forgotten. Callback errors
stay diagnostic and never grant dispatch or claim deletion completion. A callback
already running must honor its context; this does not interrupt a hung store.

Cancellation during the synchronous successful Begin save is checked before any
owner/transport call. That local absence of a call proves NotSent; it settles the
exact bounded attempt with a private cancel-before-call observation reference.
After an owner call, existing strict bridge handoff classification remains in
force. Cancellation cannot retract handoff; Unknown cannot automatically retry.
An uncertain finish save quarantines the queue and must be recovered independently.

This controller reuses context cancellation and the existing durable Attempt
rather than adding a second sender or queue. One instance/writer must own the
entire scope. Trusted source invalidation, shared pacing reservations and actual
transport cancellation must all compose through it before daemon activation.
Independent strongest broker/security threat review and actual carrier/resource
qualification remain required. No default configuration, timer or sender is wired.

## W5-D28 actual owner/bridge and file-persistence composition

The fixture captures a real LocalSignIn wrong-code event through the transactional
owner channel, flushes it to the typed owner-note source, and admits/acknowledges
it through the real adapter/collector. The same source, three actual FileStores,
controller-wrapped Engine, transactional channel and bridge handlers then dispatch
that exact private receipt's public lines. No source receipt is texted.

Text and local STOP both finish while queue Begin persistence is blocked, cancel
the scope and prevent an owner/bridge call. After actual bridge handoff, both STOP
paths persist Unknown across independent queue reopen; a late successful bridge
receipt becomes stray and cannot settle/retry that batch. Another cut blocks the
actual finish save after affirmative bridge acceptance: owner STOP remains prompt,
invalidation times out without running, and a later quiescent callback observes
the completed durable state. An affirmative receipt is not retroactively revoked
by STOP or recast as owner visibility. These tests use local handlers only, not a
carrier, power loss, delivery qualification or complete forget/authority policy.

## W5-D30 final read-only eligibility before the owner call

Source validators run both before the policy gate and after successful durable
Begin, immediately before the owner call. They must be read-only and repeatable;
a validator must never reserve pacing, consume a source or execute authority.
The policy/reservation Gate is still called exactly once. Batch expiry and context
are checked again after potentially stalled Begin persistence as well.

If the final source check or expiry refuses before an owner call, the exact
attempt settles NotSent with a private local observation reference. That permits
only the queue's existing bounded retry policy; it does not refund shared pacing,
reissue a source generation or grant dispatch. A failed finish write quarantines
the queue; actual before/after replacement tests show conservative Unknown on an
unconfirmed persisted Sending state and Ready only after observed NotSent state
is durably reconfirmed by reopen. No transport was called in either case.

The real heartbeat fixture crosses a local-day boundary during the actual Begin
save and proves an authentic yesterday-alive line is refused today. Policy-time
source refusal and exact expiry at Begin are also covered. This narrows the gap;
it does not make time observation and physical carrier handoff atomic, replace
the containment controller, qualify other validators' forget reach or complete
fresh quiet/pacing/resource policy. No daemon default is enabled.

W5-D35 separates a reservation Gate from optional read-only Recheck. Recheck
runs after durable Begin and source eligibility checks, just before the owner
call. It must not reserve or consume anything. A pre-call policy refusal settles
the exact attempt as proven NotSent; uncertain settlement still quarantines.
Expiry/cancellation is checked again after Recheck. Legacy fixtures may omit this
phase, but dailyhost requires it: use dailypolicy.Check/Recheck together with the
same approval/question grants gate and reviewed resource policy. This avoids
both stale quiet-hours policy across Begin persistence and double reservation.
