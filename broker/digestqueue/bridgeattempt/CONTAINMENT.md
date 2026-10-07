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
