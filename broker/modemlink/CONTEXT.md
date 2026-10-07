# W5-D7 cancellable bridge sends

SendContext and SendRequestContext extend the existing owner-only bridge API.
Send/SendRequest use context.Background and preserve their established timeout,
outage/request accounting and wire behavior. No daemon/owner/queue call site is
switched by this candidate; no carrier or acceptance gate is qualified.

Cancellation before admission queues nothing. Cancellation while waiting for
handoff removes the local item under the same mutex used by outbox handoff. If
the bridge has not taken it, the returned SendCanceledError has Handed=false.
That is local evidence the bridge did not receive this item through this API;
it is not general evidence about another attempt, ID or external action.

After handoff, the item's handed channel stays closed even if its out-map entry
is later removed by acknowledgment, line failure or cancellation. The error's
Handed=true therefore retains permanent possibly-sent evidence. Cancellation drops
the local item and a later receipt becomes stray; it cannot undo a remote text,
prove non-delivery or establish owner visibility. A canceled send racing with a
receipt may conservatively return cancellation despite the receipt arriving;
retain/reconcile the item identity rather than automatically retrying.

The item ID is broker correlation, not recipient control, credentials, an owner
code or send authority. ErrRecipient remains enforced. Nil contexts are refused.
Context errors unwrap for standard cancellation/deadline checks. Cancellation is
not classified as a modem timeout and does not manufacture an outage/missed-text
recovery count. Existing SendWait still bounds normal bridge operation.

A future digest dispatcher may use pre-handoff cancellation evidence for bounded
not-sent recovery, but after-handoff cancellation/timeout/lost receipts remain
outcome unknown. Before wiring, qualify the actual bridge and its trusted sent
handler; preserve watcher/owner-line failure provenance, disclosure, pacing,
quiet hours, resource bounds, STOP and shared containment with forget. Queue/source
acknowledgments remain distinct from transport/carrier/owner evidence. The bridge
is still deliberately lossy and in-memory; this API adds no durable replay.

Tests cover canceled admission, queued removal, permanent post-handoff evidence,
late receipts, prompt deadlines, success, owner restrictions and request mode.
All effects use the in-memory socket/bridge protocol, not a modem, SIM or account.
