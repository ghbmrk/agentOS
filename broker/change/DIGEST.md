# W5-D4 change-pipeline snapshot source

This implementation candidate supplies real nonconsuming pipeline source APIs.
It is not wired to the digest queue or a sender. External security review is
required. Existing pipeline callers retain legacy behavior until the first
nonempty PeekDigest successfully persists a generation.

PeekDigest renders broker-owned adoption, revert, concern, notice and outage lines
without marking them seen. It persists one pending snapshot with a monotonic
generation, exact event marks, goal-reference IDs and an acknowledgment receipt.
Repeated peeks and restart return the same snapshot. New events wait for a later
generation. Snapshots are bounded to 64 lines/64 KiB and 64 references, compatible
with the queue's source limits; oversized individual lines/references fail without
consumption. One-shot notices precede repeated declined-update reminders so
repeated lines cannot starve new notices. Both APIs use one renderer; legacy
ordering changes only by placing those repeated reminders last.

AckDigest must be called only after the complete snapshot is admitted durably.
It marks only matching event versions. A notice appended after Peek, a later
installation after staging, or a higher outage count remains pending. Generation
acknowledgments are idempotent across restart and later generations. Repeated
security-update declines are deliberately rendered again in later generations;
callers enforce the fixed digest cadence, not the agent or the source.

The receipt is an HMAC over the complete snapshot, domain-separated from the
pipeline's existing private split/probe key. It authenticates only issuance by
this private pipeline so prior exact acknowledgments can be checked without an
unbounded receipt ledger. It is not an owner code, approval, grant, provider
credential, effect permission or send authorization. Never expose it as a guest
control. State confidentiality and key protection remain the broker boundary;
receipt checks do not protect against an attacker who can read/write that state.

Every snapshot save failure makes the pipeline fail-stop until restart, even an
error after rename. A pending snapshot is re-saved before it is returned after
restart, and duplicate acknowledgments are re-saved before success. This avoids
using a successful Load as proof of durability. A failed acknowledgment restores
in-memory state, while a committed-but-unsynced store can be old or new at restart.
The existing Store atomic/durable-success contract still applies.

Once snapshot delivery has begun, the destructive Digest compatibility reader
returns no lines permanently for that state. This prevents mixed consumers from
consuming pending/new notices outside the queue. This is an opt-in mode transition,
not an automatic migration; rollback to software unaware of the new state needs
a reviewed migration and must not silently reset generation/delivery ownership.

ForgetGoal invalidates a pending snapshot referencing the goal in the same
pipeline-state save as the existing forget. Older receipts below that invalidation
floor are rejected. This covers the pending pipeline copy only. Snapshots already
acknowledged and stored in another component, backups, source/queue cancellation,
transport containment and owner completion require the coordinated forget reach.
Queue.Forget and sender invalidation must complete before an owner is told forget
succeeded. ValidateDigest checks issuance and this pending invalidation floor; it
does not prove UNDO/MORE remains valid, a goal still exists or a queued copy was
purged. Do not use it as the sole send-time validity check.

Tests cover persistent/nonconsuming Peek, restart and old exact Ack, tampering,
owned copies, events appended after Peek, changed staged/installed state, outage
counts, bounded drainage, corrupt counters, failure-before-source-consumption,
shared renderer output and pending-goal invalidation. CAP-3 coverage here is only
that pending-copy regression, not end-to-end forget qualification. Pipeline
adoption/owner-outcome semantics, grants and implicit-acceptance rules are unchanged.
