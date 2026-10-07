# W5-D29 durable daily alive source

The current collector returns nil when every source is empty. This explicitly
configured Source supplies the fixed line "Box is running." for that daily case.
Plan(ctx) stages one receipt per eligible trusted local day; it starts no timer,
does not call a sender or infer visibility. When composed alongside other sources,
the alive line remains truthful rather than saying nothing happened despite their
activity. No daemon registration or default settings are enabled.

Configuration requires a trusted atomic Clock observation that reports any time
restriction as an error, an explicit IANA zone or UTC (never host Local), an owner-
configured wall minute, and one private Store. Local-day comparison prevents day
rollback from resetting cadence. Comparing the observed wall minute, rather than
constructing an ambiguous local timestamp, permits the first minute after a spring
gap and prevents a repeated fall hour from issuing twice. Within-day clock health
and authenticated/network/carrier time remain the Clock provider's responsibility.
Time-sensitive Plan, Peek and Validate hold on restriction. Clock errors are fixed
classes, not the Clock provider's private diagnostic text.

The source persists schema/configuration, a private source key, monotone issuance
and acknowledgment generations, the last issued local day and one pending queue
snapshot. Opening strictly validates and re-saves observed state before use.
Changing zone or minute against retained state refuses without overwriting it;
owner settings changes need a reviewed cadence migration, not automatic reset.
Generation exhaustion and oversized/malformed state refuse. A Store.Save error
quarantines the instance until a fresh object confirms observed durable state.

Peek does not consume and copies returned data. The source receipt is a bounded,
canonical authenticated (generation, day) record whose MAC also binds zone/minute
and the fixed line's source domain. Re-encoding a receipt cannot mint a different
eligible outer hash. The source key never leaves its private Store. Receipts are
broker-private and must never be texted. Ack checks exact issuance and preserves
later days; already acknowledged authentic receipts remain idempotent across
reopen. Ack deliberately does not require a healthy clock, so a previously admitted
association can finish recovery during restriction without granting dispatch.

An unacknowledged older day is retained and reported stale rather than replaced.
Validate refuses an authentic older-day alive line at current-day dispatch; it
cannot masquerade as fresh liveness. After source acknowledgment, the last-day
ledger prevents a new receipt merely because collection or transport is uncertain.
A distinct following day's heartbeat may be issued, subject to reviewed dispatch
policy. Paired source/queue backups and reset identity require explicit migration.

The real collector test admits and acknowledges one otherwise-empty daily batch,
with Ready state, zero transport attempts and no acceptance inference. Actual file
cuts cover both sides of Plan/Ack replacement, with independent reopen and exact
same-day generation retention. These are caller-error cuts, not power-loss proofs.

This separate component reuses queue Source/Store/Snapshot and standard HMAC:
guard-note Event intentionally cannot express liveness or scheduling policy.
Durable source issuance is not daily delivery qualification. A scheduler, fresh
clock/quiet-hours/STOP/shared pacing and resource checks, the containment controller,
transport classification, privacy/retention/forget rules, encrypted storage and
single-writer ownership remain composition gates. Strongest independent broker/
security threat review is required; no deployment or complete CH-15 claim is made.

## W5-D31 clock observation boundaries

A zero/uninitialized time observation refuses even when the provider returned no
error; it cannot manufacture an alive receipt at the zero-time epoch. Plan, Peek
and Validate recheck context after the trusted Clock callback, before staging or
publishing eligibility. Cancellation during that callback therefore preserves
stored bytes and cannot produce a newly admitted heartbeat or successful validation.
Clock callbacks still require bounded latency: cancellation does not interrupt a
provider that never returns, or an already-entered synchronous Store.Save.
