# Opt-in daily host

`New` constructs the owner channel, typed owner-note adapter and daily workflow
as one assembly. It owns the transactional flush and notification recipient;
alternate sender/flush wiring and duplicate owner-note registrations are refused.
The underlying owner config must provide its real engine, state store and clock.
The source, heartbeat and queue must already be verified, privately protected,
single-writer objects. Additional source validators remain a closed registry.

The owner channel's engine is wrapped before it becomes available: every text or
local STOP cancels host collection/transport admission before delegating to the
engine. `Channel()` is the actual control service and preserves the existing
recovery-only startup contract. Opening owner state failure returns a held host
and recovery-only channel, not a downgraded legacy producer. `Health` must pass
before activation. Backend details never appear in host status wording.

Construction does not activate, start timers, call Channel.Boot or serve the
modem. The reviewed host lifecycle must handle owner Boot/reissue and inbound
serving as usual, and register `Run` separately. Calling Channel.Run includes its
normal Boot behavior. The runner must not substitute for those control services.
All daemon defaults and existing legacy constructor selection remain unchanged.

`Activate` is a trusted composition operation after authenticated authority and
resource review. It requires healthy source/owner state, an unstopped engine and
context-capable transport. STOP invalidates an activation already checking
health; an engine Resume never releases notifications automatically. Every send
still checks engine STOP, health, the supplied policy and current source receipts.
The owner-note validator checks issuance and then the mandatory read-only
retention/forget callback. That callback cannot serve as proof of a complete
forget reach. All invalidation uses host Quiesce, which excludes activation,
waits for workflow activity and retains the hold on all outcomes.

The supplied Daily.Gate must use the existing shared approval/question budget
and implement quiet hours, priority, resource and remaining authority rules.
No new budget is created here. The clocks supplied to owner, heartbeat and daily
workflow must come from the same trusted health-aware time basis. A zero/error
heartbeat clock blocks scheduling. The owner config's clock remains part of its
existing authority contract, not newly qualified by host construction.

`Run` accepts explicit poll and step-timeout bounds. It takes an immediate sample,
then polls on one fixed ticker, runs steps serially and starts no per-step
goroutine. Missed ticks do not form a catch-up backlog. Only one runner is allowed;
Run does not call Activate. Caller cancellation propagates into the active step
and finalizes the host held. Individual step deadlines do not release or invent
new daily batches. A closed cadence ends the runner held. `Status` is a small
saturating operational snapshot; the channel appends its fixed line to normal
owner STATUS. Transport acceptance remains distinct from visibility.

Callbacks and synchronous stores need bounded latency and cancellation handling.
Deadlines cannot interrupt a synchronous Save or a provider that never returns;
Run waits rather than abandoning a goroutine that could later send or persist.
STOP's hold never waits for such callbacks or health checks. Health failure needs
fresh verified assembly and reviewed paired-store recovery. Direct unwrapped
engine calls, direct channel Inform sends, duplicate store writers and source
mutations outside the coordinator violate the integration contract.

Local tests cover actual transactional owner/adapter/queue construction, fixed
recipient/context send, recovery-only controls, private policy/retention refusal,
STOP/resume and stale activation, serial runner/cancellation/deadline handling,
ambiguous outcomes and quiescent invalidation. Synthetic transports are local
observations, not carrier evidence. Independent strongest broker/security review,
upstream reconciliation, encrypted state, full reach/restore and deployment
qualification remain required. Nothing merged or enabled by daemon defaults.

## Explicit accepted-history retention (W5-D34)

`RetentionDays` is required, from 1 through 3650, and includes today. Each host
step runs serialized maintenance before normal collection/dispatch. Maintenance
repairs incomplete source acknowledgments first and selects only fully
acknowledged, non-redacted transport-accepted daily batches whose authentic
heartbeat age reaches that many local calendar days. UTC date arithmetic counts
calendar days across DST rather than treating every local day as 24 hours.

Current-day association is never retired, including after heartbeat Ack. No
unknown, sending, Ready, expired, cancelled or exhausted outcome is automatically
hidden, regardless of age or capacity pressure. Such records can still fill the
queue and require visible recovery. Retention must leave enough capacity for the
window and unresolved records; the host does not silently shorten it. Never call
the blanket Queue.Compact behind the workflow: it can remove current-day identity
and leave the heartbeat's acknowledged receipt without an association.

Selected compaction checks the whole set before saving, requires terminal/full
acknowledgment and retains private source high-water identities and monotone
batch IDs. Save errors quarantine the queue; verified reopen observes either
retained or retired history without recreating daily IDs. These changes remove
payload/history, not high-water metadata, backup copies or evidence retained
elsewhere; they do not establish complete forget or owner/carrier visibility.
A retention change is an explicit trusted configuration decision, not guest data.
No timer is enabled through daemon defaults.

## Two-phase notification policy (W5-D35)

Daily.Gate and Daily.Recheck are both required. The former reserves once;
the latter is read-only and repeats current policy after durable Begin, before
transport. `dailypolicy.Check` / `Recheck` use the existing shared grants budget,
trusted clock, quiet hours, STOP and a mandatory resource/authority callback.
Host wrappers add owner/source health and real engine STOP checks to both phases.
Neither a final refusal nor affirmative non-send refunds the original slot.
Callbacks must be repeatable; policy health is not owner authentication.

## Assembled bridge fixture (W5-D36)

The runtime fixture now composes real transactional owner events, separately
reopened owner/notes/heartbeat/queue files, the host runner, the shared grants
policy and actual modemlink bridge operation handlers. It verifies due-time
aggregation, bridge acceptance, no same-day resend, four-file reopen without
notice resurrection and next-day retirement/monotone identity. Text and local
STOP are tested during actual Begin persistence and after bridge handoff; only
proven pre-call cancellation is retried, and late results remain stray while
Unknown persists across reopen. Quiescence waits for actual accepted Finish
persistence while owner STOP remains prompt.

Cadence triggers and the engine are controlled local fixtures. The initial
wrong-code event is recorded by a quiescent public transactional channel before
installing a modem, avoiding an unrelated urgent alert send in these cases.
Reconstruction never operates duplicate store writers concurrently. Bridge
operations are invoked locally, not through production sockets or a carrier.
Trusted fixture engine release is not owner authentication. These tests strengthen
composition evidence without qualifying real devices, line priority (#254),
startup Boot/reissue, durable pacing restart behavior or independent acceptance.


Optional accounting health: when the common Gate has a PacingStore, bind
`Config.PolicyHealth = policy.Health` alongside Daily.Gate/Check and
Daily.Recheck/Recheck. This read-only, bounded callback runs outside the host
mutex in constructor Health, Activate, Step and the existing dispatch health wrappers.
Any callback error becomes fixed ErrPolicyRecovery; Step reports Recovery
without recording its private details, collecting or invoking transport.
Allowance exhaustion is healthy and retains the ordinary policy-deferred path.
The option remains nil for older callers; caller completeness must be reviewed,
not inferred from opaque policy callback identities. This is not daemon wiring.

A blocked accounting-health callback cannot hold the host admission mutex:
LocalStop invalidates activation before delegating physical STOP. Physical
resume alone cannot revive the stale activation when health eventually returns.
Synchronous health/store callbacks still require latency bounds and can delay
other policy work; no orphanable timeout worker or background repair is added.
Reopening must retire the old writer and preserve the exact same store. A fresh
store, restore or deletion cannot be used as recovery for a spent allowance.

Five-store integration evidence (D39): the local bridge fixture can opt into a
separate change.FileStore for the actual shared Gate, reconstruct that Gate on
reopen, and bind Policy.Health in the new Host. Reopen quiesces the old entire
scope and reconstructs owner, notes, heartbeat, queue and Gate from unchanged
paths; startup remains held. Actual question Books reserve on that same Gate
and send through owner.Channel.Notify and the real local modemlink operations.
The fixture's Book has no persistence path: these tests establish notification
debt continuity, not durable custody or replay semantics of question prompts.

Accepted and unknown outcomes keep exact batch/attempt identity across all five
stores, shared question debt survives, and late bridge acceptance stays stray.
Paced Ready work survives reopen without a send attempt and sends the same
batch only when older debt expires before its TTL. Before/after ledger-save
cuts refuse bridge handoff, expose fixed host recovery, and recover precisely
the committed debt before retry. Clearing a store fault cannot clear the live
quarantined Gate. LocalStop while ledger persistence is blocked remains prompt,
spends that reservation and allows no bridge call; explicit fresh activation
and the same stores are needed for later retry, without refund.

These are characterization tests of existing constructors and policies, not a
new production pathway or a fabricated failing implementation. The first test
trial used incorrect alive-line wording; it was corrected to heartbeat.Line,
and the trial is retained. Existing four-store fixtures remain volatile and
keep their original scope. Local engine/cadence/bridge fixtures do not qualify
real daemon startup, carrier/device delivery, callback latency, arbitrary
restore/deletion, protected path custody or multiple writers. D37's urgent/
reissue storage-fault availability hold and independent security review remain.

## Opt-in provisioned shared-policy assembly

`NewProvisioned(hostConfig, policyConfig)` reuses the existing host and
`dailypolicy.New`, binding Check/Recheck/Health together to one provided actual
shared Gate and `hostConfig.Owner.Engine`. Leave Daily.Gate, Daily.Recheck,
PolicyHealth and policyConfig.Engine unset; conflicting bindings are refused
with fixed ErrConfig before host construction. Explicit trusted Clock, Quiet,
Eligible and AgedAfter remain required. These checks do not authorize activation.

The Gate's `ProvisionedPacingConfigured` method examines only immutable
constructor options: non-nil Store, PacingRequireExisting=true and positive
PacingMaxStoreLatency no greater than five minutes. It performs no I/O, changes
no counter and certifies neither the durable bytes nor storage custody. No
provisioning or alternative counter is created by this assembly. Valid options
with a missing, malformed, faulted or overdue ledger produce a held recovery
host, whose Channel preserves owner controls. Bound policy health refuses
activation/steps and supplies fixed recovery wording without private errors.
Synchronous store calls remain uninterruptible; a Gate stuck during construction
never reaches this constructor, so an independent startup control/recovery path
is still required. Invalid assembly options yield no Host. Do not use those
errors to silently downgrade to volatile accounting or reset the installation.

Caller custody must supply the same Gate to approvals, question.Config.Reserve
and this policy. This constructor prevents conflicting host policy callbacks;
it cannot inspect every external consumer or prove deployment identity. Trusted
persistent required-mode/threshold configuration, provisioning authority,
exclusive protected store paths/writers, bounded reads and actual latency must
be independently reviewed before wiring. Missing-image detection under required
mode is not authenticated anti-deletion/rollback/restore/config-integrity proof.
The D37 urgent/reissue storage/time-fault availability hold is unchanged and
applies to overdue I/O. No daemon default, runner, timer or route is activated.

Tests-first behavior exposed permissive generic policy assembly and ambiguous
callbacks/engines. New tests cover incomplete configurations, missing-image
held recovery/STOP, actual question Book plus exactly-once digest reservation
and strict FileStore debt reopen, failure propagation and a still-blocked ledger
with host recovery/STOP. Local results are not deployment qualification, CI
green or independent broker/security acceptance.

D52 characterizes complete registered approval/question/host handoffs with one
StartupSlot/session/Gate, actual transactional Channel and journal Engine. Owner
STOP and host workflow quiescence remain available while a synchronous approval
notice and question send are blocked. Each remaining scope independently keeps
the lease and startup slot occupied; only complete external Drain permits strict
reopen, with all three reservations still spent. The fixture owns its journal
medium until all handoffs return; no background runner, approved grant executor,
future Book callback or escaped permission exists. A pending request is retained
state, not continuing work. This test does not supply the actual daemon routing,
consumer registration enforcement, permission revocation, provisioning, trusted
config persistence or filesystem/latency qualifications held in W5-D47-Q and
W5-D50-Q/W5-D51-Q. Never await Close/Drain within a registered Use callback.
