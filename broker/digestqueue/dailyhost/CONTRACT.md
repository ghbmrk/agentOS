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
