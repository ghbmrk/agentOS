// Package dailyhost assembles an opt-in daily notification host. Construction
// preserves owner controls but never activates, boots or starts a runner.
package dailyhost

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/daily"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/digestqueue/ownersource"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"math"
	"sync"
	"time"
)

var ErrPolicyRecovery = errors.New("dailyhost: notification policy needs recovery")

var ErrConfig = errors.New("dailyhost: complete exclusive host configuration required")
var ErrPolicy = errors.New("dailyhost: dispatch policy deferred")
var ErrRetention = errors.New("dailyhost: owner notes currently ineligible")
var ErrTransport = errors.New("dailyhost: context transport required")
var ErrRunning = errors.New("dailyhost: runner already active")
var ErrTicker = errors.New("dailyhost: cadence source stopped")

type Config struct {
	// PolicyHealth is an optional read-only bounded accounting health check.
	// Bind dailypolicy.Policy.Health when using durable shared pacing.
	PolicyHealth func() error
	Owner        owner.Config
	Notes        *digestnotes.Source
	// Daily.Owner/Flush and the owner-notes registry entry are owned here; leave
	// them unset. Daily.Gate remains mandatory and implements shared pacing,
	// quiet hours, priority and remaining resource/authority policy.
	Daily daily.Config
	// OwnerNotesEligible is the current retention/forget eligibility check,
	// additional to the adapter's issuance validation. It must be read-only.
	OwnerNotesEligible daily.Validator
	// RetentionDays keeps this many local days of accepted daily history,
	// including today. Unknown and undelivered outcomes are never retired.
	RetentionDays int
	PollInterval  time.Duration
	StepTimeout   time.Duration
}
type Code string

const (
	Held      Code = "held"
	Ready     Code = "ready"
	Idle      Code = "idle"
	Accepted  Code = "transport-accepted"
	Deferred  Code = "policy-deferred"
	Recovery  Code = "recovery-needed"
	Uncertain Code = "delivery-unknown"
	Deadline  Code = "deadline"
	Cancelled Code = "cancelled"
	Refused   Code = "refused"
)

type Status struct {
	Held      bool
	Running   bool
	Steps     uint64
	LastBatch uint64
	Code      Code
	Failures  uint64
}

// Line is fixed owner-only operational wording. It includes neither callback
// error details, paths, receipts, note bodies nor an owner-visibility assertion.
func (s Status) Line() string {
	text := "Daily digest: needs attention."
	switch s.Code {
	case Held:
		text = "Daily digest: held."
	case Ready:
		text = "Daily digest: ready."
	case Idle:
		text = "Daily digest: not due."
	case Accepted:
		text = "Daily digest: accepted by transport."
	case Deferred:
		text = "Daily digest: waiting for notification policy."
	case Recovery:
		text = "Daily digest: storage or source needs recovery."
	case Uncertain:
		text = "Daily digest: delivery unknown; automatic retry held."
	case Deadline:
		text = "Daily digest: step deadline reached."
	case Cancelled:
		text = "Daily digest: step cancelled."
	}
	if s.Held && s.Code != Held {
		text += " Notifications held."
	}
	return text
}

type Host struct {
	cfg       Config
	channel   *owner.Channel
	workflow  *daily.Workflow
	mu        sync.Mutex // short state/activation operations only, no I/O callbacks
	epoch     uint64
	quiescing bool
	st        Status
	newTicker func(time.Duration) (<-chan time.Time, func())
}

func New(cfg Config) (*Host, error) {
	if cfg.Notes == nil || cfg.Owner.Engine == nil || cfg.Owner.Store == nil || cfg.Owner.Now == nil || cfg.Owner.DigestNotes != nil || cfg.Daily.Owner != nil || cfg.Daily.Flush != nil || cfg.Daily.Gate == nil || cfg.Daily.Recheck == nil || cfg.OwnerNotesEligible == nil || cfg.RetentionDays < 1 || cfg.RetentionDays > 3650 || cfg.PollInterval < time.Millisecond || cfg.PollInterval > 24*time.Hour || cfg.StepTimeout < time.Millisecond || cfg.StepTimeout > 5*time.Minute || cfg.StepTimeout > cfg.PollInterval {
		return nil, ErrConfig
	}
	if _, ok := cfg.Daily.Sources[ownersource.ID]; ok {
		return nil, ErrConfig
	}
	if _, ok := cfg.Daily.Validators[ownersource.ID]; ok {
		return nil, ErrConfig
	}
	adapter, err := ownersource.New(cfg.Notes)
	if err != nil {
		return nil, err
	}
	h := &Host{cfg: cfg, st: Status{Held: true, Code: Held}, newTicker: func(d time.Duration) (<-chan time.Time, func()) { t := time.NewTicker(d); return t.C, t.Stop }}
	dc := cfg.Daily
	dc.Sources = make(map[string]dq.Source, len(cfg.Daily.Sources)+1)
	dc.Validators = make(map[string]daily.Validator, len(cfg.Daily.Validators)+1)
	for id, s := range cfg.Daily.Sources {
		dc.Sources[id] = s
	}
	for id, v := range cfg.Daily.Validators {
		dc.Validators[id] = v
	}
	dc.Sources[ownersource.ID] = adapter
	dc.Validators[ownersource.ID] = func(ctx context.Context, s dq.Snapshot) error {
		if err := adapter.Validate(ctx, s); err != nil {
			return err
		}
		if err := cfg.OwnerNotesEligible(ctx, s); err != nil {
			return errors.Join(ErrRetention, err)
		}
		return nil
	}
	dc.Owner = recipient{h}
	dc.Flush = func(ctx context.Context) error {
		if err := h.Health(); err != nil {
			return err
		}
		return h.channel.FlushDigestNotes(ctx)
	}
	dc.Gate = func(ctx context.Context, b dq.Batch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if cfg.Owner.Engine.Stopped() {
			h.Hold()
			return daily.ErrHeld
		}
		if err := h.Health(); err != nil {
			return err
		}
		if err := cfg.Daily.Gate(ctx, b); err != nil {
			return errors.Join(ErrPolicy, err)
		}
		return ctx.Err()
	}
	dc.Recheck = func(ctx context.Context, b dq.Batch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if cfg.Owner.Engine.Stopped() {
			h.Hold()
			return daily.ErrHeld
		}
		if err := h.Health(); err != nil {
			return err
		}
		if err := cfg.Daily.Recheck(ctx, b); err != nil {
			return errors.Join(ErrPolicy, err)
		}
		return ctx.Err()
	}
	h.workflow, err = daily.New(dc)
	if err != nil {
		return nil, err
	}
	oc := cfg.Owner
	oc.Engine = containedEngine{h, cfg.Owner.Engine}
	oc.Notes = append(append([]func() string{}, oc.Notes...), func() string { return h.Status().Line() })
	h.channel, err = owner.NewTransactional(oc, cfg.Notes)
	if err != nil {
		return nil, err
	}
	if h.Health() != nil {
		h.st.Code = Recovery
	}
	return h, nil
}

// Channel is the actual control service; its engine is already wrapped. Its
// transport/producer methods are trusted broker APIs, not alternative host sends.
func (h *Host) Channel() *owner.Channel { return h.channel }
func (h *Host) Health() error {
	if h.channel == nil {
		return ErrConfig
	}
	if err := h.channel.OwnerStateHealth(); err != nil {
		return err
	}
	if h.cfg.Notes.Health() != nil {
		return owner.ErrDigestRecovery
	}
	if err := h.cfg.Daily.Heartbeat.Health(); err != nil {
		return err
	}
	if h.cfg.PolicyHealth != nil && h.cfg.PolicyHealth() != nil {
		return ErrPolicyRecovery
	}
	return nil
}
func (h *Host) Status() Status { h.mu.Lock(); defer h.mu.Unlock(); return h.st }

// Activate requires reviewed authority outside this API. Checks may wait on
// source health, but a concurrent STOP invalidates their generation and never
// waits for them. Successful engine RESUME still requires this fresh operation.
func (h *Host) Activate() error {
	h.mu.Lock()
	epoch := h.epoch
	h.mu.Unlock()
	if err := h.Health(); err != nil {
		return err
	}
	if h.cfg.Owner.Engine.Stopped() {
		return daily.ErrHeld
	}
	if h.cfg.Owner.Modem == nil {
		return ErrTransport
	}
	if _, ok := h.cfg.Owner.Modem.(owner.ContextSender); !ok {
		return ErrTransport
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.quiescing {
		return daily.ErrBusy
	}
	if h.epoch != epoch {
		return daily.ErrHeld
	}
	if err := h.workflow.Activate(); err != nil {
		return err
	}
	h.st.Held = false
	h.st.Code = Ready
	return nil
}
func (h *Host) holdLocked() {
	h.epoch++
	h.workflow.Hold()
	h.st.Held = true
	h.st.Code = Held
}
func (h *Host) Hold() { h.mu.Lock(); defer h.mu.Unlock(); h.holdLocked() }
func (h *Host) record(id uint64, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.st.Steps < math.MaxUint64 {
		h.st.Steps++
	}
	h.st.LastBatch = id
	switch {
	case err == nil && id == 0:
		h.st.Code = Idle
	case err == nil:
		h.st.Code = Accepted
	case errors.Is(err, daily.ErrHeld):
		h.st.Code = Held
	case errors.Is(err, daily.ErrUncertain):
		h.st.Code = Uncertain
	case errors.Is(err, context.DeadlineExceeded):
		h.st.Code = Deadline
	case errors.Is(err, context.Canceled):
		h.st.Code = Cancelled
	case errors.Is(err, ErrPolicyRecovery):
		h.st.Code = Recovery
	case errors.Is(err, ErrPolicy), errors.Is(err, ErrRetention):
		h.st.Code = Deferred
	case errors.Is(err, daily.ErrAssociation), errors.Is(err, dq.ErrRecovery), errors.Is(err, dq.ErrFull), errors.Is(err, owner.ErrDigestRecovery), errors.Is(err, owner.ErrDigestFull), errors.Is(err, heartbeat.ErrRecovery), errors.Is(err, heartbeat.ErrStale):
		h.st.Code = Recovery
	default:
		h.st.Code = Refused
	}
	if err == nil {
		h.st.Failures = 0
	} else if h.st.Failures < math.MaxUint64 {
		h.st.Failures++
	}
}
func (h *Host) Step(ctx context.Context) (uint64, error) {
	if ctx == nil {
		return 0, ErrConfig
	}
	var id uint64
	err := ctx.Err()
	if err == nil && h.cfg.Owner.Engine.Stopped() {
		h.Hold()
		err = daily.ErrHeld
	}
	if err == nil {
		err = h.Health()
	}
	if err == nil {
		_, err = h.workflow.Maintain(ctx, h.cfg.RetentionDays)
		if err == nil {
			id, err = h.workflow.Step(ctx)
		}
	}
	h.record(id, err)
	return id, err
}

// Quiesce revokes activation even on deadline/error and serializes mutation
// against all workflow activity. It is not proof of a complete forget reach.
func (h *Host) Quiesce(ctx context.Context, fn func(context.Context) error) error {
	if ctx == nil || fn == nil {
		return ErrConfig
	}
	h.mu.Lock()
	if h.quiescing {
		h.mu.Unlock()
		return daily.ErrBusy
	}
	h.quiescing = true
	h.holdLocked()
	h.mu.Unlock()
	defer func() { h.mu.Lock(); h.quiescing = false; h.mu.Unlock() }()
	return h.workflow.Quiesce(ctx, fn)
}

// Run has one runner, one step at a time and no per-step goroutine. It samples
// immediately and then on a fixed ticker; missed ticks do not form a backlog.
// Caller cancellation holds admission and propagates into the active step.
// Synchronous stores cannot be interrupted: Run waits for the step to return.
func (h *Host) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	if h.st.Running {
		h.mu.Unlock()
		return ErrRunning
	}
	h.st.Running = true
	h.mu.Unlock()
	defer func() { h.Hold(); h.mu.Lock(); h.st.Running = false; h.mu.Unlock() }()
	ticks, stop := h.newTicker(h.cfg.PollInterval)
	defer stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		step, cancel := context.WithTimeout(ctx, h.cfg.StepTimeout)
		_, _ = h.Step(step)
		cancel()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-ticks:
			if !ok {
				return ErrTicker
			}
		}
	}
}

type recipient struct{ h *Host }

func (r recipient) InformContext(ctx context.Context, text string) error {
	if r.h.channel == nil {
		return ErrConfig
	}
	return r.h.channel.InformContext(ctx, text)
}

type containedEngine struct {
	h *Host
	e control.Engine
}

func (e containedEngine) Stop(ctx context.Context) (journal.StopReport, error) {
	e.h.Hold()
	return e.e.Stop(ctx)
}
func (e containedEngine) Resume() error          { return e.e.Resume() }
func (e containedEngine) Stopped() bool          { return e.e.Stopped() }
func (e containedEngine) List() []journal.Status { return e.e.List() }
