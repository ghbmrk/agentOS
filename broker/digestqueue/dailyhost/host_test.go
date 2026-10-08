package dailyhost

import (
	"context"
	"errors"
	"fmt"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/daily"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type engine struct {
	mu      sync.Mutex
	stopped bool
}

func (e *engine) Stop(context.Context) (journal.StopReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
	return journal.StopReport{}, nil
}
func (e *engine) Resume() error          { e.mu.Lock(); defer e.mu.Unlock(); e.stopped = false; return nil }
func (e *engine) Stopped() bool          { e.mu.Lock(); defer e.mu.Unlock(); return e.stopped }
func (e *engine) List() []journal.Status { return nil }

type transport struct {
	mu       sync.Mutex
	calls    int
	to, text string
	hook     func(context.Context) error
}

func (m *transport) Number() string            { return "+15550000001" }
func (m *transport) Inbox() <-chan modem.SMS   { return nil }
func (m *transport) Send(string, string) error { return nil }
func (m *transport) SendContext(ctx context.Context, to, text string) error {
	m.mu.Lock()
	m.calls++
	m.to = to
	m.text = text
	m.mu.Unlock()
	if m.hook != nil {
		return m.hook(ctx)
	}
	return nil
}
func (m *transport) count() int { m.mu.Lock(); defer m.mu.Unlock(); return m.calls }

type rig struct {
	cfg Config
	now time.Time
	h   *Host
	m   *transport
	e   *engine
}

func setup(t *testing.T) *rig {
	t.Helper()
	r := &rig{now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC), m: &transport{}, e: &engine{}}
	dir := t.TempDir()
	n, err := digestnotes.New(digestnotes.Config{Store: &change.FileStore{Path: filepath.Join(dir, "notes")}, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	q, err := dq.New(&change.FileStore{Path: filepath.Join(dir, "queue")}, dq.Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	clock := func() (time.Time, error) { return r.now, nil }
	hb, err := heartbeat.New(heartbeat.Config{Store: &change.FileStore{Path: filepath.Join(dir, "heartbeat")}, Clock: clock, Zone: "UTC", Minute: 720})
	if err != nil {
		t.Fatal(err)
	}
	r.cfg = Config{Owner: owner.Config{Owner: "+15550000999", Store: owner.FileStore{Path: filepath.Join(dir, "owner")}, Engine: r.e, Modem: r.m, Now: func() time.Time { return r.now }, Location: time.UTC}, Notes: n, Daily: daily.Config{Queue: q, Heartbeat: hb, Clock: clock, TTL: time.Hour, Gate: func(context.Context, dq.Batch) error { return nil }}, OwnerNotesEligible: func(context.Context, dq.Snapshot) error { return nil }, PollInterval: time.Minute, StepTimeout: time.Second}
	r.h, err = New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// REQ: CH-15, CH-18, OP-1, OP-2
func TestPublicHostAssemblesActualTransactionalChannelAndFixedRecipient(t *testing.T) {
	r := setup(t)
	if _, err := r.h.Step(t.Context()); !errors.Is(err, daily.ErrHeld) {
		t.Fatal(err)
	}
	if _, err := r.h.Channel().LocalSignIn("100000"); !errors.Is(err, owner.ErrWrongCode) {
		t.Fatal(err)
	}
	if err := r.h.Activate(); err != nil {
		t.Fatal(err)
	}
	id, err := r.h.Step(t.Context())
	if err != nil || id == 0 || r.m.count() != 1 {
		t.Fatal(id, err, r.m.count())
	}
	r.m.mu.Lock()
	text, to := r.m.text, r.m.to
	r.m.mu.Unlock()
	if to != r.cfg.Owner.Owner || !strings.Contains(text, heartbeat.Line) || !strings.Contains(text, "wrong codes entered on the box") {
		t.Fatal(to, text)
	}
	if s := r.h.Status(); s.Code != Accepted || s.LastBatch != id || s.Steps != 2 || s.Running {
		t.Fatal(s)
	}
}

// REQ: CH-2
func TestHostChannelStopAndResumeNeverAutoActivate(t *testing.T) {
	r := setup(t)
	r.h.Activate()
	if err := r.h.Channel().LocalStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s := r.h.Status(); !s.Held {
		t.Fatal(s)
	}
	if _, err := r.h.Channel().LocalResume(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.h.Step(t.Context()); !errors.Is(err, daily.ErrHeld) {
		t.Fatal(err)
	}
	if r.m.count() != 0 {
		t.Fatal("transport after STOP")
	}
}

type badOwnerStore struct{}

func (badOwnerStore) Load() (owner.State, error) {
	return owner.State{}, errors.New("synthetic private backend path")
}
func (badOwnerStore) Save(owner.State) error { panic("recovering owner must not write") }
func TestHostRecoveryStartupKeepsControlAndFixedStatus(t *testing.T) {
	r := setup(t)
	r.cfg.Owner.Store = badOwnerStore{}
	var err error
	r.h, err = New(r.cfg)
	if err != nil || r.h.Channel() == nil {
		t.Fatal(err)
	}
	if err = r.h.Activate(); err == nil {
		t.Fatal("recovery activated")
	}
	if !r.h.Status().Held || strings.Contains(r.h.Status().Line(), "private") {
		t.Fatal(r.h.Status())
	}
	if err = r.h.Channel().LocalStop(t.Context()); err != nil || !r.e.Stopped() {
		t.Fatal(err)
	}
	if r.m.count() != 0 {
		t.Fatal("recovery sent")
	}
}
func TestHostCannotReplaceTheOwnedSenderOrProducer(t *testing.T) {
	for _, which := range []string{"sender", "flush", "notes", "retention", "poll", "timeout"} {
		t.Run(which, func(t *testing.T) {
			r := setup(t)
			switch which {
			case "sender":
				r.cfg.Daily.Owner = r.h.Channel()
			case "flush":
				r.cfg.Daily.Flush = func(context.Context) error { return nil }
			case "notes":
				r.cfg.Owner.DigestNotes = r.cfg.Notes
			case "retention":
				r.cfg.OwnerNotesEligible = nil
			case "poll":
				r.cfg.PollInterval = 0
			case "timeout":
				r.cfg.StepTimeout = 0
			}
			if _, err := New(r.cfg); !errors.Is(err, ErrConfig) {
				t.Fatal(err)
			}
		})
	}
}

// REQ: TIM-1, CH-15
func TestHostPolicyAndRetentionRefusalRemainPendingAndPrivate(t *testing.T) {
	for _, retention := range []bool{false, true} {
		t.Run(fmt.Sprint(retention), func(t *testing.T) {
			r := setup(t)
			canary := errors.New("synthetic private policy detail")
			if retention {
				r.cfg.OwnerNotesEligible = func(context.Context, dq.Snapshot) error { return canary }
				r.h.Channel().LocalSignIn("100000")
			} else {
				r.cfg.Daily.Gate = func(context.Context, dq.Batch) error { return canary }
			}
			h, err := New(r.cfg)
			if err != nil {
				t.Fatal(err)
			}
			h.Activate()
			if _, err = h.Step(t.Context()); !errors.Is(err, canary) {
				t.Fatal(err)
			}
			if r.m.count() != 0 || strings.Contains(h.Status().Line(), canary.Error()) {
				t.Fatal(h.Status())
			}
		})
	}
}
