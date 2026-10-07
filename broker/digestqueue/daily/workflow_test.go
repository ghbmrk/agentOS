package daily

import (
	"context"
	"errors"
	"fmt"
	"github.com/ghbmrk/agentos/broker/change"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/journal"
	"path/filepath"
	"testing"
	"time"
)

type recipient struct {
	calls int
	err   error
}

func (r *recipient) InformContext(context.Context, string) error { r.calls++; return r.err }

type notes struct {
	snap *dq.Snapshot
	acks int
	peek func(context.Context) error
}

func (n *notes) Peek(ctx context.Context) (*dq.Snapshot, error) {
	if n.peek != nil {
		if err := n.peek(ctx); err != nil {
			return nil, err
		}
	}
	return n.snap, nil
}
func (n *notes) Ack(_ context.Context, s dq.Snapshot) error {
	n.acks++
	if n.snap != nil && n.snap.Hash == s.Hash {
		n.snap = nil
	}
	return nil
}

type fixture struct {
	now     time.Time
	dir     string
	r       recipient
	n       notes
	gateErr error
	w       *Workflow
	q       *dq.Queue
	hb      *heartbeat.Source
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Date(2026, 10, 7, 11, 0, 0, 0, time.UTC), dir: t.TempDir()}
	f.open(t)
	return f
}
func (f *fixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.q, err = dq.New(&change.FileStore{Path: filepath.Join(f.dir, "queue")}, dq.Limits{MaxBatches: 16, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	f.hb, err = heartbeat.New(heartbeat.Config{Store: &change.FileStore{Path: filepath.Join(f.dir, "heartbeat")}, Clock: func() (time.Time, error) { return f.now, nil }, Zone: "UTC", Minute: 720})
	if err != nil {
		t.Fatal(err)
	}
	f.w, err = New(Config{Queue: f.q, Heartbeat: f.hb, Sources: map[string]dq.Source{"notes": &f.n}, Validators: map[string]Validator{"notes": func(context.Context, dq.Snapshot) error { return nil }}, Owner: &f.r, Clock: func() (time.Time, error) { return f.now, nil }, TTL: time.Hour, Flush: func(context.Context) error { return nil }, Gate: func(context.Context, dq.Batch) error { return f.gateErr }})
	if err != nil {
		t.Fatal(err)
	}
}

// REQ: CH-15, TIM-1, OP-1, OP-2
func TestDailyCadenceAggregatesOnceAndReopens(t *testing.T) {
	f := setup(t)
	s, _ := dq.NewSnapshot("notes", 1, []string{"Guard challenge observed."}, nil)
	f.n.snap = &s
	if _, err := f.w.Step(t.Context()); !errors.Is(err, ErrHeld) {
		t.Fatal(err)
	}
	if err := f.w.Activate(); err != nil {
		t.Fatal(err)
	}
	if id, err := f.w.Step(t.Context()); err != nil || id != 0 || f.n.acks != 0 {
		t.Fatal(id, err, f.n.acks)
	}
	f.now = f.now.Add(time.Hour)
	id, err := f.w.Step(t.Context())
	if err != nil || id == 0 || f.r.calls != 1 || f.n.acks != 1 {
		t.Fatal(id, err, f.r.calls, f.n.acks)
	}
	s2, _ := dq.NewSnapshot("notes", 2, []string{"Later challenge."}, nil)
	f.n.snap = &s2
	f.open(t)
	f.w.Activate()
	again, err := f.w.Step(t.Context())
	if err != nil || again != id || f.r.calls != 1 || f.n.acks != 1 {
		t.Fatal(again, err)
	}
	f.now = f.now.Add(24 * time.Hour)
	next, err := f.w.Step(t.Context())
	if err != nil || next == id || f.r.calls != 2 || f.n.acks != 2 {
		t.Fatal(next, err)
	}
}
func TestPolicyRefusalRetriesSameBatchWithoutRecollection(t *testing.T) {
	f := setup(t)
	f.now = f.now.Add(time.Hour)
	f.w.Activate()
	f.gateErr = errors.New("quiet")
	id, err := f.w.Step(t.Context())
	if !errors.Is(err, f.gateErr) || id == 0 || f.r.calls != 0 {
		t.Fatal(id, err)
	}
	f.open(t)
	f.w.Activate()
	f.gateErr = nil
	again, err := f.w.Step(t.Context())
	if err != nil || again != id || f.r.calls != 1 {
		t.Fatal(again, err)
	}
}
func TestAmbiguousDeliveryNeverCreatesReplacement(t *testing.T) {
	f := setup(t)
	f.now = f.now.Add(time.Hour)
	f.r.err = errors.New("unknown transport")
	f.w.Activate()
	id, err := f.w.Step(t.Context())
	if err == nil || id == 0 {
		t.Fatal(id, err)
	}
	f.open(t)
	f.w.Activate()
	again, err := f.w.Step(t.Context())
	if !errors.Is(err, ErrUncertain) || again != id || f.r.calls != 1 {
		t.Fatal(again, err, f.r.calls)
	}
}

// REQ: CH-2, OP-1
func TestHoldCancelsCollectionAndQuiescenceWaits(t *testing.T) {
	f := setup(t)
	f.now = f.now.Add(time.Hour)
	entered := make(chan struct{})
	leave := make(chan struct{})
	f.n.peek = func(ctx context.Context) error { close(entered); <-ctx.Done(); <-leave; return ctx.Err() }
	f.w.Activate()
	done := make(chan error, 1)
	go func() { _, err := f.w.Step(context.Background()); done <- err }()
	<-entered
	f.w.Hold()
	if err := f.w.Activate(); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	called := false
	if err := f.w.Quiesce(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal(err, called)
	}
	close(leave)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.r.calls != 0 {
		t.Fatal("sent after hold")
	}
	if err := f.w.Quiesce(t.Context(), func(context.Context) error { called = true; return nil }); err != nil || !called {
		t.Fatal(err)
	}
	if _, err := f.w.Step(t.Context()); !errors.Is(err, ErrHeld) {
		t.Fatal(err)
	}
}
func TestMissingAcknowledgedAssociationHolds(t *testing.T) {
	f := setup(t)
	f.now = f.now.Add(time.Hour)
	f.hb.Plan(t.Context())
	s, _ := f.hb.Peek(t.Context())
	f.hb.Ack(t.Context(), *s)
	f.w.Activate()
	if _, err := f.w.Step(t.Context()); !errors.Is(err, ErrAssociation) {
		t.Fatal(err)
	}
	if f.r.calls != 0 {
		t.Fatal(f.r.calls)
	}
}

type cutStore struct {
	dq.Store
	saves int
	cut   int
	after bool
}

func (s *cutStore) Save(b []byte) error {
	s.saves++
	if s.saves == s.cut {
		if s.after {
			if err := s.Store.Save(b); err != nil {
				return err
			}
		}
		return errors.New("synthetic persistence cut")
	}
	return s.Store.Save(b)
}

// REQ: OP-1, OP-2, CH-15
func TestActualQueueReplacementCutsRecoverSameDailyIdentity(t *testing.T) {
	for _, cut := range []int{2, 3, 4, 5} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("save-%d-after-%t", cut, after), func(t *testing.T) {
				f := setup(t)
				f.now = f.now.Add(time.Hour)
				st := &cutStore{Store: &change.FileStore{Path: filepath.Join(f.dir, "queue")}, cut: cut, after: after}
				var err error
				f.q, err = dq.New(st, dq.Limits{MaxBatches: 16, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536})
				if err != nil {
					t.Fatal(err)
				}
				f.w, err = New(Config{Queue: f.q, Heartbeat: f.hb, Owner: &f.r, Clock: func() (time.Time, error) { return f.now, nil }, TTL: time.Hour, Flush: func(context.Context) error { return nil }, Gate: func(context.Context, dq.Batch) error { return nil }})
				if err != nil {
					t.Fatal(err)
				}
				f.w.Activate()
				if _, err = f.w.Step(t.Context()); err == nil {
					t.Fatal("cut did not fail")
				}
				before := f.r.calls
				f.open(t)
				f.w.Activate()
				id, err := f.w.Step(t.Context())
				if id != 1 {
					t.Fatal("replaced daily identity", id, err)
				}
				if cut == 4 && after || cut == 5 && !after {
					if !errors.Is(err, ErrUncertain) || f.r.calls != before {
						t.Fatal("retried uncertain", err, f.r.calls, before)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if f.r.calls > 1 {
					t.Fatal("duplicate owner call", f.r.calls)
				}
			})
		}
	}
}

type testEngine struct{ stopped bool }

func (e *testEngine) Stop(context.Context) (journal.StopReport, error) {
	e.stopped = true
	return journal.StopReport{}, nil
}
func (e *testEngine) Resume() error          { e.stopped = false; return nil }
func (e *testEngine) Stopped() bool          { return e.stopped }
func (e *testEngine) List() []journal.Status { return nil }

// REQ: CH-2
func TestWrappedEngineResumeDoesNotReactivateWorkflow(t *testing.T) {
	f := setup(t)
	f.w.Activate()
	raw := &testEngine{}
	e, err := f.w.WrapEngine(raw)
	if err != nil {
		t.Fatal(err)
	}
	e.Stop(t.Context())
	if !e.Stopped() {
		t.Fatal("not stopped")
	}
	e.Resume()
	if e.Stopped() {
		t.Fatal("still stopped")
	}
	if _, err := f.w.Step(t.Context()); !errors.Is(err, ErrHeld) {
		t.Fatal("resume released daily", err)
	}
}
func TestCancelledCurrentDoesNotExposeAcknowledgedIdentity(t *testing.T) {
	f := setup(t)
	f.now = f.now.Add(time.Hour)
	f.hb.Plan(t.Context())
	s, _ := f.hb.Peek(t.Context())
	f.hb.Ack(t.Context(), *s)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if s, err := f.hb.Current(ctx); s != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(s, err)
	}
}
