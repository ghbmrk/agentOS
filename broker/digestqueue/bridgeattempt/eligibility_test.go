package bridgeattempt

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"testing"
	"time"
)

// REQ: CH-15, TIM-1, OP-1, OP-2
func TestSourceRefusedAfterPolicyNeverCallsOwnerAndGateReservesOnce(t *testing.T) {
	q, _, b, n, cfg := rig(t, "Fixed notice.")
	eligible := true
	gates, validations := 0, 0
	refused := errors.New("synthetic source became ineligible")
	cfg.Sources["change"] = func(context.Context, digestqueue.Snapshot) error {
		validations++
		if !eligible {
			return refused
		}
		return nil
	}
	cfg.Gate = func(context.Context, digestqueue.Batch) error { gates++; eligible = false; return nil }
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(t.Context(), b.ID); !errors.Is(err, refused) {
		t.Fatal("stale source dispatched", err)
	}
	if n.calls != 0 || gates != 1 || validations != 2 {
		t.Fatal(n.calls, gates, validations)
	}
	if got := state(t, q, b.ID); got.State != digestqueue.Ready || got.Attempts != 1 {
		t.Fatal("pre-call refusal did not settle exact attempt", got)
	}
}

type eligibilityBeginStore struct {
	digestqueue.Store
	hook func()
}

func (s *eligibilityBeginStore) Save(raw []byte) error {
	if err := s.Store.Save(raw); err != nil {
		return err
	}
	if s.hook != nil {
		h := s.hook
		s.hook = nil
		h()
	}
	return nil
}
func TestExpiryDuringDurableBeginNeverCallsTransport(t *testing.T) {
	_, store, b, n, cfg := rig(t, "Fixed notice.")
	clock := now
	wrapped := &eligibilityBeginStore{Store: store}
	q, err := digestqueue.New(wrapped, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	wrapped.hook = func() { clock = b.Expires }
	cfg.Queue = q
	cfg.Now = func() time.Time { return clock }
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(t.Context(), b.ID); !errors.Is(err, digestqueue.ErrExpired) {
		t.Fatal("expired after Begin reached owner", err)
	}
	if n.calls != 0 {
		t.Fatal(n.calls)
	}
	if got := state(t, q, b.ID); got.State != digestqueue.Ready || got.Attempts != 1 {
		t.Fatal(got)
	}
}
func TestActualHeartbeatRolloverDuringBeginRefusesStaleAliveLine(t *testing.T) {
	clock := now
	s, err := heartbeat.New(heartbeat.Config{Store: &change.MemStore{}, Clock: func() (time.Time, error) { return clock, nil }, Zone: "UTC", Minute: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Plan(t.Context()); err != nil {
		t.Fatal(err)
	}
	store := &eligibilityBeginStore{Store: &change.MemStore{}}
	q, err := digestqueue.New(store, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	collector, err := digestqueue.NewCollector(q, map[string]digestqueue.Source{heartbeat.ID: s})
	if err != nil {
		t.Fatal(err)
	}
	b, err := collector.Collect(t.Context(), now, now.Add(48*time.Hour))
	if err != nil || b == nil {
		t.Fatal(b, err)
	}
	store.hook = func() { clock = now.Add(24 * time.Hour) }
	n := &notice{}
	gates := 0
	a, err := New(Config{Queue: q, Owner: n, Now: func() time.Time { return clock }, Gate: func(context.Context, digestqueue.Batch) error { gates++; return nil }, Sources: map[string]Validator{heartbeat.ID: s.Validate}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(t.Context(), b.ID); !errors.Is(err, heartbeat.ErrStale) {
		t.Fatal("yesterday's alive line sent today", err)
	}
	if n.calls != 0 || gates != 1 {
		t.Fatal(n.calls, gates)
	}
	if got := state(t, q, b.ID); got.State != digestqueue.Ready || got.Attempts != 1 {
		t.Fatal(got)
	}
}

type eligibilityFinishCut struct {
	change.FileStore
	saves int
	after bool
}

func (s *eligibilityFinishCut) Save(raw []byte) error {
	s.saves++
	if s.saves != 5 {
		return s.FileStore.Save(raw)
	}
	if s.after {
		if err := s.FileStore.Save(raw); err != nil {
			return err
		}
	}
	return errors.New("synthetic refusal finish uncertainty")
}
func TestPrecallRefusalFinishUncertaintyNeverCallsOwnerAndReopensConservatively(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			store := &eligibilityFinishCut{FileStore: change.FileStore{Path: t.TempDir() + "/queue.json"}, after: after}
			limits := digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20}
			q, err := digestqueue.New(store, limits)
			if err != nil {
				t.Fatal(err)
			}
			snap, err := digestqueue.NewSnapshot("change", 1, []string{"Fixed notice."}, nil)
			if err != nil {
				t.Fatal(err)
			}
			b, err := q.Enqueue([]digestqueue.Snapshot{snap}, now, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err := q.Acknowledge(b.ID, snap.Source, snap.Generation, snap.Hash); err != nil {
				t.Fatal(err)
			}
			n := &notice{}
			eligible := true
			refused := errors.New("synthetic source refusal")
			a, err := New(Config{Queue: q, Owner: n, Now: func() time.Time { return now }, Gate: func(context.Context, digestqueue.Batch) error { eligible = false; return nil }, Sources: map[string]Validator{"change": func(context.Context, digestqueue.Snapshot) error {
				if !eligible {
					return refused
				}
				return nil
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Send(t.Context(), b.ID); !errors.Is(err, refused) || !errors.Is(err, digestqueue.ErrRecovery) || n.calls != 0 {
				t.Fatal(err, n.calls)
			}
			fresh, err := digestqueue.New(&change.FileStore{Path: store.Path}, limits)
			if err != nil {
				t.Fatal(err)
			}
			want := digestqueue.Unknown
			if after {
				want = digestqueue.Ready
			}
			if got := state(t, fresh, b.ID); got.State != want || got.Attempts != 1 {
				t.Fatal(got)
			}
		})
	}
}
