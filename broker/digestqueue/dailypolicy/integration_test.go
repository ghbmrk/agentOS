package dailypolicy

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/bridgeattempt"
	"github.com/ghbmrk/agentos/broker/grants"
	"path/filepath"
	"testing"
	"time"
)

type beginStore struct {
	dq.Store
	hook func()
}

func (s *beginStore) Save(raw []byte) error {
	if err := s.Store.Save(raw); err != nil {
		return err
	}
	var st struct {
		Batches []dq.Batch `json:"batches"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	for _, b := range st.Batches {
		if b.State == dq.Sending && s.hook != nil {
			fn := s.hook
			s.hook = nil
			fn()
			break
		}
	}
	return nil
}

type ownerRecipient struct{ calls int }

func (o *ownerRecipient) InformContext(context.Context, string) error { o.calls++; return nil }

// REQ: CH-15, TIM-1, OP-1, OP-2
func TestSharedPolicyQuietBoundaryDuringActualBeginReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue")
	st := &beginStore{Store: &change.FileStore{Path: path}}
	limits := dq.Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536}
	q, err := dq.New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := dq.NewSnapshot("fixed", 1, []string{"Fixed broker notice."}, nil)
	b, err := q.Enqueue([]dq.Snapshot{snap}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	q.Acknowledge(b.ID, snap.Source, snap.Generation, snap.Hash)
	g := grants.New(grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 1})
	quiet := false
	cfg := config(g)
	cfg.Quiet = func(time.Time) bool { return quiet }
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st.hook = func() { quiet = true }
	o := &ownerRecipient{}
	a, err := bridgeattempt.New(bridgeattempt.Config{Queue: q, Owner: o, Now: func() time.Time { return now }, Gate: p.Check, Recheck: p.Recheck, Sources: map[string]bridgeattempt.Validator{"fixed": func(context.Context, dq.Snapshot) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(t.Context(), b.ID); !errors.Is(err, ErrQuiet) || o.calls != 0 {
		t.Fatal(err, o.calls)
	}
	if g.Reserve(false) {
		t.Fatal("proven non-send refunded reserved slot")
	}
	fresh, err := dq.New(&change.FileStore{Path: path}, limits)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := fresh.Get(b.ID)
	if err != nil || saved.State != dq.Ready || saved.Attempts != 1 {
		t.Fatal(saved, err)
	}
}
