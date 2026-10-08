package dailypolicy

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/bridgeattempt"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/question"
)

type ledgerCut struct {
	file        *change.FileStore
	fail, after bool
}

func (s *ledgerCut) Load() ([]byte, error) { return s.file.Load() }
func (s *ledgerCut) Save(b []byte) error {
	if !s.fail {
		return s.file.Save(b)
	}
	if s.after {
		if err := s.file.Save(b); err != nil {
			return err
		}
	}
	return errors.New("synthetic private ledger path canary")
}

// REQ: CH-15, CAP-10
func TestActualQuestionAndDigestAllowanceSurvivesFileReopen(t *testing.T) {
	clock := now
	path := filepath.Join(t.TempDir(), "budget")
	open := func() (*grants.Gate, *Policy, *question.Book, *int) {
		g := grants.New(grants.Config{Now: func() time.Time { return clock }, RequestsPerHour: 2, PacingStore: &change.FileStore{Path: path}})
		cfg := config(g)
		cfg.Clock = func(context.Context) (time.Time, error) { return clock, nil }
		p, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		sent := new(int)
		book, err := question.New(question.Config{Send: func(string) error { *sent++; return nil }, Now: cfg.Clock, Reserve: g.Reserve})
		if err != nil {
			t.Fatal(err)
		}
		return g, p, book, sent
	}
	ask := func(book *question.Book, key string) question.Status {
		r, err := book.Ask(t.Context(), "synthetic-agent", key, question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	g, p, book, sent := open()
	if ask(book, "first").State != question.Waiting || *sent != 1 {
		t.Fatal("first question not sent")
	}
	if err := p.Check(t.Context(), batch()); err != nil {
		t.Fatal(err)
	}
	g, p, book, sent = open()
	if err := p.Health(); err != nil {
		t.Fatal(err)
	}
	if err := p.Check(t.Context(), batch()); !errors.Is(err, ErrPaced) {
		t.Fatal(err)
	}
	if ask(book, "second").State != question.Held || *sent != 0 || g.Reserve(false) {
		t.Fatal("reopen reset question/digest allowance")
	}
	clock = clock.Add(time.Hour)
	_, p, book, sent = open()
	if ask(book, "next-hour").State != question.Waiting || *sent != 1 {
		t.Fatal("new hour did not release question")
	}
	b := batch()
	b.Created = clock.Add(-time.Minute)
	b.Expires = clock.Add(time.Hour)
	if err := p.Check(t.Context(), b); err != nil {
		t.Fatal(err)
	}
}

// REQ: CH-15
func TestPolicySeparatesRecoveryFromOrdinaryPacing(t *testing.T) {
	s := &ledgerCut{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "budget")}}
	g := grants.New(grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 1, PacingStore: s})
	p, err := New(config(g))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Check(t.Context(), batch()); err != nil {
		t.Fatal(err)
	}
	if err = p.Check(t.Context(), batch()); !errors.Is(err, ErrPaced) || p.Health() != nil {
		t.Fatal("exhaustion reported as recovery", err)
	}
	// Recovery can arise from a different user of the same real budget.
	// An unpaced request would also quarantine, but Reserve needs an available
	// slot here. Use a fresh two-slot fixture for the failed shared reservation.
	cfg := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 2, PacingStore: &ledgerCut{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "other")}}}
	g = grants.New(cfg)
	p, _ = New(config(g))
	cfg.PacingStore.(*ledgerCut).fail = true
	if err = p.Check(t.Context(), batch()); !errors.Is(err, ErrRecovery) || errors.Is(err, ErrPaced) || strings.Contains(err.Error(), "canary") {
		t.Fatal("recovery masked or disclosed", err)
	}
	if err = p.Health(); err != ErrRecovery {
		t.Fatal(err)
	}
	if err = p.Recheck(t.Context(), batch()); !errors.Is(err, ErrRecovery) {
		t.Fatal("read-only phase ignored ledger recovery", err)
	}
}

// REQ: CH-15, OP-1, OP-2
func TestLedgerFailureDuringActualBeginPreventsOwnerHandoff(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			dir := t.TempDir()
			ledgerPath := filepath.Join(dir, "budget")
			queuePath := filepath.Join(dir, "queue")
			ls := &ledgerCut{file: &change.FileStore{Path: ledgerPath}, after: after}
			gc := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingStore: ls}
			g := grants.New(gc)
			p, err := New(config(g))
			if err != nil {
				t.Fatal(err)
			}
			sent := 0
			book, err := question.New(question.Config{Send: func(string) error { sent++; return nil }, Now: func(context.Context) (time.Time, error) { return now, nil }, Reserve: g.Reserve})
			if err != nil {
				t.Fatal(err)
			}
			st := &beginStore{Store: &change.FileStore{Path: queuePath}}
			limits := dq.Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536}
			q, err := dq.New(st, limits)
			if err != nil {
				t.Fatal(err)
			}
			snap, _ := dq.NewSnapshot("fixed", 1, []string{"Fixed notice."}, nil)
			b, err := q.Enqueue([]dq.Snapshot{snap}, now, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err = q.Acknowledge(b.ID, snap.Source, snap.Generation, snap.Hash); err != nil {
				t.Fatal(err)
			}
			st.hook = func() {
				ls.fail = true
				r, err := book.Ask(t.Context(), "synthetic-agent", "during-begin", question.Spec{Text: "Which tray?", Default: "left", Wait: 10 * time.Minute})
				if err != nil || r.State != question.Held || sent != 0 {
					t.Fatal(r, err, sent)
				}
			}
			o := &ownerRecipient{}
			a, err := bridgeattempt.New(bridgeattempt.Config{Queue: q, Owner: o, Now: func() time.Time { return now }, Gate: p.Check, Recheck: p.Recheck, Sources: map[string]bridgeattempt.Validator{"fixed": func(context.Context, dq.Snapshot) error { return nil }}})
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Send(t.Context(), b.ID); !errors.Is(err, ErrRecovery) || o.calls != 0 || sent != 0 {
				t.Fatal("handoff escaped shared recovery", err, o.calls, sent)
			}
			fresh, err := dq.New(&change.FileStore{Path: queuePath}, limits)
			if err != nil {
				t.Fatal(err)
			}
			saved, err := fresh.Get(b.ID)
			if err != nil || saved.State != dq.Ready || saved.Attempts != 1 {
				t.Fatal(saved, err)
			}
			gc.PacingStore = &change.FileStore{Path: ledgerPath}
			freshGate := grants.New(gc)
			if err = freshGate.PacingHealth(); err != nil {
				t.Fatal(err)
			}
			available := 0
			for freshGate.Reserve(false) {
				available++
			}
			expected := 2
			if after {
				expected = 1
			}
			if available != expected {
				t.Fatalf("non-send refund or lost question reservation: %d want %d", available, expected)
			}
		})
	}
}
