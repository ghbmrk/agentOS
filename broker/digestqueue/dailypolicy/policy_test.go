package dailypolicy

import (
	"context"
	"errors"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/question"
	"sync"
	"testing"
	"time"
)

type engine struct{ stopped bool }

func (e *engine) Stop(context.Context) (journal.StopReport, error) {
	e.stopped = true
	return journal.StopReport{}, nil
}
func (e *engine) Resume() error          { e.stopped = false; return nil }
func (e *engine) Stopped() bool          { return e.stopped }
func (e *engine) List() []journal.Status { return nil }

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func config(g *grants.Gate) Config {
	return Config{Budget: g, Engine: &engine{}, Clock: func(context.Context) (time.Time, error) { return now, nil }, Quiet: func(time.Time) bool { return false }, Eligible: func(context.Context, dq.Batch) error { return nil }, AgedAfter: 30 * time.Minute}
}
func batch() dq.Batch {
	return dq.Batch{ID: 1, State: dq.Ready, Created: now.Add(-time.Minute), Expires: now.Add(time.Hour)}
}

// REQ: CH-15
func TestRealQuestionBookAndDigestUseTheSameGateBudget(t *testing.T) {
	g := grants.New(grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 2})
	p, err := New(config(g))
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	book, err := question.New(question.Config{Send: func(string) error { sent++; return nil }, Now: func(context.Context) (time.Time, error) { return now, nil }, Reserve: g.Reserve})
	if err != nil {
		t.Fatal(err)
	}
	first, err := book.Ask(t.Context(), "agent", "first", question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
	if err != nil || first.State != question.Waiting || sent != 1 {
		t.Fatal(first, err, sent)
	}
	if err := p.Check(t.Context(), batch()); err != nil {
		t.Fatal(err)
	}
	second, err := book.Ask(t.Context(), "other-agent", "second", question.Spec{Text: "Which tray?", Default: "left", Wait: 10 * time.Minute})
	if err != nil || second.State != question.Held || sent != 1 {
		t.Fatal(second, err, sent)
	}
	if err := p.Check(t.Context(), batch()); !errors.Is(err, ErrPaced) {
		t.Fatal(err)
	}
	if g.Reserve(false) {
		t.Fatal("separate digest budget bypassed shared limit")
	}
}

// REQ: CH-2, CH-15, TIM-1
func TestPreReservationRefusalsConsumeNoSharedBudget(t *testing.T) {
	for _, reason := range []string{"stop", "quiet", "clock", "zero", "resource", "cancel-clock", "cancel-quiet", "cancel-resource", "expired"} {
		t.Run(reason, func(t *testing.T) {
			g := grants.New(grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 1})
			cfg := config(g)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			b := batch()
			switch reason {
			case "stop":
				cfg.Engine.(*engine).stopped = true
			case "quiet":
				cfg.Quiet = func(time.Time) bool { return true }
			case "clock":
				cfg.Clock = func(context.Context) (time.Time, error) { return now, errors.New("restricted") }
			case "zero":
				cfg.Clock = func(context.Context) (time.Time, error) { return time.Time{}, nil }
			case "resource":
				cfg.Eligible = func(context.Context, dq.Batch) error { return errors.New("resource unavailable") }
			case "cancel-clock":
				cfg.Clock = func(context.Context) (time.Time, error) { cancel(); return now, nil }
			case "cancel-quiet":
				cfg.Quiet = func(time.Time) bool { cancel(); return false }
			case "cancel-resource":
				cfg.Eligible = func(context.Context, dq.Batch) error { cancel(); return nil }
			case "expired":
				b.Expires = now
			}
			p, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Check(ctx, b); err == nil {
				t.Fatal("policy permitted refused text")
			}
			if !g.Reserve(false) {
				t.Fatal("refusal consumed slot")
			}
		})
	}
}
func TestConcurrentDigestReservationsDoNotExceedSharedBudget(t *testing.T) {
	g := grants.New(grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 3})
	p, err := New(config(g))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- p.Check(t.Context(), batch()) }()
	}
	wg.Wait()
	close(results)
	passed := 0
	for err := range results {
		if err == nil {
			passed++
		} else if !errors.Is(err, ErrPaced) {
			t.Fatal(err)
		}
	}
	if passed != 3 {
		t.Fatal(passed)
	}
}
func TestPolicyRequiresExplicitFullConfiguration(t *testing.T) {
	g := grants.New(grants.Config{})
	for _, field := range []string{"budget", "engine", "clock", "quiet", "eligible", "aging"} {
		cfg := config(g)
		switch field {
		case "budget":
			cfg.Budget = nil
		case "engine":
			cfg.Engine = nil
		case "clock":
			cfg.Clock = nil
		case "quiet":
			cfg.Quiet = nil
		case "eligible":
			cfg.Eligible = nil
		case "aging":
			cfg.AgedAfter = 0
		}
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Fatal(field, err)
		}
	}
}
func TestReadOnlyRecheckDoesNotReserveAndObservesLateQuietHours(t *testing.T) {
	g := grants.New(grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 2})
	quiet := false
	cfg := config(g)
	cfg.Quiet = func(time.Time) bool { return quiet }
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Check(t.Context(), batch()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err = p.Recheck(t.Context(), batch()); err != nil {
			t.Fatal(err)
		}
	}
	quiet = true
	if err = p.Recheck(t.Context(), batch()); !errors.Is(err, ErrQuiet) {
		t.Fatal(err)
	}
	if !g.Reserve(false) {
		t.Fatal("read-only phase reserved another slot")
	}
}
func TestPolicyReobservesQuietAndClockAfterResourceCheck(t *testing.T) {
	for _, kind := range []string{"quiet", "clock", "stop"} {
		t.Run(kind, func(t *testing.T) {
			g := grants.New(grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 1})
			cfg := config(g)
			late := false
			cfg.Eligible = func(context.Context, dq.Batch) error { late = true; return nil }
			switch kind {
			case "quiet":
				cfg.Quiet = func(time.Time) bool { return late }
			case "clock":
				cfg.Clock = func(context.Context) (time.Time, error) {
					if late {
						return now, errors.New("became restricted")
					}
					return now, nil
				}
			case "stop":
				cfg.Eligible = func(context.Context, dq.Batch) error { cfg.Engine.(*engine).stopped = true; return nil }
			}
			p, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.Check(t.Context(), batch()); err == nil {
				t.Fatal("late boundary ignored")
			}
			if !g.Reserve(false) {
				t.Fatal("late refusal spent slot")
			}
		})
	}
}
