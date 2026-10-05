package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/question"
	"github.com/ghbmrk/agentos/broker/vm"
)

// questions is the owner-question book (P3-8) live (W9). The daemon's
// handlers and the grants gate take it before it opens, since the book
// texts through the owner channel the daemon makes; until it opens, and
// for good when there is no owner channel, nothing is answered and no
// question text counts.
type questions struct{ b atomic.Pointer[question.Book] }

// Answer is the owner channel's answer hook (control.Handler.Answer).
func (q *questions) Answer(ctx context.Context, msg string) (string, bool) {
	b := q.b.Load()
	if b == nil {
		return "", false
	}
	return b.Answer(ctx, msg)
}

// Texts is the gate's count of question texts on the shared CH-15 budget.
func (q *questions) Texts(now time.Time) int {
	b := q.b.Load()
	if b == nil {
		return 0
	}
	return b.Texts(now)
}

// List and Call serve the question tools on each guest socket.
func (q *questions) List() []map[string]any { return question.Tools }

func (q *questions) Call(ctx context.Context, machine, lineage, name string, args json.RawMessage) (string, bool, error) {
	b := q.b.Load()
	if b == nil {
		if name == question.ToolAsk || name == question.ToolStatus {
			return "", true, errors.New("the broker cannot text the owner now")
		}
		return "", false, nil
	}
	return question.GuestTools{Book: b}.Call(ctx, machine, lineage, name, args)
}

// questionConfig is where the book and the box clock keep their state.
type questionConfig struct {
	Path, ClockPath string
}

// open starts the box clock (P2-9) and the question book on the owner
// channel. Deadlines run on the guard's time and hold while it is
// restricted (TIM-1). Reveal raises the reading machine to private before it
// sees the owner's words (REV-5). Questions and approval requests share
// the gate's CH-15 budget, approval requests first (question Q3).
func (q *questions) open(ctx context.Context, d *daemon.Daemon, pre *preempter, cfg questionConfig) (*clock.Guard, error) {
	ch := d.Owner()
	if ch == nil {
		return nil, errors.New("no owner channel")
	}
	// No Notify yet: the guard's texts tell the owner that pre-allowances,
	// request expiry and updates are playing safe, and those move onto the
	// guard only with the rest of P2-9's carry-forward (clock K7). Until
	// then a restriction holds questions without a text.
	guard, err := clock.New(clock.Config{
		Synced:    clock.Synced,
		StatePath: cfg.ClockPath,
		Logf:      log.Printf,
	})
	if err != nil {
		return nil, err
	}
	b, err := question.New(question.Config{
		Send: ch.Notify,
		Now:  guard.Now,
		Reveal: func(machine string) error {
			m := pre.m.Load()
			if m == nil {
				return errors.New("machine manager not open")
			}
			return m.RaiseLabel(machine, vm.Private)
		},
		Path:          cfg.Path,
		Hidden:        owner.SecretShaped,
		ApprovalsOpen: ch.ApprovalsOpen,
		Shared:        d.Gate().Pacing,
		Logf:          log.Printf,
	})
	if err != nil {
		return nil, err
	}
	q.b.Store(b)
	go guard.Run(ctx)
	go b.Run(ctx, 30*time.Second)
	return guard, nil
}

func defaultQuestionConfig(dir string) questionConfig {
	return questionConfig{Path: filepath.Join(dir, "questions.json"), ClockPath: filepath.Join(dir, "clock.json")}
}
