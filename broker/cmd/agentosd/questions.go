package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/guesterr"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/question"
	"github.com/ghbmrk/agentos/broker/vm"
)

// questions is the owner-question book (P3-8) live (W9). The daemon's
// handlers take it before it opens, since the book texts through the
// owner channel the daemon makes; until it opens, and for good when there
// is no owner channel, nothing is answered and no tool is offered. The box
// clock guard is its own dependency (CLOCK-guard-own, #1246): it opens
// before the book and stays open when the book cannot, since STATUS
// reads it too.
type questions struct {
	b atomic.Pointer[question.Book]
	g atomic.Pointer[clock.Guard]
	// run is the guard's and the book's loops, which write state files
	// until ctx is done; wait waits for them.
	run sync.WaitGroup
}

// wait returns once the loops open started have stopped (cancel their
// ctx first) and the guard's queued notices are delivered. Flushing only
// after the loops stop keeps Flush from racing the guard's own checks.
func (q *questions) wait() {
	q.run.Wait()
	if g := q.g.Load(); g != nil {
		g.Flush()
	}
}

// Answer is the owner channel's answer hook (control.Handler.Answer).
func (q *questions) Answer(ctx context.Context, msg string) (string, bool) {
	b := q.b.Load()
	if b == nil {
		return "", false
	}
	return b.Answer(ctx, msg)
}

// Clock is STATUS's time check line (a control.Handler note): the guard's
// last check in the box's zone, so a restriction is visible while the
// guard texts nothing (UX R3, L3 S1 on #95). With no guard open the
// line says so: time-sensitive checks are then restricted (#1246).
func (q *questions) Clock() string {
	g := q.g.Load()
	if g == nil {
		return "Time check: not running (time-sensitive checks restricted)."
	}
	return clockLine(g.Status(), time.Local)
}

// clockLine is the line for s, or "" when the sources agree: STATUS shows
// only exceptions, degraded checks included (UX-98-1).
func clockLine(s clock.Status, loc *time.Location) string {
	if s.State == clock.Agreed {
		return ""
	}
	return s.Line(loc)
}

// List and Call serve the question tools on each guest socket.
func (q *questions) List() []map[string]any { return question.Tools }

func (q *questions) Call(ctx context.Context, machine, lineage, name string, args json.RawMessage) (string, bool, error) {
	b := q.b.Load()
	if b == nil {
		if name == question.ToolAsk || name == question.ToolStatus {
			return "", true, guesterr.New("the broker cannot text the owner now")
		}
		return "", false, nil
	}
	return question.GuestTools{Book: b}.Call(ctx, machine, lineage, name, args)
}

// questionConfig is where the book and the box clock keep their state.
type questionConfig struct {
	Path, ClockPath string
}

// open starts the box clock (P2-9), then the question book on the owner
// channel. The guard opens first and alone, so a missing owner channel or
// a book that fails to load leaves it running (#1246). Deadlines run on the guard's time and hold while it is
// restricted (TIM-1). Reveal raises the reading machine to private before it
// sees the owner's words (REV-5). Questions and approval requests share
// the gate's CH-15 budget, approval requests first (question Q3): the
// gate reserves each question's text under its own lock.
func (q *questions) open(ctx context.Context, d *daemon.Daemon, pre *preempter, cfg questionConfig) error {
	guard, err := q.openClock(ctx, cfg)
	if err != nil {
		return err
	}
	ch := d.Owner()
	if ch == nil {
		return errors.New("no owner channel")
	}
	b, err := question.New(question.Config{
		// Never held: a question's wait starts at its text, so the book
		// paces it itself (#1563), up to the owner's TEXTS an hour (#2363).
		// Its deadline makes it approval class (D-129, #2250): while
		// approval is urgent it ignores quiet hours and the shared
		// reservation, not the book's limit; under URGENT APPROVAL OFF it
		// keeps quiet hours and reserves the CH-15 budget before sending.
		// In an open task chat it is conversation, not counted (CH-15).
		Send:       questionSend(ch.NotifyNow),
		Converse:   questionSend(ch.Converse),
		PerHour:    ch.TextsPerHour,
		Chat:       questionChatting(ch),
		Now:        guard.Now,
		Quiet:      questionQuiet(ch),
		QuietHours: questionQuietHours(ch),
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
		Reserve:       questionReserve(ch, d.Gate().Reserve),
		Logf:          log.Printf,
	})
	if err != nil {
		return err
	}
	q.b.Store(b)
	q.run.Add(1)
	go func() { defer q.run.Done(); b.Run(ctx, 30*time.Second) }()
	return nil
}

// openClock opens the box clock guard and starts its loop. It needs no
// owner channel: no Notify yet, since the guard's texts tell the owner
// that pre-allowances, request expiry and updates are playing safe, and
// those move onto the guard only with the rest of P2-9's carry-forward
// (clock K7). Questions keep going out through a restriction, their waits
// on the monotonic clock (question Q15).
func (q *questions) openClock(ctx context.Context, cfg questionConfig) (*clock.Guard, error) {
	guard, err := clock.New(clock.Config{
		Sync:      clock.Sync,
		RTC:       clock.RTC, // learns the hardware clock's offset (HW-8, agentos-clock-boot)
		HostID:    clock.HostID,
		StatePath: cfg.ClockPath,
		Logf:      log.Printf,
	})
	if err != nil {
		return nil, err
	}
	q.g.Store(guard)
	q.run.Add(1)
	go func() { defer q.run.Done(); guard.Run(ctx) }()
	return guard, nil
}

// quietSource is the owner channel's view of quiet hours.
type quietSource interface {
	Urgent(owner.Class) bool
	Quiet(time.Time) bool
	QuietHours() bool
}

// questionQuiet holds a question in the owner's quiet hours under URGENT
// APPROVAL OFF: a question carries a deadline, so it is approval class,
// urgent by default (QH-5, D-129, #2250).
func questionQuiet(ch quietSource) func(time.Time) bool {
	return func(t time.Time) bool {
		return !ch.Urgent(owner.ClassApproval) && ch.Quiet(t)
	}
}

// questionQuietHours is questionQuiet for a caller that cannot read the
// time: whether any quiet hours could hold a question.
func questionQuietHours(ch quietSource) func() bool {
	return func() bool {
		return !ch.Urgent(owner.ClassApproval) && ch.QuietHours()
	}
}

// questionChatting opens the chat only on task chat the agent got, never
// on a control word, setting or answer, which a spoofed owner number can
// send (security B1 on #2372), and keeps it open for the owner's CHAT
// window, 30 minutes unless set (CH-15).
func questionChatting(ch interface{ ChatOpen() bool }) func() bool {
	return func() bool { return ch.ChatOpen() }
}

// questionSend marks the owner channel's refusals, which provably sent
// nothing, as question.ErrNotSent, so the book keeps those questions
// held under the same IDs; any other error may have reached the owner
// and is booked as sent (#2363, D-116).
func questionSend(send func(string) error) func(string) error {
	return func(text string) error {
		err := send(text)
		for _, not := range []error{modem.ErrNotSent, owner.ErrPaced, owner.ErrAgentReaction, owner.ErrNoModem} {
			if errors.Is(err, not) {
				return fmt.Errorf("%w: %w", question.ErrNotSent, err)
			}
		}
		return err
	}
}

// questionReserve skips the CH-15 reservation while approval is urgent,
// as an urgent approval request skips the hourly limit; NotifyNow still
// counts the text on the owner's hour, which is the gate's allowance.
// Under URGENT APPROVAL OFF the gate decides (D-129, #2250).
func questionReserve(ch quietSource, reserve func(aged bool) bool) func(aged bool) bool {
	return func(aged bool) bool {
		return ch.Urgent(owner.ClassApproval) || reserve(aged)
	}
}

// start is open, logging a failure and recording it for STATUS (OP-9
// C9): the owner channel failing to take questions must not take the box
// down; the tools are then not offered and replies are task chat.
func (q *questions) start(ctx context.Context, d *daemon.Daemon, pre *preempter, cfg questionConfig, caps *capState) {
	if err := q.open(ctx, d, pre, cfg); err != nil {
		log.Printf("owner questions disabled: %v", err)
		caps.questionsOff.Store(true)
	}
}

// wire gives the daemon the answer hook and the STATUS clock line; call
// it before daemon.Run.
func (q *questions) wire(cfg *daemon.Config) {
	cfg.Answer = q.Answer
	cfg.Notes = append(cfg.Notes, q.Clock)
}

// tools is what the guest plane serves beside the effect tools: the
// question tools once the book is open, else none.
func (q *questions) tools() guest.Tools {
	if q.b.Load() == nil {
		return nil
	}
	return q
}

func defaultQuestionConfig(dir string) questionConfig {
	return questionConfig{Path: filepath.Join(dir, "questions.json"), ClockPath: filepath.Join(dir, "clock.json")}
}
