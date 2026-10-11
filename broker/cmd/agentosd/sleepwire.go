package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/workers"
)

// sleepSource runs a loop's evaluating work with the agent asleep, on a
// box where the agent and a replay machine do not fit together (PE7).
// The unit puts the agent to sleep first, or does not run (it is offered
// again later), and wakes it when it ends. Without a sleeper the source is
// unchanged.
type sleepSource struct {
	loops.Source
	sleep *atomic.Pointer[sleeper]
}

// Digest keeps the wrapped source's digest lines.
func (s sleepSource) Digest() []string {
	if d, ok := s.Source.(loops.Digester); ok {
		return d.Digest()
	}
	return nil
}

func (s sleepSource) Next(ctx context.Context, modelOK bool) (loops.Job, bool) {
	job, ok := s.Source.Next(ctx, modelOK)
	sl := s.sleep.Load()
	if !ok || !job.Evaluates || sl == nil {
		return job, ok
	}
	run := job.Run
	job.Run = func(ctx context.Context) loops.Result {
		if err := sl.Sleep(ctx); err != nil {
			// Not run: the scheduler offers it again later (PE3).
			return loops.Result{Err: fmt.Errorf("agent did not sleep: %w", change.ErrInterrupted)}
		}
		defer sl.Wake(wakeUnit)
		return run(ctx)
	}
	return job, ok
}

// sleepGuard runs one evaluator call under the sleeper's guard: a wake
// cuts it at once, and the cut is returned as the owner's interruption
// (change.ErrOwnerWork or ErrOwnerStop wrapping change.ErrInterrupted),
// so PE5 does not count it (UX P2-b on #147).
func sleepGuard(ctx context.Context, sl *sleeper, run func(context.Context) ([]byte, error)) ([]byte, error) {
	if sl == nil {
		return run(ctx)
	}
	gctx, done := sl.guard(ctx)
	defer done()
	out, err := run(gctx)
	if ctx.Err() == nil && gctx.Err() != nil {
		if cause := context.Cause(gctx); errors.Is(cause, change.ErrOwnerPreempt) {
			return nil, fmt.Errorf("agent woke: %w: %w", cause, change.ErrInterrupted)
		}
	}
	return out, err
}

// keepsAwake reports that the sleeper wants the box for the agent: on a
// sleep-mode box, while the agent is awake and may not sleep now, loop
// work waits (PE7 condition 1). A wake mid-unit is the owner's (condition
// 7), so it is reported as the owner's work.
func (s *sleeper) keepsAwake() bool {
	return !s.Asleep() && s.why(s.cfg.Now()) != ""
}

// sleepDigest is the one-time digest line on a sleep-mode box (PE7
// condition 16).
const sleepDigest = "My memory is too small to run your agent and test changes together, so I test them at night while your agent sleeps. Any task message wakes it."

// sleepModeNote is STATUS's learning line on a sleep-mode box, in place of
// noRoomNote.
const sleepModeNote = "Learning: at night only, while your agent sleeps (my memory is too small to run both)."

// sleepDeps are the daemon parts the sleeper reads.
type sleepDeps struct {
	d     *daemon.Daemon
	m     *vm.Manager
	plane *guest.Plane
	qs    *questions
	agent *lateAgent
	id    string
	hours func(time.Time) bool
	// workers, if set, serves the guest's worker tools (CAP-8).
	workers *workers.Tools
}

// sleepWork is where the agent's work in hand is read (condition 2). Any
// check that holds keeps the agent awake; clock does too, since the
// sleeper's hours read the box clock (TIM-1, security R1 on #149).
type sleepWork struct {
	intent, undo, gate, handed func() bool
	// worker, if set, reports a worker tool call in flight (L3 on #149).
	worker func() bool
	qs     *questions
}

func (w sleepWork) checks() map[string]func() bool {
	m := map[string]func() bool{
		"intent": w.intent, "undo": w.undo, "gate": w.gate, "handed": w.handed,
		"question": w.qs.pending, "clock": w.qs.restricted,
	}
	if w.worker != nil {
		m["worker"] = w.worker
	}
	return m
}

// openSleeper makes the agent sleeper for a box where the agent and a
// replay machine do not fit together (PE7), wakes an agent a restart left
// asleep (security R1 on #147), and starts its watch. Call it before the
// keeper starts.
func openSleeper(ctx context.Context, deps sleepDeps) *sleeper {
	d := deps.d
	s := newSleeper(sleepConfig{
		Machines: deps.m,
		ID:       deps.id,
		Hours:    deps.hours,
		LastOwner: func() time.Time {
			t := deps.agent.lastDelivered()
			if ch := d.Owner(); ch != nil && ch.LastActive().After(t) {
				t = ch.LastActive()
			}
			return t
		},
		Pending: sleepWork{
			intent: d.Engine().GuestActive,
			undo: func() bool {
				ch := d.Owner()
				return ch != nil && ch.UndoOpen()
			},
			gate:   d.Gate().Holding,
			handed: func() bool { return deps.plane.OwnerPending(deps.id) },
			worker: workerBusy(deps.workers, deps.id),
			qs:     deps.qs,
		}.checks(),
		Stopped: d.Engine().Stopped,
		Journal: d.Engine().RecordSleep,
		Hold: func() {
			if ch := d.Owner(); ch != nil {
				if err := ch.Inform(holdLine); err != nil {
					log.Printf("agent machine %s: holding line not sent: %v", deps.id, err)
				}
			}
		},
		Logf: log.Printf,
	})
	s.recover(ctx)
	go s.watch(ctx, 30*time.Second)
	return s
}

// parseSleepHours reads -sleep-hours, "HH:MM-HH:MM" in box time, which may
// run past midnight. Empty is the default, 01:00 to 06:00.
func parseSleepHours(v string) (func(time.Time) bool, error) {
	if v == "" {
		return nil, nil
	}
	from, to, ok := strings.Cut(v, "-")
	if !ok {
		return nil, fmt.Errorf("sleep hours %q: want HH:MM-HH:MM", v)
	}
	minute := func(s string) (int, error) {
		t, err := time.Parse("15:04", s)
		if err != nil {
			return 0, fmt.Errorf("sleep hours %q: %v", v, err)
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	a, err := minute(from)
	if err != nil {
		return nil, err
	}
	b, err := minute(to)
	if err != nil {
		return nil, err
	}
	if a == b {
		return nil, fmt.Errorf("sleep hours %q: empty", v)
	}
	return func(t time.Time) bool {
		m := t.Hour()*60 + t.Minute()
		if a < b {
			return m >= a && m < b
		}
		return m >= a || m < b
	}, nil
}

// whileAwake runs f, the keeper's start, unless the agent is asleep; a
// sleep or wake does not run meanwhile, so the keeper never restarts an
// agent under its checkpoint.
func (s *sleeper) whileAwake(f func() error) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.Asleep() {
		return nil
	}
	return f()
}

// workerBusy reports whether id has a worker tool call in flight; nil
// without worker tools.
func workerBusy(wt *workers.Tools, id string) func() bool {
	if wt == nil {
		return nil
	}
	return func() bool { return wt.Busy(id) }
}

// agentKeeper is the keeper of the agent machine id. With no sleeper (a
// box whose agent and a replay machine fit together), a sleep checkpoint
// left from when the box did sleep its agent is restored or deleted
// first, so none outlives the mode (security R2 on #149).
func agentKeeper(ctx context.Context, m *vm.Manager, record func(journal.SleepNote) error, id string, spec vm.Spec, sl *sleeper) *keeper {
	if sl == nil {
		newSleeper(sleepConfig{Machines: m, ID: id, Journal: record}).recover(ctx)
	}
	return &keeper{m: m, id: id, spec: spec, every: 30 * time.Second, logf: log.Printf, status: agentWaiting, sleep: sl}
}

// sleepResume is how long a preempted evaluation is kept on a box whose
// agent sleeps for learning: past the next night's window, so work cut
// when one window ends resumes in the next (PE7 condition 17).
const sleepResume = 36 * time.Hour

// sleepMode reports whether the agent sleeps while the box learns: a
// replay machine is configured but does not fit beside the agent (PE7).
// main decides both the sleeper and sleepResumeFor from it, so they never
// disagree (L3 on #153).
func sleepMode(capacityMB, headroomMB, agentMB, replayMB int64) bool {
	return replayMB > 0 && replayFits(capacityMB, headroomMB, agentMB, replayMB) != nil
}

// sleepResumeFor is sleepResume in sleep mode; zero (change.ResumeFor)
// otherwise.
func sleepResumeFor(asleep bool) time.Duration {
	if asleep {
		return sleepResume
	}
	return 0
}
