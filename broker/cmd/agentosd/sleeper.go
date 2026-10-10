package main

import (
	"context"
	"errors"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/vm"
)

// sleepMachines is the vm.Manager part the sleeper uses.
type sleepMachines interface {
	Get(id string) (vm.Machine, error)
	Snapshot(id string) (vm.Snapshot, error)
	CheckpointAndStop(ctx context.Context, id string) (vm.Snapshot, error)
	ResumeFromCheckpoint(ctx context.Context, id, snapID string) (vm.Wake, error)
}

// Why the agent woke: fixed codes for the journal (PE7 condition 12).
const (
	wakeOwner   = "owner_message"
	wakeStop    = "stop"
	wakeWindow  = "window_end"
	wakeMax     = "max_sleep"
	wakeUnit    = "unit_done"
	wakeRestart = "restart"
	wakeWork    = "work_pending"
)

// coldCodes are vm's cold-wake reasons as journal codes (potency R1 on
// #147).
var coldCodes = map[string]string{
	vm.ColdNotSleep: "not_sleep_checkpoint",
	vm.ColdNewer:    "newer_snapshot",
	vm.ColdStarted:  "started_since",
	vm.ColdChanged:  "checkpoint_changed",
	vm.ColdFailed:   "restore_failed",
}

// The owner's lines (PE7 conditions 14, 15). Neither says whether a wake
// kept the agent's memory (UX P2-c).
const (
	sleepStatus = "Your agent is asleep while I learn. Any task message wakes it."
	holdLine    = "One moment, your agent is waking up."
)

const (
	defaultIdleAfter = 30 * time.Minute
	defaultPreWake   = 10 * time.Minute
	defaultMaxSleep  = 5 * time.Hour
	defaultHoldAfter = 15 * time.Second
	// defaultRestoreFor bounds one wake's restore, so a hung restore
	// cannot hold the keeper and every later wake (L3 on #149).
	defaultRestoreFor = 2 * time.Minute
)

// errNoSleep: the agent may not sleep now.
var errNoSleep = errors.New("agent may not sleep now")

type sleepConfig struct {
	Machines sleepMachines
	ID       string // the agent machine
	Now      func() time.Time
	// Hours reports the owner's quiet hours, the only time the agent may
	// sleep (condition 1). Nil: 01:00 to 06:00 box time.
	Hours func(time.Time) bool
	// IdleAfter is how long the owner must have been quiet; PreWake how
	// long before the hours end the agent wakes (condition 3); MaxSleep
	// the longest sleep, read on the monotonic clock (condition 6);
	// HoldAfter how long a wake for an owner message runs before the
	// holding line (condition 14).
	IdleAfter, PreWake, MaxSleep, HoldAfter time.Duration
	// RestoreFor bounds one wake's restore (defaultRestoreFor). After a
	// wake at MaxSleep the agent stays awake for IdleAfter before it may
	// sleep again (condition 6, L3 on #149).
	RestoreFor time.Duration
	// LastOwner is when the owner last sent the agent a message.
	LastOwner func() time.Time
	// Pending names the checks for work in hand (condition 2): any true
	// keeps the agent awake.
	Pending map[string]func() bool
	Stopped func() bool
	// Journal records each sleep and wake (condition 12); Hold sends the
	// holding line.
	Journal func(journal.SleepNote) error
	Hold    func()
	Logf    func(format string, args ...any)
	// AfterFunc runs f once d has passed on the clock Now reads, and
	// returns what stops it. Nil is time.AfterFunc; tests drive the
	// holding line on their own clock.
	AfterFunc func(d time.Duration, f func()) (stop func() bool)
}

// sleeper stops the agent machine with its memory saved while the box
// evaluates a change, on a box where the agent and a replay machine do
// not fit together (PE7), and wakes it again. Being asleep is held in
// memory only, so a broker restart always wakes the agent (recover).
type sleeper struct {
	cfg sleepConfig

	// op orders a sleep's checkpoint and a wake's restore.
	op sync.Mutex

	mu     sync.Mutex
	asleep bool
	snap   string
	since  time.Time
	rested time.Time // no sleep before this, after a wake at MaxSleep
	// hold is this sleep's holding-line timer, armed by the first owner
	// message; held is set once the line went (one per sleep).
	hold   func() bool // stops the timer
	held   bool
	cuts   map[int]context.CancelCauseFunc
	nextID int
}

func newSleeper(cfg sleepConfig) *sleeper {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Hours == nil {
		cfg.Hours = defaultSleepHours
	}
	if cfg.IdleAfter <= 0 {
		cfg.IdleAfter = defaultIdleAfter
	}
	if cfg.PreWake <= 0 {
		cfg.PreWake = defaultPreWake
	}
	if cfg.MaxSleep <= 0 {
		cfg.MaxSleep = defaultMaxSleep
	}
	if cfg.HoldAfter <= 0 {
		cfg.HoldAfter = defaultHoldAfter
	}
	if cfg.RestoreFor <= 0 {
		cfg.RestoreFor = defaultRestoreFor
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.AfterFunc == nil {
		cfg.AfterFunc = func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }
	}
	return &sleeper{cfg: cfg, cuts: map[int]context.CancelCauseFunc{}}
}

// defaultSleepHours is 01:00 to 06:00 box time.
func defaultSleepHours(t time.Time) bool { h := t.Hour(); return h >= 1 && h < 6 }

// inHours reports whether t and t+PreWake are both inside the hours.
func (s *sleeper) inHours(t time.Time) bool {
	return s.cfg.Hours(t) && s.cfg.Hours(t.Add(s.cfg.PreWake))
}

// why names what keeps the agent awake now, or "" if it may sleep.
func (s *sleeper) why(now time.Time) string {
	switch {
	case !s.inHours(now):
		return "outside its hours"
	case now.Before(s.rested):
		return "just woke from its longest sleep"
	case s.cfg.LastOwner != nil && now.Sub(s.cfg.LastOwner()) < s.cfg.IdleAfter:
		return "owner recent"
	}
	return s.pending()
}

// Asleep reports whether the agent is asleep or going to sleep; the keeper
// does not restart it then.
func (s *sleeper) Asleep() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asleep
}

// Status is STATUS's agent line while asleep, empty otherwise.
func (s *sleeper) Status() string {
	if s.Asleep() {
		return sleepStatus
	}
	return ""
}

// Sleep stops the agent with its memory saved, if it may sleep now; it
// returns errNoSleep if not. Only the scheduler's evaluation job calls it,
// never a candidate (condition 6).
func (s *sleeper) Sleep(ctx context.Context) error {
	s.op.Lock()
	defer s.op.Unlock()
	now := s.cfg.Now()
	s.mu.Lock()
	if s.asleep {
		s.mu.Unlock()
		return nil
	}
	if s.why(now) != "" {
		s.mu.Unlock()
		return errNoSleep
	}
	// Marked first, so the keeper does not restart the agent under the
	// checkpoint.
	s.asleep, s.since = true, now
	s.hold, s.held = nil, false
	s.mu.Unlock()
	snap, err := s.cfg.Machines.CheckpointAndStop(ctx, s.cfg.ID)
	if err != nil {
		s.mu.Lock()
		s.asleep = false
		s.mu.Unlock()
		s.journal(journal.SleepNote{Event: journal.SleepFailed})
		return err
	}
	s.mu.Lock()
	s.snap = snap.ID
	s.mu.Unlock()
	s.journal(journal.SleepNote{Event: journal.SleepAsleep})
	// Work that arrived while the checkpoint was taken wakes the agent
	// again at once (condition 2, L3 on #149).
	if s.pending() != "" {
		s.wakeLocked(wakeWork)
		return errNoSleep
	}
	return nil
}

// pending names the work in hand or STOP, or "".
func (s *sleeper) pending() string {
	if s.cfg.Stopped != nil && s.cfg.Stopped() {
		return "STOP"
	}
	names := make([]string, 0, len(s.cfg.Pending))
	for n := range s.cfg.Pending {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if s.cfg.Pending[n]() {
			return n
		}
	}
	return ""
}

// guard returns ctx for one evaluator run while the agent sleeps: a wake
// cancels it at once with the owner's cause (conditions 6, 7; UX P2-b).
// done releases it.
func (s *sleeper) guard(ctx context.Context) (context.Context, func()) {
	gctx, cancel := context.WithCancelCause(ctx)
	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.cuts[id] = cancel
	s.mu.Unlock()
	return gctx, func() {
		s.mu.Lock()
		delete(s.cuts, id)
		s.mu.Unlock()
		cancel(nil)
	}
}

// Wake restores the agent, if asleep, for cause (a wake code). Any
// evaluation running is cut first, as the owner's: STOP's cut is
// change.ErrOwnerStop, any other change.ErrOwnerWork, so neither counts
// against the candidate (PE5).
func (s *sleeper) Wake(cause string) {
	s.cut(cause)
	s.op.Lock()
	defer s.op.Unlock()
	s.wakeLocked(cause)
}

// OwnerMessage wakes the agent for an owner message delivered to its
// inbox at at. If the agent is asleep or going to sleep and is still not
// awake HoldAfter after at, the holding line goes out once (condition
// 14): the clock runs from the delivery, not from when the wake gets its
// turn behind a checkpoint in progress (L3 on #149).
func (s *sleeper) OwnerMessage(at time.Time) {
	s.mu.Lock()
	if !s.asleep {
		s.mu.Unlock()
		return
	}
	// One timer per sleep, from the first message: later messages during
	// the same wake send no second line (L3 MUST-A on #149).
	if s.cfg.Hold != nil && s.hold == nil && !s.held {
		s.hold = s.cfg.AfterFunc(s.cfg.HoldAfter-s.cfg.Now().Sub(at), s.holdLine)
	}
	s.mu.Unlock()
	s.cut(wakeOwner)
	s.op.Lock()
	defer s.op.Unlock()
	s.wakeLocked(wakeOwner)
}

// holdLine sends the holding line if the agent is still asleep and the
// line has not gone this sleep.
func (s *sleeper) holdLine() {
	s.mu.Lock()
	if !s.asleep || s.held {
		s.mu.Unlock()
		return
	}
	s.held = true
	s.mu.Unlock()
	s.cfg.Hold()
}

// cut ends every guarded evaluation with the owner's cause for a wake.
func (s *sleeper) cut(cause string) {
	c := change.ErrOwnerWork
	if cause == wakeStop {
		c = change.ErrOwnerStop
	}
	s.mu.Lock()
	for _, f := range s.cuts {
		f(c)
	}
	s.mu.Unlock()
}

// wakeLocked restores the agent with s.op held, and stops the holding
// line's timer as it marks the agent awake. The agent is marked awake even
// if the restore and its cold fallback both fail, so the keeper starts it
// again.
func (s *sleeper) wakeLocked(cause string) {
	s.mu.Lock()
	if !s.asleep {
		s.mu.Unlock()
		return
	}
	snap := s.snap
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RestoreFor)
	w, err := s.cfg.Machines.ResumeFromCheckpoint(ctx, s.cfg.ID, snap)
	cancel()
	if err != nil {
		// The cold resume failed too: the keeper retries it.
		s.cfg.Logf("agent machine %s: waking: %v", s.cfg.ID, err)
		w = vm.Wake{Cold: vm.ColdFailed}
	}
	s.mu.Lock()
	s.asleep, s.snap = false, ""
	if s.hold != nil {
		s.hold()
		s.hold = nil
	}
	if cause == wakeMax {
		s.rested = s.cfg.Now().Add(s.cfg.IdleAfter)
	}
	s.mu.Unlock()
	s.journal(journal.SleepNote{Event: journal.SleepAwake, Cause: cause, Cold: coldCode(w)})
}

func coldCode(w vm.Wake) string {
	if w.Restored {
		return ""
	}
	if c, ok := coldCodes[w.Cold]; ok {
		return c
	}
	return "unknown"
}

// check wakes the agent when STOP is in force, its hours are about to
// end, or it has slept MaxSleep (conditions 3, 6).
func (s *sleeper) check() {
	s.mu.Lock()
	asleep, since := s.asleep, s.since
	s.mu.Unlock()
	if !asleep {
		return
	}
	now := s.cfg.Now()
	switch {
	case s.cfg.Stopped != nil && s.cfg.Stopped():
		s.Wake(wakeStop)
	case !s.inHours(now):
		s.Wake(wakeWindow)
	case now.Sub(since) >= s.cfg.MaxSleep:
		s.Wake(wakeMax)
	}
}

// watch runs check every every until ctx ends.
func (s *sleeper) watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.check()
		}
	}
}

// recover wakes an agent a broker restart left asleep: stopped, with a
// sleep checkpoint as its newest snapshot. The checkpoint is restored,
// or deleted if it cannot be (security R1 on #147). Call it before the
// keeper starts.
func (s *sleeper) recover(ctx context.Context) {
	mc, err := s.cfg.Machines.Get(s.cfg.ID)
	if err != nil || mc.State == vm.Running || mc.Last == "" {
		return
	}
	snap, err := s.cfg.Machines.Snapshot(mc.Last)
	if err != nil || !snap.Sleep || snap.Machine != s.cfg.ID {
		return
	}
	w, err := s.cfg.Machines.ResumeFromCheckpoint(ctx, s.cfg.ID, snap.ID)
	if err != nil {
		s.cfg.Logf("agent machine %s: waking after a restart: %v", s.cfg.ID, err)
	}
	s.journal(journal.SleepNote{Event: journal.SleepAwake, Cause: wakeRestart, Cold: coldCode(w)})
}

func (s *sleeper) journal(n journal.SleepNote) {
	if s.cfg.Journal == nil {
		return
	}
	n.Machine = s.cfg.ID
	if err := s.cfg.Journal(n); err != nil {
		s.cfg.Logf("agent machine %s: journaling %s: %v", s.cfg.ID, n.Event, err)
	}
}
