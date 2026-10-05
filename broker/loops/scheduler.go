package loops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Job is one unit of loop work.
type Job struct {
	// Name is a fixed word for logs ("recheck", "routing", "candidate").
	Name string
	// UsesModel marks work that makes model calls. It is not offered while
	// the spare budget has no room.
	UsesModel bool
	// Evaluates marks work that runs replay evaluations; while it runs,
	// the spare meter keeps evaluation's reserved share (EvalShare).
	Evaluates bool
	// Run does the work. It must return soon after ctx is cancelled (the
	// scheduler's Preempt), and a source whose job was cancelled offers
	// that work again later.
	Run func(ctx context.Context) Result
}

// Result is a job's measured value: held-out gain, a reverted regression,
// a security finding, a qualified update (LOOP-3). The scheduler measures
// the cost itself.
type Result struct {
	Value float64
	Err   error
}

// Source supplies one loop's work.
type Source interface {
	Loop() Loop
	// Next returns the next unit of worthwhile work, or false when there
	// is none. With modelOK false, only work that makes no model calls
	// may be returned.
	Next(ctx context.Context, modelOK bool) (Job, bool)
}

// Digester is a source with lines for the owner's digest.
type Digester interface {
	Digest() []string
}

// Journal is the part of the intent engine (or the policy gate in front of
// it) the scheduler uses for its settings intents.
type Journal = change.Journal

// Config configures New.
type Config struct {
	Store change.Store
	// Spare is the spare budget meter (LOOP-2): a meter of its own, never
	// the guests', through which every loop model call goes (replay,
	// clean room, Loop 1's builder). Its overall cap is set from the
	// owner's setting; Loop code has no other handle on it.
	Spare   *meter.Meter
	Sources []Source
	// Journal is where settings intents go; set it with Attach when the
	// engine is built after the scheduler.
	Journal Journal
	// Busy reports that foreground or accepted work needs the box (RES-1,
	// from admission). No loop work starts while it is true. Nil: never.
	Busy func() bool
	// Stopped reports that STOP is in force; loops pause with everything
	// else. Nil: never.
	Stopped func() bool
	// Sharing applies STOP SHARING / START SHARING (the change pipeline's
	// SetSharing).
	Sharing func(ctx context.Context, on bool) error
	// YieldTarget is the frozen preemption target (RES-1, LOOP-1): how
	// long Preempt waits for running work to return. Default 2 s.
	YieldTarget time.Duration
	// Poll is how often Busy and Stopped are read while work runs; work
	// is preempted as soon as either is true, even if nothing called
	// Preempt. Default 250 ms.
	Poll time.Duration
	// Retry is how soon to look again when the box is busy or stopped.
	// Default 1 minute.
	Retry time.Duration
	// Idle is how long to sleep when no loop has worthwhile work, unless
	// Wake comes first. Default 1 hour.
	Idle time.Duration
	// DryRuns is how many runs in a row without value park a loop; a
	// parked loop is offered work again after DryRecheck (default 3 and
	// 24 hours).
	DryRuns    int
	DryRecheck time.Duration
	// ComputeTokens prices one second of compute in tokens, so local work
	// counts as cost too. Default 50.
	ComputeTokens float64
	// MinShare is the smallest share a loop with measured value keeps.
	// Default 0.05.
	MinShare float64
	// HalfLife is how fast past spend is forgotten. Default 24 hours.
	HalfLife time.Duration
	Now      func() time.Time
	Logf     func(format string, args ...any)
}

// Scheduler runs loop work in spare capacity. It is the journal executor
// and policy for loop settings (Executor, Check).
type Scheduler struct {
	cfg  Config
	wake chan struct{}

	mu          sync.Mutex
	st          state
	loops       map[Loop]*measure
	cancel      context.CancelFunc
	runningLoop Loop
	done        chan struct{}
	preempted   bool
	evaluating  atomic.Bool
	last        time.Time // when spent was last decayed
}

// measure is a loop's measured return (LOOP-3), kept in memory: after a
// restart every loop starts unmeasured and earns its share again.
type measure struct {
	runs   int
	value  float64 // moving average of value per run
	cost   float64 // moving average of cost per run
	spent  float64 // decayed recent cost
	dry    int
	parked time.Time // offered no work until then
}

const ewma = 0.3

// New loads the settings (every loop on, on first start) and applies the
// spare budget to the spare meter.
func New(cfg Config) (*Scheduler, error) {
	if cfg.Store == nil || cfg.Spare == nil {
		return nil, errors.New("loops: Store and Spare are required")
	}
	if cfg.YieldTarget <= 0 {
		cfg.YieldTarget = 2 * time.Second
	}
	if cfg.Retry <= 0 {
		cfg.Retry = time.Minute
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 250 * time.Millisecond
	}
	if cfg.Idle <= 0 {
		cfg.Idle = time.Hour
	}
	if cfg.DryRuns <= 0 {
		cfg.DryRuns = 3
	}
	if cfg.DryRecheck <= 0 {
		cfg.DryRecheck = 24 * time.Hour
	}
	if cfg.ComputeTokens <= 0 {
		cfg.ComputeTokens = 50
	}
	if cfg.MinShare <= 0 {
		cfg.MinShare = 0.05
	}
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Busy == nil {
		cfg.Busy = func() bool { return false }
	}
	if cfg.Stopped == nil {
		cfg.Stopped = func() bool { return false }
	}
	s := &Scheduler{cfg: cfg, wake: make(chan struct{}, 1), loops: map[Loop]*measure{}, last: cfg.Now()}
	seen := map[Loop]bool{}
	for _, src := range cfg.Sources {
		l := src.Loop()
		if l.number() == 0 {
			return nil, fmt.Errorf("loops: source for unknown loop %q", l)
		}
		if seen[l] {
			return nil, fmt.Errorf("loops: two sources for loop %s", l)
		}
		seen[l] = true
		s.loops[l] = &measure{}
	}
	b, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if b == nil {
		s.st = state{Settings: Settings{SpareCalls: DefaultSpareCalls}}
	} else if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("loops: saved state: %v", err)
	}
	if s.st.Applied == nil {
		s.st.Applied = map[string]bool{}
	}
	if err := cfg.Spare.SetOverallCap(SpareLimits(s.st.Settings.SpareCalls)); err != nil {
		return nil, err
	}
	if b == nil {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Attach gives the scheduler the journal (or gate) its settings intents go
// through; the engine needs the scheduler as an executor first.
func (s *Scheduler) Attach(j Journal) { s.cfg.Journal = j }

// Wake tells a sleeping scheduler that something new arrived: an owner
// outcome, a new release, the box going idle.
func (s *Scheduler) Wake() {
	s.mu.Lock()
	s.wakeLocked()
	s.mu.Unlock()
}

func (s *Scheduler) wakeLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// ErrSlowYield: running loop work did not return within the preemption
// target. Its machines are still preempted by admission (RES-1).
var ErrSlowYield = errors.New("loops: work did not yield within the preemption target")

// Preempt cancels running loop work because foreground or accepted work
// needs the box (LOOP-1), and waits at most YieldTarget for it to return.
// The work is offered again once the box is spare.
func (s *Scheduler) Preempt() error {
	s.mu.Lock()
	done := s.done
	if done != nil {
		s.preempted = true
		s.cancelLocked()
	}
	s.mu.Unlock()
	if done == nil {
		return nil
	}
	t := time.NewTimer(s.cfg.YieldTarget)
	defer t.Stop()
	select {
	case <-done:
		return nil
	case <-t.C:
		return ErrSlowYield
	}
}

func (s *Scheduler) cancelLocked() {
	if s.cancel != nil {
		s.cancel()
	}
}

// Run drives the scheduler until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	for {
		ran, wait := s.Tick(ctx)
		if ran {
			continue
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// Tick runs at most one unit of loop work. It returns whether work ran
// and, when none did, how long to wait before looking again.
func (s *Scheduler) Tick(ctx context.Context) (bool, time.Duration) {
	if s.cfg.Stopped() || s.cfg.Busy() {
		return false, s.cfg.Retry
	}
	set := s.Settings()
	if set.Off {
		return false, s.cfg.Idle
	}
	used, limit := s.cfg.Spare.Overall()
	modelOK := set.SpareCalls > 0 && used.Calls < limit.Calls && used.Tokens < limit.Tokens
	for _, src := range s.order(set) {
		job, ok := src.Next(ctx, modelOK)
		if !ok {
			continue
		}
		if job.UsesModel && !modelOK {
			s.cfg.Logf("loops: %s offered model work with no spare budget; skipped", src.Loop())
			continue
		}
		if s.cfg.Busy() || s.cfg.Stopped() {
			return false, s.cfg.Retry // the box got busy while the source looked
		}
		s.run(ctx, src.Loop(), job)
		return true, 0
	}
	// Nothing worthwhile remains: sleep (LOOP-3).
	return false, s.cfg.Idle
}

// order is the loops that may run now, most deserving first: share by
// measured return over recent spend (LOOP-3). Parked loops come back
// after DryRecheck.
func (s *Scheduler) order(set Settings) []Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	s.decayLocked(now)
	best := 0.0
	for _, m := range s.loops {
		if r := m.ret(); m.runs > 0 && r > best {
			best = r
		}
	}
	type cand struct {
		src  Source
		prio float64
		n    int
	}
	var cs []cand
	for _, src := range s.cfg.Sources {
		l := src.Loop()
		m := s.loops[l]
		if !set.On(l) || now.Before(m.parked) {
			continue
		}
		share := 1.0 // unmeasured: explore
		if m.runs > 0 {
			share = s.cfg.MinShare
			if best > 0 {
				share = math.Max(m.ret()/best, s.cfg.MinShare)
			}
		}
		cs = append(cs, cand{src, share / (1 + m.spent), l.number()})
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].prio != cs[j].prio {
			return cs[i].prio > cs[j].prio
		}
		return cs[i].n < cs[j].n
	})
	out := make([]Source, len(cs))
	for i, c := range cs {
		out[i] = c.src
	}
	return out
}

func (m *measure) ret() float64 { return m.value / math.Max(m.cost, 1) }

func (s *Scheduler) decayLocked(now time.Time) {
	dt := now.Sub(s.last)
	if dt <= 0 {
		return
	}
	f := math.Exp2(-float64(dt) / float64(s.cfg.HalfLife))
	for _, m := range s.loops {
		m.spent *= f
	}
	s.last = now
}

func (s *Scheduler) run(ctx context.Context, l Loop, job Job) {
	jctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.mu.Lock()
	s.cancel, s.runningLoop, s.done, s.preempted = cancel, l, done, false
	s.mu.Unlock()
	before, _ := s.cfg.Spare.Overall()
	start := s.cfg.Now()

	watch := make(chan struct{})
	go func() {
		t := time.NewTicker(s.cfg.Poll)
		defer t.Stop()
		for {
			select {
			case <-watch:
				return
			case <-t.C:
				if s.cfg.Busy() || s.cfg.Stopped() {
					s.mu.Lock()
					s.preempted = true
					s.cancelLocked()
					s.mu.Unlock()
					return
				}
			}
		}
	}()
	s.evaluating.Store(job.Evaluates)
	res := s.safeRun(jctx, job)
	s.evaluating.Store(false)
	close(watch)

	after, _ := s.cfg.Spare.Overall()
	secs := s.cfg.Now().Sub(start).Seconds()
	cost := float64(max(after.Tokens-before.Tokens, 0)) + math.Max(secs, 0)*s.cfg.ComputeTokens
	s.mu.Lock()
	preempted := s.preempted
	s.cancel, s.runningLoop, s.done = nil, "", nil
	m := s.loops[l]
	m.spent += cost
	if !preempted {
		// A preempted unit is offered again; it is not measured.
		v := math.Max(res.Value, 0)
		if m.runs == 0 {
			m.value, m.cost = v, cost
		} else {
			m.value = ewma*v + (1-ewma)*m.value
			m.cost = ewma*cost + (1-ewma)*m.cost
		}
		m.runs++
		if v > 0 {
			m.dry = 0
		} else if m.dry++; m.dry >= s.cfg.DryRuns {
			// It stopped producing value: park it (LOOP-3).
			m.parked, m.dry = s.cfg.Now().Add(s.cfg.DryRecheck), 0
		}
	}
	s.mu.Unlock()
	cancel()
	close(done)
	if res.Err != nil {
		s.cfg.Logf("loops: %s %s: %v", l, job.Name, res.Err)
	}
}

func (s *Scheduler) safeRun(ctx context.Context, job Job) (res Result) {
	defer func() {
		if v := recover(); v != nil {
			res = Result{Err: fmt.Errorf("panic: %v", v)}
		}
	}()
	return job.Run(ctx)
}

// Share reports each loop's current share of spare capacity, for STATUS
// and tests: its measured return relative to the best loop's, or 1 while
// unmeasured, and 0 while parked or off.
func (s *Scheduler) Share() map[Loop]float64 {
	set := s.Settings()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	best := 0.0
	for _, m := range s.loops {
		if r := m.ret(); m.runs > 0 && r > best {
			best = r
		}
	}
	out := map[Loop]float64{}
	for l, m := range s.loops {
		switch {
		case !set.On(l) || now.Before(m.parked):
			out[l] = 0
		case m.runs == 0:
			out[l] = 1
		case best == 0:
			out[l] = s.cfg.MinShare
		default:
			out[l] = math.Max(m.ret()/best, s.cfg.MinShare)
		}
	}
	return out
}

// Digest is the scheduler's lines for the owner's digest, in fixed
// wording: what is off, and the spare budget's use (LOOP-2), then each
// source's own lines.
func (s *Scheduler) Digest() []string {
	set := s.Settings()
	var out []string
	if set.Off {
		out = append(out, "Spare-time work is off. Reply LOOPS ON to restart it.")
	} else {
		for _, l := range All {
			if set.Paused[l] {
				out = append(out, fmt.Sprintf("%s is off. Reply %s ON to restart it.", capitalize(strings.ToLower(loopAliases[l])), loopAliases[l]))
			}
		}
	}
	used, _ := s.cfg.Spare.Overall()
	if used.Calls > 0 {
		out = append(out, fmt.Sprintf("Spare-time AI use, last 24 hours: %d of %d calls (self-tests and learning).", used.Calls, set.SpareCalls))
	}
	for _, src := range s.cfg.Sources {
		if d, ok := src.(Digester); ok && set.On(src.Loop()) {
			out = append(out, d.Digest()...)
		}
	}
	return out
}

var _ journal.Executor = (*Scheduler)(nil)

// EvalReserve is the share of the spare budget kept for replay evaluation
// while evaluation work runs (LOOP-5's separate evaluation budget; the
// arbitrator's work-conserving reserve on #49).
const EvalReserve = 0.3

// Evaluating reports whether the unit running now runs replay evaluations.
func (s *Scheduler) Evaluating() bool { return s.evaluating.Load() }

// EvalShare is the spare meter's share for replay machines: EvalReserve of
// the spare budget, kept from every other spare-meter user (builders, the
// clean room) while the scheduler runs evaluation work, and lent to them
// otherwise. The wiring passes it, with the clean room's share, to
// Spare.SetShares (loops L3).
func (s *Scheduler) EvalShare() meter.Share {
	return meter.Share{Prefix: vm.EvalPrefix, Reserve: EvalReserve, Active: s.Evaluating}
}
