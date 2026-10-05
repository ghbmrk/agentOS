package loops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// Signal is what in the journal a hypothesis comes from (LOOP-4).
type Signal string

const (
	SignalFailure    Signal = "failure"    // an effect that did not happen or is unknown
	SignalCorrection Signal = "correction" // the owner's wrong verdict
	SignalSlow       Signal = "slow"       // a step that took long to complete
	SignalExpensive  Signal = "expensive"  // a task that cost far more than usual
	SignalRepeat     Signal = "repeat"     // the same trajectory across tasks
)

// signalClass is the kind of candidate each signal asks for: a better
// procedure for failures and corrections, a compiled skill for slow or
// repeated steps, a narrower context for expensive tasks.
var signalClass = map[Signal]change.Class{
	SignalFailure:    change.ClassProcedure,
	SignalCorrection: change.ClassProcedure,
	SignalSlow:       change.ClassSkill,
	SignalRepeat:     change.ClassSkill,
	SignalExpensive:  change.ClassContext,
}

// classNS is where a candidate for a class may write.
var classNS = map[change.Class]string{
	change.ClassProcedure: "procedures",
	change.ClassSkill:     "skills",
	change.ClassContext:   "context",
}

// Hypothesis is one thing Loop 1 might improve (LOOP-4). It names journal
// identifiers (accounts and actions) and the tasks behind it, never a
// held-out task.
type Hypothesis struct {
	Signal Signal
	Class  change.Class
	// Key identifies the hypothesis: the signal and the actions involved.
	Key string
	// Tasks are the task keys behind it (TaskKey).
	Tasks []string
	// Evidence is the journal record of those tasks.
	Evidence []journal.Status
}

// Brief is everything a builder gets: the hypothesis and the dev split.
// It carries no held-out case, no evaluation count, and no evaluation
// model-call record (CHG-1; replay K3; change C14 (d)).
type Brief struct {
	Hypothesis Hypothesis
	Dev        []change.Case
}

// Builder turns a hypothesis into a candidate, typically by running a
// model-backed agent in an experiment machine whose model calls go through
// the spare budget meter. Whatever it returns is only a proposal.
type Builder interface {
	Build(ctx context.Context, b Brief) (change.Candidate, error)
}

// Handler is a builder that builds only for some signals; Loop 1 offers it
// only those hypotheses.
type Handler interface {
	Handles(Signal) bool
}

// BySignal routes each hypothesis to the builder for its signal, such as
// the skill compiler for repeated trajectories (CAP-5) and a model-backed
// agent for the rest.
type BySignal map[Signal]Builder

func (b BySignal) Handles(s Signal) bool { return b[s] != nil }

func (b BySignal) Build(ctx context.Context, br Brief) (change.Candidate, error) {
	x := b[br.Hypothesis.Signal]
	if x == nil {
		return change.Candidate{}, fmt.Errorf("loops: no builder for %s", br.Hypothesis.Signal)
	}
	return x.Build(ctx, br)
}

// Pipeline is the part of the change pipeline Loop 1 drives. Proposing is
// Loop 1's only way to change anything (LOOP-6).
type Pipeline interface {
	Propose(ctx context.Context, c change.Candidate) (change.Report, error)
	ProposeRouting(ctx context.Context, r change.Router) (change.Report, bool, error)
	Recheck(ctx context.Context) ([]string, error)
	Adoptions() []change.Adoption
}

// JournalReader is what the miner reads.
type JournalReader interface {
	List() []journal.Status
	Trail() []journal.Record
}

// LearnConfig configures NewLearn.
type LearnConfig struct {
	Pipeline Pipeline
	Journal  JournalReader
	Harvest  *Harvester
	// Builder may be nil: Loop 1 then proposes only routing rules and
	// rechecks adoptions.
	Builder Builder
	// Router may be nil: no routing candidates.
	Router change.Router
	// ModelWired reports that replay has model access (EvalModel). Without
	// it evaluation is offline, so routing candidates are not proposed
	// (both sides would answer alike) and no evaluation counts as model
	// work.
	ModelWired bool
	// Cost returns a task's model tokens, for the expensive signal. Nil:
	// no expensive signal.
	Cost func(task string) (int64, bool)
	// MinHeldOut is the held-out evidence a proposal waits for (C14 (b));
	// set it to the pipeline's MinHeldOut. Default 5.
	MinHeldOut int
	// SlowStep marks a step slow; Repeat is how many tasks make a
	// trajectory repeated; ExpensiveFactor is how many times the median
	// cost makes a task expensive. Defaults 2 minutes, 3, and 3.
	SlowStep        time.Duration
	Repeat          int
	ExpensiveFactor float64
	// RecheckCases is how many new held-out cases make Recheck due;
	// RecheckEvery runs it anyway after that long if any arrived.
	// Defaults 5 and 7 days.
	RecheckCases int
	RecheckEvery time.Duration
	// Backoff is how long after a proposal that waited on the owner the
	// same hypothesis may be proposed again; it doubles each time, and
	// after MaxAsks it is not proposed again: the owner's digest lists it
	// (change C14 (g), arbitrator PL1). Defaults 24 hours and 2.
	Backoff time.Duration
	MaxAsks int
	Now     func() time.Time
}

// Learn is Loop 1's Source.
type Learn struct {
	cfg LearnConfig

	mu          sync.Mutex
	tried       map[string]int // hypothesis or routing key -> evidence when tried
	asks        map[string]int // key -> proposals that waited on the owner
	notBefore   map[string]time.Time
	waiting     int // hypotheses held for evidence
	heldOut     int
	lastRecheck time.Time
	recheckedAt int // held-out count at the last recheck
}

// NewLearn checks cfg and returns Loop 1's source.
func NewLearn(cfg LearnConfig) (*Learn, error) {
	if cfg.Pipeline == nil || cfg.Journal == nil || cfg.Harvest == nil {
		return nil, errors.New("loops: Pipeline, Journal, and Harvest are required")
	}
	if cfg.MinHeldOut <= 0 {
		cfg.MinHeldOut = 5
	}
	if cfg.SlowStep <= 0 {
		cfg.SlowStep = 2 * time.Minute
	}
	if cfg.Repeat <= 1 {
		cfg.Repeat = 3
	}
	if cfg.ExpensiveFactor <= 1 {
		cfg.ExpensiveFactor = 3
	}
	if cfg.RecheckCases <= 0 {
		cfg.RecheckCases = 5
	}
	if cfg.RecheckEvery <= 0 {
		cfg.RecheckEvery = 7 * 24 * time.Hour
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 24 * time.Hour
	}
	if cfg.MaxAsks <= 0 {
		cfg.MaxAsks = 2
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Learn{cfg: cfg, tried: map[string]int{}, asks: map[string]int{}, notBefore: map[string]time.Time{},
		lastRecheck: cfg.Now()}, nil
}

func (l *Learn) Loop() Loop { return Improve }

// Next offers, in order: a due recheck of adopted changes, a routing rule
// the router measured, and a candidate for the next untried hypothesis.
// With too little held-out evidence it proposes nothing and the digest
// says it is waiting (C14 (b)).
func (l *Learn) Next(ctx context.Context, modelOK bool) (Job, bool) {
	ev, err := l.cfg.Harvest.Evidence()
	if err != nil {
		return Job{}, false
	}
	evalModel := l.cfg.ModelWired
	if evalModel && !modelOK {
		return Job{}, false // every evaluation would call the model
	}
	active := false
	for _, a := range l.cfg.Pipeline.Adoptions() {
		active = active || a.Reverted == ""
	}
	l.mu.Lock()
	l.heldOut = ev.HeldOut
	if !active {
		// Nothing to recheck: whatever is adopted next is evaluated on
		// every case there is now, so only later cases count.
		l.recheckedAt, l.lastRecheck = ev.HeldOut, l.cfg.Now()
	}
	due := ev.HeldOut-l.recheckedAt >= l.cfg.RecheckCases ||
		ev.HeldOut > l.recheckedAt && l.cfg.Now().Sub(l.lastRecheck) >= l.cfg.RecheckEvery
	l.mu.Unlock()
	if due {
		return Job{Name: "recheck", UsesModel: evalModel, Evaluates: true, Run: func(ctx context.Context) Result {
			reverted, err := l.cfg.Pipeline.Recheck(ctx)
			if ctx.Err() == nil {
				l.mu.Lock()
				l.recheckedAt, l.lastRecheck = ev.HeldOut, l.cfg.Now()
				l.mu.Unlock()
			}
			// Each revert removed a change that now does worse.
			return Result{Value: float64(len(reverted)), Err: err}
		}}, true
	}

	hyps := l.mine(ev)
	l.mu.Lock()
	defer l.mu.Unlock()
	if ev.HeldOut < l.cfg.MinHeldOut {
		l.waiting = len(hyps)
		return Job{}, false
	}
	l.waiting = 0
	if l.cfg.Router != nil && l.cfg.ModelWired {
		key := "routing:" + digest(fmt.Sprint(l.cfg.Router.Candidate()))
		if l.tried[key] < ev.HeldOut && l.mayAskLocked(key) {
			return Job{Name: "routing", UsesModel: true, Evaluates: true, Run: func(ctx context.Context) Result {
				rep, ok, err := l.cfg.Pipeline.ProposeRouting(ctx, l.cfg.Router)
				l.done(ctx, key, ev.HeldOut)
				l.asked(key, rep)
				if !ok {
					return Result{Err: err}
				}
				return Result{Value: value(rep), Err: err}
			}}, true
		}
	}
	if l.cfg.Builder == nil {
		return Job{}, false
	}
	sel, _ := l.cfg.Builder.(Handler)
	for _, h := range hyps {
		if l.tried[h.Key] >= len(h.Tasks) || !l.mayAskLocked(h.Key) {
			continue // tried with this much evidence already, or the owner was asked lately
		}
		if sel != nil && !sel.Handles(h.Signal) {
			continue
		}
		h := h
		return Job{Name: "candidate", UsesModel: true, Evaluates: true, Run: func(ctx context.Context) Result {
			rep, err := l.propose(ctx, h, ev)
			l.done(ctx, h.Key, len(h.Tasks))
			l.asked(h.Key, rep)
			return Result{Value: value(rep), Err: err}
		}}, true
	}
	return Job{}, false
}

// mayAskLocked reports whether key may be proposed now: not while its
// backoff runs, and never after MaxAsks proposals waited on the owner.
func (l *Learn) mayAskLocked(key string) bool {
	return l.asks[key] < l.cfg.MaxAsks && !l.cfg.Now().Before(l.notBefore[key])
}

// asked starts key's backoff when its proposal waited on the owner, so an
// owner who lets a request lapse is not asked again every cycle.
func (l *Learn) asked(key string, rep change.Report) {
	if rep.State != change.StateAwaitingOwner {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asks[key]++
	l.notBefore[key] = l.cfg.Now().Add(l.cfg.Backoff << (l.asks[key] - 1))
}

// done marks a key tried, unless the work was preempted: then it is
// offered again.
func (l *Learn) done(ctx context.Context, key string, n int) {
	if ctx.Err() != nil {
		return
	}
	l.mu.Lock()
	l.tried[key] = n
	l.mu.Unlock()
}

// ErrOutOfClass: the builder wrote outside the namespace its hypothesis
// is for. The candidate is dropped, not proposed.
var ErrOutOfClass = errors.New("loops: candidate writes outside its hypothesis's namespace")

func (l *Learn) propose(ctx context.Context, h Hypothesis, ev Evidence) (change.Report, error) {
	cand, err := l.cfg.Builder.Build(ctx, Brief{Hypothesis: h, Dev: ev.Dev})
	if err != nil {
		return change.Report{}, err
	}
	ns := classNS[h.Class]
	for p := range cand.Files {
		if first, _, _ := strings.Cut(p, "/"); first != ns {
			return change.Report{}, fmt.Errorf("%w: %s", ErrOutOfClass, h.Class)
		}
	}
	for _, p := range cand.Delete {
		if first, _, _ := strings.Cut(p, "/"); first != ns {
			return change.Report{}, fmt.Errorf("%w: %s", ErrOutOfClass, h.Class)
		}
	}
	// Source, origin, and the public mark are the broker's, from the
	// REV-5 labels of every input; the builder asserts none of them.
	cand.Source, cand.Origin, cand.Public = change.Local, "loop1", public(h, ev.Dev)
	return l.cfg.Pipeline.Propose(ctx, cand)
}

// value is a proposal's measured return: its held-out gain over the
// baseline, plus a little for an adoption with no gain (it qualified with
// no regression), half for one waiting on the owner, none if rejected.
func value(rep change.Report) float64 {
	gain := math.Max(float64(rep.Passed-rep.BaselinePassed), 0)
	switch rep.State {
	case change.StateAdopted:
		return gain + 0.25
	case change.StateAwaitingOwner:
		return gain / 2
	}
	return 0
}

func public(h Hypothesis, dev []change.Case) bool {
	for _, s := range h.Evidence {
		if s.Intent.Label != "public" {
			return false
		}
	}
	for _, c := range dev {
		if !c.Public {
			return false
		}
	}
	return true
}

// Digest is Loop 1's line while it waits for evidence (C14 (b)).
func (l *Learn) Digest() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.waiting == 0 || l.heldOut >= l.cfg.MinHeldOut {
		return nil
	}
	return []string{fmt.Sprintf("Learning: %d ideas are waiting until there are %d past tasks to test them on (%d so far).",
		l.waiting, l.cfg.MinHeldOut, l.heldOut)}
}

// TaskKey is the task an intent belongs to: its goal, or, for intents
// with none, the origin that ran it (replay ASSUMPTIONS R4).
func TaskKey(in journal.Intent) string {
	if in.GoalID != "" {
		return "goal:" + in.GoalID
	}
	return originKey(in)
}

// originKey is the task key of in's origin's intents that carry no goal.
func originKey(in journal.Intent) string { return "origin:" + in.Origin }

// mine turns the journal into hypotheses (LOOP-4). A task with a held-out
// case is never mined, so nothing from the held-out suite reaches a
// builder (CHG-1). Broker-state intents are not tasks.
func (l *Learn) mine(ev Evidence) []Hypothesis {
	sts := l.cfg.Journal.List()
	byTask := map[string][]journal.Status{}
	var order []string
	for _, s := range sts {
		if s.Intent.Account == journal.BrokerAccount {
			continue
		}
		k := TaskKey(s.Intent)
		if ev.Held(k) {
			continue
		}
		if _, ok := byTask[k]; !ok {
			order = append(order, k)
		}
		byTask[k] = append(byTask[k], s)
	}
	took := l.durations()

	type agg struct {
		h     Hypothesis
		tasks map[string]bool
		n     int
	}
	found := map[string]*agg{}
	add := func(sig Signal, what, task string, n int, sts []journal.Status) {
		key := string(sig) + ":" + what
		a := found[key]
		if a == nil {
			a = &agg{h: Hypothesis{Signal: sig, Class: signalClass[sig], Key: key}, tasks: map[string]bool{}}
			found[key] = a
		}
		a.n += n
		if !a.tasks[task] {
			a.tasks[task] = true
			a.h.Tasks = append(a.h.Tasks, task)
			a.h.Evidence = append(a.h.Evidence, sts...)
		}
	}
	trajectories := map[string][]string{}
	var costs []int64
	taskCost := map[string]int64{}
	for _, k := range order {
		ts := byTask[k]
		var seq []string
		for _, s := range ts {
			act := s.Intent.Account + "/" + s.Intent.Action
			seq = append(seq, act)
			switch s.State {
			case journal.NotApplied, journal.OutcomeUnknown:
				add(SignalFailure, act, k, 1, ts)
			}
			if s.Quality.Verdict == journal.VerdictWrong && s.Quality.Source == l.cfg.Harvest.source() {
				add(SignalCorrection, act, k, 1, ts)
			}
			if d, ok := took[s.Intent.ID]; ok && d > l.cfg.SlowStep {
				add(SignalSlow, act, k, 1, ts)
			}
		}
		if len(seq) >= 2 {
			sig := strings.Join(seq, ">")
			trajectories[sig] = append(trajectories[sig], k)
		}
		if l.cfg.Cost != nil {
			if c, ok := l.cfg.Cost(k); ok {
				costs = append(costs, c)
				taskCost[k] = c
			}
		}
	}
	for sig, tasks := range trajectories {
		if len(tasks) >= l.cfg.Repeat {
			for _, k := range tasks {
				add(SignalRepeat, sig, k, 1, byTask[k])
			}
		}
	}
	if len(costs) >= 3 {
		sort.Slice(costs, func(i, j int) bool { return costs[i] < costs[j] })
		median := float64(costs[len(costs)/2])
		for _, k := range order {
			if c, ok := taskCost[k]; ok && median > 0 && float64(c) > l.cfg.ExpensiveFactor*median {
				first := byTask[k][0].Intent
				add(SignalExpensive, first.Account+"/"+first.Action, k, 1, byTask[k])
			}
		}
	}
	var out []Hypothesis
	for _, a := range found {
		// A slow step must recur to be a pattern, not a bad moment.
		if a.h.Signal == SignalSlow && a.n < 2 {
			continue
		}
		out = append(out, a.h)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Tasks) != len(out[j].Tasks) {
			return len(out[i].Tasks) > len(out[j].Tasks) // most evidence first
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// durations is how long each dispatched intent took from its first
// dispatch to its first final observation.
func (l *Learn) durations() map[string]time.Duration {
	start := map[string]time.Time{}
	out := map[string]time.Duration{}
	for _, r := range l.cfg.Journal.Trail() {
		switch r.Type {
		case journal.RecDispatched:
			if _, ok := start[r.ID]; !ok {
				start[r.ID] = r.At
			}
		case journal.RecObserved:
			if r.Result != journal.ResultSucceeded && r.Result != journal.ResultNotApplied {
				continue
			}
			if t, ok := start[r.ID]; ok {
				if _, seen := out[r.ID]; !seen {
					out[r.ID] = r.At.Sub(t)
				}
			}
		}
	}
	return out
}

func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
