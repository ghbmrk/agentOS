package loops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/skill/format"
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

// supersedes is a namespace a class may also delete from: a compiled skill
// replaces the procedure of its shape (CAP-5), and only that one.
var supersedes = map[change.Class]string{
	change.ClassSkill: "procedures",
}

// supersededBy reports whether path is a procedure file's name,
// procedures/p<shape>.json (format.IsFileName, so a free-form file is
// never "superseded", L3 and security R1 on #89), and the candidate writes
// exactly one file, that shape's skills/k<shape>.json.
// inClass has already checked that every skill or procedure file a
// candidate writes is for the task its name says (format.DecodeFile), so
// the name pairs the skill with its own shape's procedure (P3-6e).
func supersededBy(path string, files map[string][]byte) bool {
	shape, ok := strings.CutPrefix(path, "procedures/p")
	if !ok || !format.IsFileName(path) || len(files) != 1 {
		return false
	}
	_, ok = files["skills/k"+shape]
	return ok
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

// Readier is a builder that can tell, without model calls, that a
// hypothesis's evidence cannot yet yield a candidate (the skill compiler
// needs enough owner-accepted runs). Loop 1 then offers no job for it, so
// nothing is measured against the loop, and waits for more supporting
// tasks (L10).
type Readier interface {
	Ready(b Brief) bool
}

// Private is a builder whose candidates are never public, whatever the
// REV-5 labels of their inputs: it builds in a private machine with
// private model egress (loopbuild; security C-3c-4, C-3c-6).
type Private interface {
	Private(b Brief) bool
}

// BySignal routes each hypothesis to the builder for its signal, such as
// the skill compiler for repeated trajectories (CAP-5) and a model-backed
// agent for the rest.
type BySignal map[Signal]Builder

func (b BySignal) Handles(s Signal) bool { return b[s] != nil }

// Ready defers to the signal's builder when it is a Readier.
func (b BySignal) Ready(br Brief) bool {
	if r, ok := b[br.Hypothesis.Signal].(Readier); ok {
		return r.Ready(br)
	}
	return true
}

// Private defers to the signal's builder when it is Private.
func (b BySignal) Private(br Brief) bool {
	p, ok := b[br.Hypothesis.Signal].(Private)
	return ok && p.Private(br)
}

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
	// Unseeded reports a candidate nothing could use yet: it writes only
	// namespaces no machine is seeded from (skills and procedures before
	// W4). Loop 1 does not propose it, so the owner is never asked about
	// a change with no effect (UX-S3-1), and the digest counts it. Nil:
	// none.
	Unseeded func(change.Candidate) bool
	// Router may be nil: no routing candidates.
	Router change.Router
	// ModelWired reports that replay has model access (replay.RuleModel). Without
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
	// ResumeFor is how long a preempted candidate is kept for reuse:
	// change.ResumeFor unless set (36 h when the agent sleeps for
	// learning, PE7). It matches the pipeline's.
	ResumeFor time.Duration
}

// Learn is Loop 1's Source.
type Learn struct {
	cfg LearnConfig

	mu        sync.Mutex
	tried     map[string]int // hypothesis or routing key -> evidence when tried
	asks      map[string]int // key -> proposals that waited on the owner
	notBefore map[string]time.Time
	// needsExplicit maps the keys whose last proposal the explicit-case
	// anchor sent to the owner instead of adopting (change NeedsExplicit)
	// to that proposal's ID.
	needsExplicit map[string]string
	waiting       int // hypotheses held for evidence
	heldOut       int
	lastRecheck   time.Time
	recheckedAt   int // held-out count at the last recheck
	// built keeps a candidate whose evaluation was preempted, by
	// hypothesis key, so it is proposed again without another build and
	// the pipeline resumes its evaluation (PE1). In memory only.
	built map[string]keptCandidate
	// unseeded are the hypotheses whose candidate was not proposed
	// because nothing could use it yet (UX-S3-1), at most maxUnseeded.
	unseeded map[string]time.Time
	// nowTested is set when a held hypothesis is proposed after all, so
	// the next digest says once that drafted skills are being tested
	// (potency C1, UX-120-1 on #120).
	nowTested bool
	// gone are the goals forgotten since start (ForgetGoal).
	gone map[string]bool
	// triedGoals are the goals each tried hypothesis's evidence held, so
	// forgetting one lets it be tried again on what remains (CAP-3). In
	// memory only, like tried: a restart tries every hypothesis afresh.
	triedGoals map[string][]string
}

// ForgetGoal drops every candidate Loop 1 keeps that was built from goal,
// and keeps none built from it from now on (W3-tasks part 2, security C1
// on #120). Only the broker's handling of an authenticated owner forget
// calls it, with the pipeline's ForgetGoal (change C23); new hypotheses
// never mine a forgotten goal, since the daemon's tombstone hides its
// intents.
func (l *Learn) ForgetGoal(goal string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gone == nil {
		l.gone = map[string]bool{}
	}
	l.gone[goal] = true
	for k, kc := range l.built {
		if l.goneLocked(kc.cand.Goals) {
			delete(l.built, k)
		}
	}
	// SPEC CAP-3: what was learned from a forgotten task is rebuilt from
	// the remaining evidence, so a hypothesis tried with it is tried again
	// at once, with one task fewer, rather than waiting for more (potency
	// on #160).
	for k, goals := range l.triedGoals {
		if slices.Contains(goals, goal) {
			delete(l.tried, k)
			delete(l.notBefore, k)
			delete(l.triedGoals, k)
		}
	}
}

// Forgot reports whether ForgetGoal was called for goal since start. It
// is for tests: nothing decides on it.
func (l *Learn) Forgot(goal string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gone[goal]
}

func (l *Learn) goneLocked(goals []string) bool {
	for _, g := range goals {
		if l.gone[g] {
			return true
		}
	}
	return false
}

// goalsRead are the goals of the owner tasks a builder's brief carries:
// the hypothesis's evidence intents and the dev cases, sorted.
func goalsRead(h Hypothesis, dev []change.Case) []string {
	var out []string
	for _, s := range h.Evidence {
		if s.Intent.GoalID != "" {
			out = append(out, s.Intent.GoalID)
		}
	}
	for _, c := range dev {
		if c.Goal != "" {
			out = append(out, c.Goal)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Holds reports whether Loop 1 would build c but hold it unproposed,
// because nothing could use it yet (LearnConfig.Unseeded, L21).
func (l *Learn) Holds(c change.Candidate) bool {
	return l.cfg.Unseeded != nil && l.cfg.Unseeded(c)
}

// maxUnseeded bounds the hypotheses the digest counts as kept until the
// agent can use them.
const maxUnseeded = 256

// ErrUnseeded: the candidate was built but not proposed, since nothing
// could use it yet (LearnConfig.Unseeded).
var ErrUnseeded = errors.New("loops: candidate kept until a machine can use it")

// keptCandidate is a built candidate and the brief it was built from.
type keptCandidate struct {
	cand  change.Candidate
	brief string // briefDigest of the builder's brief
	tasks []string
	// intents are the journal intents the brief carried: its evidence
	// and its dev cases' tasks (ForgetIntents).
	intents []string
	at      time.Time
}

// ForgetIntents drops every kept candidate whose brief carried one of ids,
// as an evidence intent or a dev case's task: recall's deletion reach
// erases them (CAP-3, change C19; security F1 on #153), so a candidate
// built from them is not kept. The harvester's ForgetIntents calls it
// (NewLearn wires it), which the reach runs before the journal erases the
// intents and after.
func (l *Learn) ForgetIntents(ids []string) {
	gone := map[string]bool{}
	for _, id := range ids {
		gone[id] = true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, kc := range l.built {
		for _, in := range kc.intents {
			if gone[in] {
				delete(l.built, k)
				break
			}
		}
	}
}

// briefIntents are the journal intents a brief carries.
func briefIntents(h Hypothesis, dev []change.Case) []string {
	var out []string
	for _, s := range h.Evidence {
		out = append(out, s.Intent.ID)
	}
	for _, c := range dev {
		if c.Task != "" {
			out = append(out, c.Task)
		}
	}
	return out
}

// briefDigest names everything a builder saw: the hypothesis's tasks, its
// evidence intents and their labels, and the dev cases. A kept candidate
// is reused only for the same brief (L3 MUST-1 on #103), so a candidate
// built from a task that is now held out is never scored on that task.
func briefDigest(h Hypothesis, dev []change.Case) string {
	var parts []string
	for _, t := range h.Tasks {
		parts = append(parts, "t\x00"+t)
	}
	for _, s := range h.Evidence {
		parts = append(parts, "e\x00"+s.Intent.ID+"\x00"+s.Intent.Label)
	}
	for _, c := range dev {
		parts = append(parts, "d\x00"+c.ID)
	}
	sort.Strings(parts)
	return digest(h.Key + "\x01" + strings.Join(parts, "\x01"))
}

// maxKeptCandidates bounds Learn.built.
const maxKeptCandidates = 16

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
	l := &Learn{cfg: cfg, tried: map[string]int{}, asks: map[string]int{}, notBefore: map[string]time.Time{},
		needsExplicit: map[string]string{}, lastRecheck: cfg.Now(), built: map[string]keptCandidate{}, unseeded: map[string]time.Time{}}
	forget := l.ForgetIntents
	cfg.Harvest.erased.Store(&forget)
	return l, nil
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
			if ctx.Err() == nil && !errors.Is(err, change.ErrInterrupted) {
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
				l.done(ctx, err, key, ev.HeldOut, nil)
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
	ready, _ := l.cfg.Builder.(Readier)
	hyps = l.finishFirstLocked(hyps)
	for _, h := range hyps {
		if l.tried[h.Key] >= len(h.Tasks) || !l.mayAskLocked(h.Key) {
			continue // tried with this much evidence already, or the owner was asked lately
		}
		if sel != nil && !sel.Handles(h.Signal) {
			continue
		}
		if ready != nil && !ready.Ready(Brief{Hypothesis: h, Dev: ev.Dev}) {
			l.tried[h.Key] = len(h.Tasks) // wait for more supporting tasks
			l.triedGoalsLocked(h.Key, goalsRead(h, ev.Dev))
			continue
		}
		h := h
		return Job{Name: "candidate", UsesModel: true, Evaluates: true, Run: func(ctx context.Context) Result {
			rep, err := l.propose(ctx, h, ev)
			l.done(ctx, err, h.Key, len(h.Tasks), goalsRead(h, ev.Dev))
			if errors.Is(err, ErrUnseeded) {
				return Result{}
			}
			l.asked(h.Key, rep)
			return Result{Value: value(rep), Err: err}
		}}, true
	}
	return Job{}, false
}

// ResumeWindow is how long Loop 1 keeps a preempted candidate for
// reuse: LearnConfig.ResumeFor, or change.ResumeFor (PE7).
func (l *Learn) ResumeWindow() time.Duration { return l.resumeFor() }

func (l *Learn) resumeFor() time.Duration {
	if l.cfg.ResumeFor > 0 {
		return l.cfg.ResumeFor
	}
	return change.ResumeFor
}

// finishFirstLocked orders hyps so the kept candidate closest to a
// verdict is finished first (PE7 condition 19), where the pipeline counts
// kept pairs.
func (l *Learn) finishFirstLocked(hyps []Hypothesis) []Hypothesis {
	if kc, ok := l.cfg.Pipeline.(keptCounter); ok && len(l.built) > 0 {
		return finishFirst(hyps, l.built, kc)
	}
	return hyps
}

// keptCounter is the pipeline's count of a candidate's kept pairs
// (change.Pipeline.KeptPairs).
type keptCounter interface {
	KeptPairs(change.Candidate) int
}

var _ keptCounter = (*change.Pipeline)(nil)

// finishFirst puts the hypotheses whose kept candidate has kept pairs
// first, most pairs first, so the candidate closest to a verdict is
// finished before another starts (PE7); the rest keep their order.
func finishFirst(hyps []Hypothesis, built map[string]keptCandidate, kc keptCounter) []Hypothesis {
	n := make(map[string]int, len(built))
	for k, b := range built {
		n[k] = kc.KeptPairs(b.cand)
	}
	out := slices.Clone(hyps)
	slices.SortStableFunc(out, func(a, b Hypothesis) int { return n[b.Key] - n[a.Key] })
	return out
}

// mayAskLocked reports whether key may be proposed now: not while its
// backoff runs, and never after MaxAsks proposals waited on the owner.
func (l *Learn) mayAskLocked(key string) bool {
	return l.asks[key] < l.cfg.MaxAsks && !l.cfg.Now().Before(l.notBefore[key])
}

// asked starts key's backoff when its proposal waited on the owner, so an
// owner who lets a request lapse is not asked again every cycle.
func (l *Learn) asked(key string, rep change.Report) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rep.NeedsExplicit && rep.State == change.StateAwaitingOwner {
		l.needsExplicit[key] = rep.ID
	} else {
		delete(l.needsExplicit, key)
	}
	if rep.State != change.StateAwaitingOwner {
		return
	}
	l.asks[key]++
	l.notBefore[key] = l.cfg.Now().Add(l.cfg.Backoff << (l.asks[key] - 1))
}

// done marks a key tried, unless the work was preempted (ctx ended, or
// the evaluator was interrupted, PE3): then it is offered again.
func (l *Learn) done(ctx context.Context, err error, key string, n int, goals []string) {
	if ctx.Err() != nil || errors.Is(err, change.ErrInterrupted) {
		return
	}
	l.mu.Lock()
	l.tried[key] = n
	l.triedGoalsLocked(key, goals)
	l.mu.Unlock()
}

// triedGoalsLocked records the goals key was tried with (ForgetGoal).
func (l *Learn) triedGoalsLocked(key string, goals []string) {
	if len(goals) == 0 {
		delete(l.triedGoals, key)
		return
	}
	if l.triedGoals == nil {
		l.triedGoals = map[string][]string{}
	}
	l.triedGoals[key] = goals
}

// ErrOutOfClass: the builder wrote outside the namespace its hypothesis
// is for. The candidate is dropped, not proposed.
var ErrOutOfClass = errors.New("loops: candidate writes outside its hypothesis's namespace")

func (l *Learn) propose(ctx context.Context, h Hypothesis, ev Evidence) (change.Report, error) {
	brief := briefDigest(h, ev.Dev)
	l.mu.Lock()
	k, ok := l.built[h.Key]
	delete(l.built, h.Key)
	l.mu.Unlock()
	cand := k.cand
	reuse := ok && k.brief == brief && l.cfg.Now().Sub(k.at) <= l.resumeFor()
	for _, t := range k.tasks {
		reuse = reuse && !ev.Held(t)
	}
	if !reuse {
		// No kept candidate, or its brief changed, it expired, or one of
		// its tasks is now held out: build afresh.
		br := Brief{Hypothesis: h, Dev: ev.Dev}
		built, err := l.cfg.Builder.Build(ctx, br)
		if err != nil {
			return change.Report{}, err
		}
		// Checked and proposed bytes are the same: a builder keeps no
		// handle on what is checked (L3 on #89).
		cand = owned(built)
		if err := inClass(h.Class, cand); err != nil {
			return change.Report{}, err
		}
		// Source, origin, and the public mark are the broker's, from the
		// REV-5 labels of every input; the builder asserts none of them.
		cand.Source, cand.Origin, cand.Public = change.Local, "loop1", public(h, ev.Dev)
		cand.Goals = goalsRead(h, ev.Dev)
		if p, ok := l.cfg.Builder.(Private); ok && p.Private(br) {
			cand.Public = false
		}
	}
	l.mu.Lock()
	if l.Holds(cand) {
		l.unseeded[h.Key] = l.cfg.Now()
		for len(l.unseeded) > maxUnseeded {
			oldest := ""
			for k, at := range l.unseeded {
				if oldest == "" || at.Before(l.unseeded[oldest]) || at.Equal(l.unseeded[oldest]) && k < oldest {
					oldest = k
				}
			}
			delete(l.unseeded, oldest)
		}
		l.mu.Unlock()
		return change.Report{}, ErrUnseeded
	}
	if _, held := l.unseeded[h.Key]; held {
		delete(l.unseeded, h.Key)
		l.nowTested = true
	}
	l.mu.Unlock()
	rep, err := l.cfg.Pipeline.Propose(ctx, cand)
	if errors.Is(err, change.ErrInterrupted) {
		// Preempted mid-evaluation: keep the checked candidate for the
		// next offer, so the pipeline can resume its pairs, unless its
		// goal was forgotten or an intent erased meanwhile.
		intents := briefIntents(h, ev.Dev)
		l.mu.Lock()
		if l.goneLocked(cand.Goals) || l.cfg.Harvest.erasedAny(intents) {
			// Security F1 on #153; change C23.
			l.mu.Unlock()
			return rep, err
		}
		l.built[h.Key] = keptCandidate{cand: cand, brief: brief, tasks: slices.Clone(h.Tasks),
			intents: intents, at: l.cfg.Now()}
		for len(l.built) > maxKeptCandidates {
			oldest := ""
			for k, v := range l.built {
				if oldest == "" || v.at.Before(l.built[oldest].at) || v.at.Equal(l.built[oldest].at) && k < oldest {
					oldest = k
				}
			}
			delete(l.built, oldest)
		}
		l.mu.Unlock()
	}
	return rep, err
}

// owned copies a candidate's files and deletions.
func owned(c change.Candidate) change.Candidate {
	files := make(map[string][]byte, len(c.Files))
	for p, b := range c.Files {
		files[p] = bytes.Clone(b)
	}
	c.Files, c.Delete = files, slices.Clone(c.Delete)
	return c
}

// inClass checks that a candidate writes only its class's namespace, and
// deletes only there or in the namespace the class supersedes. Every file
// it writes with a skill or procedure file's name (the only ones the skill
// bridge offers or a skill supersedes) must decode canonically as one whose
// name is its own: its ID, and the shape its steps give (security R1 on
// #74, C1 on #89).
func inClass(class change.Class, cand change.Candidate) error {
	ns := classNS[class]
	for p, b := range cand.Files {
		if first, _, _ := strings.Cut(p, "/"); first != ns {
			return fmt.Errorf("%w: %s", ErrOutOfClass, class)
		}
		if format.IsFileName(p) {
			if _, err := format.DecodeFile(p, b); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrOutOfClass, class, err)
			}
		}
	}
	for _, p := range cand.Delete {
		first, _, _ := strings.Cut(p, "/")
		if first == ns {
			continue
		}
		if first != supersedes[class] || !supersededBy(p, cand.Files) {
			return fmt.Errorf("%w: %s", ErrOutOfClass, class)
		}
	}
	return nil
}

// value is a proposal's measured return: its held-out gain over the
// baseline, implicit cases' gain counted half (potency C3(c) on #90), plus
// a little for an adoption with no gain (it qualified with no regression),
// half for one waiting on the owner, none if rejected.
func value(rep change.Report) float64 {
	explicit := (rep.Passed - rep.ImplicitPassed) - (rep.BaselinePassed - rep.ImplicitBaselinePassed)
	gain := math.Max(float64(explicit)+float64(rep.ImplicitPassed-rep.ImplicitBaselinePassed)/2, 0)
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

// Digest is Loop 1's lines: while it waits for evidence (C14 (b)), and
// for ideas the explicit-case anchor sent to the owner (change
// NeedsExplicit; potency on the PW3 design).
func (l *Learn) Digest() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	if l.waiting > 0 && l.heldOut < l.cfg.MinHeldOut {
		out = append(out, fmt.Sprintf("Learning: %d ideas are waiting until there are %d past tasks to test them on (%d so far).",
			l.waiting, l.cfg.MinHeldOut, l.heldOut))
	}
	// Only requests still waiting count: one that lapsed is listed by the
	// owner channel instead (L18), never twice (UX on #109).
	w, _ := l.cfg.Pipeline.(interface{ Waiting(id string) bool })
	n := 0
	for _, id := range l.needsExplicit {
		if w == nil || w.Waiting(id) {
			n++
		}
	}
	switch {
	case n == 1:
		out = append(out, "Learning: 1 idea is waiting for your approval instead of taking effect on its own, because it wasn't tested on a task you said YES to.")
	case n > 1:
		out = append(out, fmt.Sprintf("Learning: %d ideas are waiting for your approval instead of taking effect on their own, because none was tested on a task you said YES to.", n))
	}
	// Built but not proposed, since the agent cannot use them yet
	// (UX-S3-1).
	switch n := len(l.unseeded); {
	case n == 1:
		out = append(out, "Learning: 1 new skill drafted. It'll be tested once your agent can use it.")
	case n > 1:
		out = append(out, fmt.Sprintf("Learning: %d new skills drafted. They'll be tested once your agent can use them.", n))
	case l.nowTested:
		// Once, when the agent can use them after all.
		out = append(out, "Learning: drafted skills are now being tested.")
		l.nowTested = false
	}
	return out
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
// builder (CHG-1). Broker-state intents, and the broker's own effects
// (origin "broker:...", such as CH-20's evidence email carrying private
// replies), are not tasks.
func (l *Learn) mine(ev Evidence) []Hypothesis {
	sts := l.cfg.Journal.List()
	held := heldWithNext(sts, ev)
	byTask := map[string][]journal.Status{}
	var order []string
	for _, s := range sts {
		if s.Intent.Account == journal.BrokerAccount || strings.HasPrefix(s.Intent.Origin, "broker:") {
			continue
		}
		k := TaskKey(s.Intent)
		if held[k] {
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

// heldWithNext is the task keys mining skips (arbitrator on #55). Every
// held key; and, around each held case in a lineage, the goals whose work
// may be the held task's own (guest G14):
//   - a held goal's span runs from its first to its last intent; every
//     other goal with an intent inside it ran while it was active;
//   - a held case with no goal (the lineage held two messages open, or none
//     was attributable) is a span of that one intent, and the nearest goal
//     stamped before it is held too, since the unstamped work may be that
//     goal's;
//   - after either span, the first goal the lineage started is held: a
//     guest still finishing the held task when handed the next owner
//     message stamps that trailing work with the next goal.
//
// Each held case is handled on its own, so several held goals each hold
// their own neighbours. Trailing work that lands past the next goal is
// still mined (loops L8). Order is the journal's submission order; the
// unstamped bucket itself is the origin key, which Evidence holds.
func heldWithNext(sts []journal.Status, ev Evidence) map[string]bool {
	held := map[string]bool{}
	type at struct {
		i int
		k string // goal key; "" for an unstamped intent
	}
	type span struct{ first, last int }
	type ok struct{ origin, k string }
	byOrigin := map[string][]at{} // origin -> intents in order
	// goalSpan is per origin: a goal's work can reach more than one
	// lineage (a CAP-8 worker stamped with its creator's goal, G14 (b)).
	goalSpan := map[ok]*span{}
	var points []struct {
		origin string
		i      int
	}
	for i, s := range sts {
		in := s.Intent
		if in.Account == journal.BrokerAccount {
			continue
		}
		k := TaskKey(in)
		if ev.Held(k) {
			held[k] = true
		}
		if in.GoalID == "" {
			byOrigin[in.Origin] = append(byOrigin[in.Origin], at{i, ""})
			if ev.heldIntents[in.ID] {
				points = append(points, struct {
					origin string
					i      int
				}{in.Origin, i})
			}
			continue
		}
		if sp := goalSpan[ok{in.Origin, k}]; sp == nil {
			goalSpan[ok{in.Origin, k}] = &span{i, i}
		} else {
			sp.last = i
		}
		byOrigin[in.Origin] = append(byOrigin[in.Origin], at{i, k})
	}
	// around holds the goals of origin within [first, last], the first
	// goal started after it, and, when before is set, the nearest goal
	// stamped before it.
	around := func(origin string, first, last int, before bool) {
		ats := byOrigin[origin]
		for _, a := range ats {
			if a.k == "" {
				continue
			}
			if a.i >= first && a.i <= last {
				held[a.k] = true
			}
			if a.i > last && goalSpan[ok{origin, a.k}].first > last {
				held[a.k] = true
				break
			}
		}
		if before {
			for n := len(ats) - 1; n >= 0; n-- {
				if a := ats[n]; a.i < first && a.k != "" {
					held[a.k] = true
					break
				}
			}
		}
	}
	for g, sp := range goalSpan {
		if ev.Held(g.k) {
			around(g.origin, sp.first, sp.last, false)
		}
	}
	for _, p := range points {
		around(p.origin, p.i, p.i, true)
	}
	return held
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
