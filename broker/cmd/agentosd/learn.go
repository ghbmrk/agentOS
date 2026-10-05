package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/replay"
	"github.com/ghbmrk/agentos/broker/routerule"
	"github.com/ghbmrk/agentos/broker/vm"
)

// learning is the learning plane (W3, loops L16): the change pipeline, the
// loop scheduler with Loop 1, and the spare meter, all deterministic and in
// this process. Model-calling builders stay behind a socket (W3 step 3);
// until then Loop 1 only rechecks adoptions. It needs the engine, which the
// daemon builds from the gate it configures, so its journal and admission
// are bound late (attach), and the replay evaluator, which needs the
// machine manager, later still (openEvaluator).
type learning struct {
	spare   *meter.Meter
	pipe    *change.Pipeline
	sched   *loops.Scheduler
	harvest *loops.Harvester
	cases   harvester // where owner verdicts go: harvest, or a test's
	eval    lateEvaluator
	eng     atomic.Pointer[journal.Engine]
	adm     atomic.Pointer[admission.Controller]
	routing *syncedRouting // nil: routing held
	tasks   *taskTexts     // the owner's task texts, for harvesting
	// verdicts queues the gate's owner verdicts for harvesting, so a slow
	// learning plane never holds the gate (security A2 on PW3).
	verdicts chan grants.OwnerOutcome
}

// learnPaths are where the learning plane keeps its state.
type learnPaths struct {
	Dir   string // pipeline, scheduler, and harvest state
	Spare string // the spare meter (LOOP-2), apart from the guests' OP-8 meter
	// Routing is the vault process's routing socket, through which the
	// pipeline reads and adopts the active routing rule (PW4 on #90).
	// Empty holds routing changes (heldRouting).
	Routing string
}

// openLearning opens the learning plane and wires it into the daemon's
// configuration: the gate's Changes and Loops policies, their executors,
// and the owner's settings texts.
func openLearning(p learnPaths, modelWired bool, cfg *daemon.Config) (*learning, error) {
	l := &learning{}
	spare, err := meter.Open(meter.Config{
		Path: p.Spare,
		// The scheduler sets the overall cap from the owner's setting;
		// until then it is the least the meter allows.
		MachineCap: meter.DefaultMachineCap,
		OverallCap: loops.SpareLimits(0),
	})
	if err != nil {
		return nil, err
	}
	l.spare = spare
	var target change.Target = heldRouting{}
	var sync *syncedRouting
	if p.Routing != "" {
		sync = &syncedRouting{r: modelroute.NewRouting(p.Routing), restoring: true, logf: log.Printf}
		target = sync
	}
	if l.pipe, err = change.New(change.Config{
		Store:     change.FileStore{Path: filepath.Join(p.Dir, "change.json")},
		Evaluator: &l.eval,
		Targets:   map[string]change.Target{"routing": target},
	}); err != nil {
		return nil, err
	}
	var router change.Router
	if sync != nil {
		sync.doneRestoring()
		pipe := l.pipe
		sync.active = func() routerule.Rule { return routerOf{pipe: pipe}.active() }
		sync.note = pipe.Notice
		l.routing = sync
		router = routerOf{sync, l.pipe}
	}
	l.harvest = &loops.Harvester{J: lateQuality{&l.eng}, Pipeline: l.pipe, Store: change.FileStore{Path: filepath.Join(p.Dir, "harvest.json")}}
	if l.tasks, err = openTaskTexts(change.FileStore{Path: filepath.Join(p.Dir, "tasks.json")}, time.Now, log.Printf); err != nil {
		return nil, err
	}
	learn, err := loops.NewLearn(loops.LearnConfig{
		Pipeline:   l.pipe,
		Journal:    lateReader{&l.eng},
		Harvest:    l.harvest,
		Router:     router,
		ModelWired: modelWired,
	})
	if err != nil {
		return nil, err
	}
	if l.sched, err = loops.New(loops.Config{
		Store:   change.FileStore{Path: filepath.Join(p.Dir, "loops.json")},
		Spare:   spare,
		Sources: []loops.Source{learn},
		Sharing: l.pipe.SetSharing,
		Busy:    l.busy,
		Stopped: l.stopped,
		Logf:    log.Printf,
	}); err != nil {
		return nil, err
	}
	l.harvest.Wake = l.sched.Wake
	l.cases = l.harvest
	// Evaluation keeps its reserve of the spare budget while Loop 1
	// evaluates (loops L3). The clean room takes its Max here once it
	// exists.
	if err := spare.SetShares([]meter.Share{l.sched.EvalShare()}); err != nil {
		return nil, err
	}
	cfg.Grants.Changes = l.pipe
	cfg.Grants.Loops = l.sched
	if cfg.BrokerExecutors == nil {
		cfg.BrokerExecutors = map[string]journal.Executor{}
	}
	cfg.BrokerExecutors[change.Executor] = l.pipe
	cfg.BrokerExecutors[loops.Executor] = l.sched
	cfg.Settings = l.sched.Text
	cfg.Narrows = l.sched.Narrows
	cfg.HelpExtra = loops.HelpLine
	// The owner's verdicts on the agent's effects become Loop 1's cases
	// (loops L6; potency PW3 on #90). Set last, once nothing
	// can fail, so a plane that did not open has no hook (security F1).
	l.verdicts = make(chan grants.OwnerOutcome, maxVerdicts)
	cfg.Grants.Outcome = func(o grants.OwnerOutcome) {
		select {
		case l.verdicts <- o:
		default:
			log.Printf("learning: owner verdict not harvested: queue full")
		}
	}
	return l, nil
}

// learningOffText answers loop settings and ends HELP when the learning
// plane could not start (L3 S3 on #90). It names everything the loop texts
// cover, and a restart retries opening the plane (UX-92-1).
const learningOffText = "Spare-time work (learning, self-tests, update checks) is not running on this box. Restarting the box may fix it."

// learningOffNote is STATUS's line for it, so the owner learns it without
// sending a loop setting (UX R1 on #92).
const learningOffNote = "Spare-time work: not running."

// learningOff wires the owner's loop settings when the learning plane
// could not start: they are answered by the box, locked or not, never sent
// to the agent as chat, and change nothing.
func learningOff(cfg *daemon.Config) {
	cfg.Settings = func(_ context.Context, msg string, _ bool) (string, bool) {
		if _, ok := loops.ParseText(msg); ok {
			return learningOffText, true
		}
		return "", false
	}
	cfg.Narrows = func(msg string) bool {
		_, ok := loops.ParseText(msg)
		return ok
	}
	cfg.HelpExtra = learningOffText
	cfg.Notes = append(cfg.Notes, func() string { return learningOffNote })
}

// attach binds the running daemon's engine and admission and starts the
// scheduler. Before it, the box reads as busy and stopped: no loop work.
func (l *learning) attach(ctx context.Context, d *daemon.Daemon) {
	eng := d.Engine()
	l.pipe.Attach(eng)
	l.sched.Attach(eng)
	l.eng.Store(eng)
	l.adm.Store(d.Admission())
	if l.routing != nil {
		go l.routing.run(ctx, 30*time.Second)
	}
	go l.sched.Run(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case o := <-l.verdicts:
				func() {
					defer func() {
						if recover() != nil {
							log.Printf("learning: owner verdict not harvested: harvester failed")
						}
					}()
					l.record(o)
				}()
			}
		}
	}()
}

// learningOn reports whether the owner has learning on: the Improve loop
// on and loops not all off. While it is off, nothing new is recorded from
// the owner (UX-101-1 on #101); texts already kept stay until their sweep.
func (l *learning) learningOn() bool { return l.sched.Settings().On(loops.Improve) }

// delivered keeps the owner's task text for harvesting (guest G16).
func (l *learning) delivered(goal, text string, public bool) {
	if l.learningOn() {
		l.tasks.put(goal, text, public)
	}
}

// record harvests an owner verdict as a Loop 1 case (loops L6).
func (l *learning) record(o grants.OwnerOutcome) {
	if l.learningOn() {
		harvestOutcome(l.cases, l.tasks, o, log.Printf)
	}
}

func (l *learning) busy() bool {
	a := l.adm.Load()
	return a == nil || a.Busy()
}

func (l *learning) stopped() bool {
	e := l.eng.Load()
	return e == nil || e.Stopped()
}

// evalConfig is the replay machine and its model route.
type evalConfig struct {
	Dir    string  // replay machines' socket directories
	Spec   vm.Spec // the replay machine: the agent's image and launch
	Egress string  // the vault process's model socket; empty: no model access
}

// openEvaluator opens the replay evaluator (LOOP-5, replay R8) over the
// machine manager and hands replay machines to it (lateServices.eval).
// Replay machines' model calls go to the vault process through the
// evaluation route, metered by the spare meter, which applies the tree's
// routing rule within the -eval-from machine's grants (egress K10).
func (l *learning) openEvaluator(m *vm.Manager, services *lateServices, c evalConfig) (*replay.Evaluator, error) {
	eng := l.eng.Load()
	if eng == nil {
		return nil, errors.New("learning plane not attached")
	}
	var ev *replay.Evaluator
	rc := replay.Config{
		Machines:   m,
		Recordings: replay.JournalRecordings{J: eng, Task: l.pipe.ProbeTask},
		Active:     l.pipe.Files,
		Spec:       c.Spec,
		Dir:        c.Dir,
		Logf:       log.Printf,
	}
	if c.Egress != "" {
		rc.Meter = l.spare
		rc.Model = replay.RuleModel(modelroute.Evaluation(modelroute.Config{
			Socket: c.Egress,
			Label:  m.DataLabel,
			Denied: evalDenied(log.Printf),
			Logf:   log.Printf,
			// ev is set before any replay machine exists: machines
			// start only through Run, after New returns.
			OverCeiling: func(id string) { ev.OverPriceCeiling(id) },
		}))
	}
	ev, err := replay.New(rc)
	if err != nil {
		return nil, err
	}
	services.eval.Store(&svc{ev})
	l.eval.e.Store(ev)
	return ev, nil
}

// evalDenied handles the vault process's refusals of replay machines'
// model calls. They are the evaluator's (a run over the price ceiling
// ends as not evaluated) and never the owner's: they stay out of the
// journal's egress records, which feed owner alerts and the digest (W3a,
// #62 L3 item 7). They are logged by fixed class only, never the
// vault process's reason text (security R1 on #90).
func evalDenied(logf func(string, ...any)) func(machine string, d modelroute.Denial) {
	return func(machine string, d modelroute.Denial) {
		if !strings.HasPrefix(machine, vm.EvalPrefix) {
			return
		}
		// The reason is the vault process's text and may quote a
		// private replay's request; only its fixed class is logged.
		class := "refused"
		if d.Reason == modelroute.ReasonEvalCeiling {
			class = "over the evaluation price ceiling"
		}
		logf("replay %s: model call %s (status %d)", machine, class, d.Status)
	}
}

// heldRouting is the routing namespace's target when agentosd has no
// routing socket to the vault process, which holds the router: an adoption
// would leave the vault process routing, and pricing evaluations, by
// another rule than the pipeline's, so none applies; Loop 1 gets no
// Router, so none is proposed either.
type heldRouting struct{}

func (heldRouting) Current() (change.Tree, error) { return change.Tree{}, nil }

func (heldRouting) Apply(t change.Tree) error {
	if len(t) != 0 {
		return errors.New("routing changes wait until agentos-egress follows them")
	}
	return nil
}

// lateEvaluator is the pipeline's evaluator until the replay evaluator
// opens; before then, and when there are no agent machines, nothing is
// evaluated and nothing adopts (change C8: no evaluation, no adoption).
type lateEvaluator struct {
	e atomic.Pointer[replay.Evaluator]
}

func (l *lateEvaluator) Run(ctx context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	e := l.e.Load()
	if e == nil {
		return nil, change.ErrNotEvaluated
	}
	return e.Run(ctx, t, p)
}

// lateReader is Loop 1's journal reader, empty until the engine runs.
type lateReader struct {
	e *atomic.Pointer[journal.Engine]
}

func (r lateReader) List() []journal.Status {
	if e := r.e.Load(); e != nil {
		return e.List()
	}
	return nil
}

func (r lateReader) Trail() []journal.Record {
	if e := r.e.Load(); e != nil {
		return e.Trail()
	}
	return nil
}

// lateQuality records the harvester's owner verdicts once the engine runs.
type lateQuality struct {
	e *atomic.Pointer[journal.Engine]
}

func (q lateQuality) RecordQuality(id string, v journal.Quality) (journal.Status, error) {
	if e := q.e.Load(); e != nil {
		return e.RecordQuality(id, v)
	}
	return journal.Status{}, errors.New("journal not open")
}

// routingClient is the vault process's routing socket (modelroute.Routing).
type routingClient interface {
	State(ctx context.Context) (modelroute.RoutingState, error)
	Set(ctx context.Context, rule routerule.Rule) error
}

// syncedRouting is the routing namespace's target over the vault
// process's routing socket (PW4 on #90). An empty routing tree is the
// owner's -rule. Current is the vault process's active rule, or, if it
// cannot be reached on first start, the owner's -rule, pushed once it can
// (potency PW6). Apply adopts a rule there, which the vault process takes
// only as a reordering of the owner's -rule. While the pipeline restores
// its state at start, a rule the vault process cannot take yet is kept
// and pushed by run. After start, an adoption the vault process does not
// take fails, so nothing is recorded as adopted that the router does not
// route by. run also keeps the router on the pipeline's active rule when
// the vault process restarts or loses it (L3 S1 on #96). A rule the vault
// process refuses there (the owner changed -rule) gives way to the owner's
// rule and stands for it from then on, so a later revert to it is not
// refused (security R1 on PW4); the owner's digest says so once (W3-route).
type syncedRouting struct {
	r      routingClient
	logf   func(string, ...any)
	active func() routerule.Rule // the pipeline's active rule; nil until it exists

	// mu is held across each call to the vault process, so a delayed push
	// never lands after a newer adoption (L3 M2 on #96).
	mu        sync.Mutex
	restoring bool
	pending   *routerule.Rule // to push once the vault process is up; empty: -rule
	refused   routerule.Rule  // a rule the vault process refused at restore or check
	applied   int             // Applies so far, so a check never pushes a rule read before one

	// note queues a digest line once per key (change.Pipeline.Notice);
	// nil until the pipeline exists. owe is a refused rule whose line is
	// not queued yet (W3-route).
	note func(key, line string) error
	owe  routerule.Rule
}

// routingStandsInText is the digest line telling the owner that their own
// model order is in use in place of an order the box learned, because
// they changed their AI settings since (W3-route; UX-108-1 on #108). Not
// urgent, so it waits for the digest (CH-15).
const routingStandsInText = "Your AI model settings changed, so the box uses your order of models. It learns a new order over time while learning is on."

// routingProjectedText replaces it when part of the learned order still
// fits the owner's new rule, so Loop 1 proposes that part (W3-route-a,
// potency PR1 on #108). One GSM-7 segment.
const routingProjectedText = "Your AI model settings changed, so the box uses your order of models. While learning is on, it will check whether its learned order still helps."

// project carries a learned order onto the owner's rule (W3-route-a): in
// each of the owner's classes, routes the learned order had keep their
// learned relative order, routes new to the owner's rule keep the owner's
// places, and routes the owner's rule dropped are gone. The result is
// always a reordering of owner, so the vault process can take it.
func project(learned, owner routerule.Rule) routerule.Rule {
	out := routerule.Rule{}
	for c, rs := range owner {
		has := map[routerule.Route]bool{}
		for _, r := range rs {
			has[r] = true
		}
		var kept []routerule.Route
		inLearned := map[routerule.Route]bool{}
		for _, r := range learned[c] {
			if has[r] && !inLearned[r] {
				kept = append(kept, r)
				inLearned[r] = true
			}
		}
		next := make([]routerule.Route, len(rs))
		k := 0
		for i, r := range rs {
			if inLearned[r] {
				next[i] = kept[k]
				k++
			} else {
				next[i] = r
			}
		}
		out[c] = next
	}
	return out
}

// projected is the projection Loop 1 proposes: only while the pipeline's
// rule is the refused one (the owner's rule stands in for it), and only
// when it differs from the owner's rule.
func projected(active, refused, owner routerule.Rule) (routerule.Rule, bool) {
	if refused == nil || len(owner) == 0 || !sameRule(active, refused) {
		return nil, false
	}
	p := project(refused, owner)
	if sameRule(p, owner) {
		return nil, false
	}
	return p, true
}

func (s *syncedRouting) Current() (change.Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := s.r.State(ctx)
	if err != nil {
		s.logf("routing: vault process not reachable at first start; recording the owner's rule")
		s.pending = &routerule.Rule{}
		return change.Tree{}, nil
	}
	b, err := json.Marshal(st.Rule)
	if err != nil {
		return nil, err
	}
	return change.Tree{change.RoutingPath: b}, nil
}

func (s *syncedRouting) Apply(t change.Tree) error {
	var rule routerule.Rule
	if len(t) != 0 {
		b, ok := t[change.RoutingPath]
		if !ok || len(t) != 1 {
			return errors.New("routing needs exactly " + change.RoutingPath)
		}
		if err := json.Unmarshal(b, &rule); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied++
	if s.refused != nil && sameRule(rule, s.refused) {
		rule = nil
	}
	err := s.set(context.Background(), rule)
	switch {
	case err == nil:
		s.pending = nil
	case s.restoring:
		s.pending = &rule
		return nil
	}
	return err
}

func (s *syncedRouting) set(ctx context.Context, rule routerule.Rule) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.r.Set(ctx, rule)
}

func (s *syncedRouting) doneRestoring() {
	s.mu.Lock()
	s.restoring = false
	s.mu.Unlock()
}

// push sends a rule kept from the start, if any; otherwise it checks that
// the vault process routes by the pipeline's active rule, and sets it if
// not. It reports whether the vault process has the rule.
func (s *syncedRouting) push(ctx context.Context) bool {
	// The pipeline's rule is read before mu: the pipeline holds its own
	// lock while it calls Apply.
	s.mu.Lock()
	gen := s.applied
	s.mu.Unlock()
	var want routerule.Rule
	if s.active != nil {
		want = s.active()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// One budget for the whole check, so mu is never held long (L3 N1).
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if s.pending != nil {
		want = *s.pending
	} else {
		if s.applied != gen || s.active == nil {
			return true // an Apply since: the next check reads its rule
		}
		st, err := s.r.State(ctx)
		if err != nil {
			return false
		}
		if len(want) == 0 || (s.refused != nil && sameRule(want, s.refused)) {
			want = st.Owner
		}
		if sameRule(st.Rule, want) {
			return true
		}
		s.logf("routing: the vault process was not routing by the adopted rule; setting it")
	}
	err := s.set(ctx, want)
	switch {
	case err == nil:
		s.pending = nil
		return true
	case errors.Is(err, modelroute.ErrRoutingRefused) && len(want) != 0:
		s.logf("routing: the adopted rule %s no longer reorders the owner's rule; using the owner's rule", ruleText(want))
		s.refused = want
		s.pending = &routerule.Rule{}
		s.owe = want
	default:
		s.logf("routing: vault process not reachable or did not keep the rule")
		if s.pending == nil {
			s.pending = &want
		}
	}
	return false
}

// check pushes as push does, then queues the owner's digest line for a
// refused rule.
func (s *syncedRouting) check(ctx context.Context) bool {
	ok := s.push(ctx)
	s.tell()
	return ok
}

// tell queues the digest line once per refused rule, keyed by the rule, so
// a restart that refuses it again adds nothing. It runs outside mu, since
// the pipeline holds its own lock while it calls Apply; a line that could
// not be queued is tried again at the next check.
func (s *syncedRouting) tell() {
	s.mu.Lock()
	owe, note := s.owe, s.note
	s.mu.Unlock()
	if owe == nil || note == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	st, err := s.r.State(ctx)
	cancel()
	if err != nil {
		return // the vault process is down: tried at the next check
	}
	text := routingStandsInText
	if _, ok := projected(owe, owe, st.Owner); ok {
		text = routingProjectedText
	}
	if err := note("routing-refused:"+ruleText(owe), text); err != nil {
		s.logf("routing: the owner's digest line was not queued: %v", err)
		return
	}
	s.mu.Lock()
	if sameRule(s.owe, owe) {
		s.owe = nil
	}
	s.mu.Unlock()
}

// run keeps the vault process on the pipeline's rule: it pushes the rule
// kept from the start, then checks every period.
func (s *syncedRouting) run(ctx context.Context, every time.Duration) {
	for {
		s.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// ruleText is a rule as logged: provider and model names only.
func ruleText(r routerule.Rule) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func sameRule(a, b routerule.Rule) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// routerOf is Loop 1's router (ADP-4): the vault process's measured
// proposal. While the owner's rule stands in for a refused learned rule
// and the router has measured nothing new, the proposal is the learned
// order projected onto the owner's rule (W3-route-a). If the vault
// process cannot be reached, or proposes the rule it already routes by,
// the proposal is the pipeline's own active rule, so nothing is proposed.
type routerOf struct {
	s    *syncedRouting
	pipe *change.Pipeline
}

func (r routerOf) state() (modelroute.RoutingState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.s.r.State(ctx)
}

func (r routerOf) active() routerule.Rule {
	var rule routerule.Rule
	_ = json.Unmarshal(r.pipe.Files("routing")[change.RoutingPath], &rule)
	return rule
}

func (r routerOf) Rule() routerule.Rule {
	if st, err := r.state(); err == nil {
		return st.Rule
	}
	return r.active()
}

// SetRule goes through the routing target, as the pipeline's own
// adoptions do.
func (r routerOf) SetRule(rule routerule.Rule) error {
	b, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	return r.s.Apply(change.Tree{change.RoutingPath: b})
}

func (r routerOf) Candidate() routerule.Rule {
	st, err := r.state()
	if err != nil {
		return r.active()
	}
	if len(st.Candidate) > 0 && !sameRule(st.Candidate, st.Rule) {
		return st.Candidate
	}
	// Until the router measures the owner's new rule, a refused learned
	// order is proposed as projected onto it (W3-route-a).
	active := r.active()
	if p, ok := projected(active, r.s.refusedRule(), st.Owner); ok {
		return p
	}
	return active
}

func (s *syncedRouting) refusedRule() routerule.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}
