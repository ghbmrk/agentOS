package main

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/replay"
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
	eval    lateEvaluator
	eng     atomic.Pointer[journal.Engine]
	adm     atomic.Pointer[admission.Controller]
}

// learnPaths are where the learning plane keeps its state.
type learnPaths struct {
	Dir   string // pipeline, scheduler, and harvest state
	Spare string // the spare meter (LOOP-2), apart from the guests' OP-8 meter
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
	if l.pipe, err = change.New(change.Config{
		Store:     change.FileStore{Path: filepath.Join(p.Dir, "change.json")},
		Evaluator: &l.eval,
		Targets:   map[string]change.Target{"routing": heldRouting{}},
	}); err != nil {
		return nil, err
	}
	l.harvest = &loops.Harvester{J: lateQuality{&l.eng}, Pipeline: l.pipe, Store: change.FileStore{Path: filepath.Join(p.Dir, "harvest.json")}}
	learn, err := loops.NewLearn(loops.LearnConfig{
		Pipeline:   l.pipe,
		Journal:    lateReader{&l.eng},
		Harvest:    l.harvest,
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
	return l, nil
}

// learningOffText answers loop settings and ends HELP when the learning
// plane could not start (L3 S3 on #90). It names everything the loop texts
// cover, and a restart retries opening the plane (UX-92-1).
const learningOffText = "Spare-time work (learning, self-tests, update checks) is not running on this box. Restarting the box may fix it."

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
}

// attach binds the running daemon's engine and admission and starts the
// scheduler. Before it, the box reads as busy and stopped: no loop work.
func (l *learning) attach(ctx context.Context, d *daemon.Daemon) {
	eng := d.Engine()
	l.pipe.Attach(eng)
	l.sched.Attach(eng)
	l.eng.Store(eng)
	l.adm.Store(d.Admission())
	go l.sched.Run(ctx)
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

// heldRouting is the routing namespace's target until agentos-egress,
// which holds the router, follows routing adoptions (its -rule is read at
// start). Until then an adoption would leave the vault process routing,
// and pricing evaluations, by another rule than the pipeline's, so none
// applies; Loop 1 gets no Router, so none is proposed either.
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
