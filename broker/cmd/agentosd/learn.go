package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
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
	// sleep is the agent sleeper on a box where the agent and a replay
	// machine do not fit together (PE7); nil elsewhere.
	sleep   atomic.Pointer[sleeper]
	eng     atomic.Pointer[journal.Engine]
	adm     atomic.Pointer[admission.Controller]
	routing *syncedRouting // nil: routing held
	tasks   *taskTexts     // the owner's task texts, for harvesting
	// builder is Loop 1's: the skill compiler for repeated trajectories,
	// in-process since it calls no model (W3 step 3a).
	builder loops.BySignal
	// build is the model-backed builder for every other signal, in its
	// own private machine (W3-builder), once the machine plane attaches it.
	build lateBuild
	learn *loops.Learn
	// guard is Loop 2's passive checks (W5a, loop2.go); contain and
	// notify reach the gate and the owner once the daemon attaches.
	guard *loops.Guard
	// running counts the scheduler's run, so a test can wait for it.
	running sync.WaitGroup
	contain loop2Contain
	notify  loop2Notify
	// forgetOwner is the owner's FORGET (W3-forget, forget.go).
	forgetOwner *ownerForget
	// values are the guest's task values, for the compiler only
	// (W3-values); mining is the journal everything else in Loop 1 reads,
	// which keeps none (security V3).
	values *taskValues
	mining lateReader
	// forgotten tombstones the goals the owner forgot (security F1 on
	// #123): mining skips their intents, and nothing is kept for them
	// again.
	forgotten *forgotten
	observed  chan journal.Intent
	// verdicts queues the gate's owner verdicts for harvesting, so a slow
	// learning plane never holds the gate (security A2 on PW3).
	verdicts chan grants.OwnerOutcome
	// noRoom is set when replay evaluation was not opened because the
	// agent machine and one replay machine do not fit in memory (PE2).
	noRoom atomic.Bool
	// builderOff is set when -builder-image was given but the builder
	// did not start (UX-126-1).
	builderOff atomic.Bool
	// builderUnset is set when no -builder-image was given (potency R3 on
	// #126).
	builderUnset atomic.Bool
}

// learnPaths are where the learning plane keeps its state.
type learnPaths struct {
	Dir   string // pipeline, scheduler, and harvest state
	Spare string // the spare meter (LOOP-2), apart from the guests' OP-8 meter
	// Routing is the vault process's routing socket, through which the
	// pipeline reads and adopts the active routing rule (PW4 on #90).
	// Empty holds routing changes (heldRouting).
	Routing string
	// Tree, if set, is the live agent's copy of the tree's procedures,
	// skills and context (W4); nil holds them in the pipeline.
	Tree *liveTree
	// ResumeFor is how long a preempted evaluation's pairs and candidates
	// are kept; zero is change.ResumeFor (sleepResumeFor).
	ResumeFor time.Duration
}

// openLearning opens the learning plane and wires it into the daemon's
// configuration: the gate's Changes and Loops policies, their executors,
// and the owner's settings texts.
func openLearning(p learnPaths, modelWired bool, cfg *daemon.Config) (*learning, error) {
	restored, err := readRestoredForgets(p.Dir)
	if err != nil {
		return nil, err
	}
	l := &learning{}
	l.eval.sleep = &l.sleep
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
	targets := map[string]change.Target{"routing": target}
	if p.Tree != nil {
		for ns, t := range p.Tree.targets() {
			targets[ns] = t
		}
	}
	if l.pipe, err = change.New(change.Config{
		Store:     change.FileStore{Path: filepath.Join(p.Dir, "change.json")},
		Evaluator: &l.eval,
		Targets:   targets,
		ResumeFor: p.ResumeFor,
		Logf:      log.Printf,
	}); err != nil {
		return nil, err
	}
	var router change.Router
	if sync != nil {
		sync.doneRestoring()
		pipe := l.pipe
		sync.active = func() routerule.Rule { return routerOf{pipe: pipe}.active() }
		sync.wire(pipe, filepath.Join(p.Dir, "routing-learned.json"))
		l.routing = sync
		router = routerOf{sync, l.pipe}
	}
	l.harvest = &loops.Harvester{J: lateQuality{&l.eng}, Pipeline: l.pipe, Store: change.FileStore{Path: filepath.Join(p.Dir, "harvest.json")}}
	if l.tasks, err = openTaskTexts(change.FileStore{Path: filepath.Join(p.Dir, "tasks.json")}, time.Now, log.Printf); err != nil {
		return nil, err
	}
	// The compiler reads values from the journal, which keeps none while
	// the daemon redacts all free text: a trajectory holding the mark is
	// never compiled, so it builds nothing until the journal keeps values
	// (W3 step 3b).
	if l.values, err = openTaskValues(change.FileStore{Path: filepath.Join(p.Dir, "values.json")}, filepath.Join(p.Dir, "values.key"), time.Now, log.Printf); err != nil {
		return nil, err
	}
	if l.forgotten, err = openForgotten(change.FileStore{Path: filepath.Join(p.Dir, "forgotten.json")}, time.Now); err != nil {
		return nil, err
	}
	for _, e := range restored {
		if !l.forgotten.has(e.Goal) {
			if err := l.forgotten.add(e.Goal); err != nil {
				return nil, err
			}
		}
	}
	l.mining = lateReader{&l.eng, l.forgotten}
	if l.builder, err = skillBuilder(l.mining, l.values, l.pipe); err != nil {
		return nil, err
	}
	for _, sig := range []loops.Signal{loops.SignalFailure, loops.SignalCorrection, loops.SignalSlow, loops.SignalExpensive} {
		l.builder[sig] = &l.build
	}
	learn, err := loops.NewLearn(loops.LearnConfig{
		Pipeline:   l.pipe,
		Journal:    l.mining,
		Harvest:    l.harvest,
		Builder:    l.builder,
		Router:     router,
		ModelWired: modelWired,
		ResumeFor:  p.ResumeFor,
	})
	if err != nil {
		return nil, err
	}
	l.learn = learn
	if l.guard, err = loops.NewGuard(loops.GuardConfig{
		Pipeline:  l.pipe,
		Store:     change.FileStore{Path: filepath.Join(p.Dir, "loop2.json")},
		Contain:   &l.contain,
		NotRun:    loop2NotRun,
		Notify:    l.notify.send,
		ResumeFor: p.ResumeFor,
	}); err != nil {
		return nil, err
	}
	if l.sched, err = loops.New(loops.Config{
		Store:     change.FileStore{Path: filepath.Join(p.Dir, "loops.json")},
		Spare:     spare,
		Sources:   []loops.Source{sleepSource{learn, &l.sleep}, l.guard},
		Sharing:   l.pipe.SetSharing,
		Busy:      l.busy,
		BusyCause: l.busyCause,
		Stopped:   l.stopped,
		Logf:      log.Printf,
	}); err != nil {
		return nil, err
	}
	l.harvest.Wake = l.sched.Wake
	l.cases = l.harvest
	if err := l.replayForgotten(); err != nil {
		return nil, err
	}
	if p.Tree != nil {
		p.Tree.markReady() // the pipeline applied its state, if it had any
	}
	// Evaluation keeps its reserve of the spare budget while Loop 1
	// evaluates (loops L3); builder machines take at most their Max of it
	// (C-3c-5). The clean room takes its Max here once it exists.
	if err := spare.SetShares([]meter.Share{l.sched.EvalShare(), builderShare()}); err != nil {
		return nil, err
	}
	cfg.Grants.Changes = l.pipe
	cfg.Grants.Loops = l.sched
	if cfg.BrokerExecutors == nil {
		cfg.BrokerExecutors = map[string]journal.Executor{}
	}
	cfg.BrokerExecutors[change.Executor] = l.pipe
	cfg.BrokerExecutors[loops.Executor] = l.sched
	l.forgetOwner = &ownerForget{tasks: l.tasks, learned: l.pipe.LearnedFrom, forget: l.forgetTask, forgotten: l.forgotten.has,
		inform: func(s string) { l.notify.send(s, false) }, tell: l.notify.try, now: time.Now, loc: time.Local, sleep: sleepCtx}
	// The done texts the last boot owed (W3-forget-b3): the replay above
	// has finished each tombstoned one, and attach texts them once the
	// owner channel is up. An owed file that does not read is started
	// afresh; its texts are lost, not its forgets.
	owedStore := change.FileStore{Path: filepath.Join(p.Dir, "forget-owed.json")}
	owed, err := openForgetOwed(owedStore)
	if err != nil {
		// Kept aside, not read again, and the owner told (L3 B2 on #425).
		if rerr := os.Rename(owedStore.Path, owedStore.Path+".bad"); rerr != nil {
			log.Printf("forget: unreadable owed file not kept aside: %v", rerr)
		}
		log.Printf("forget: owed done texts lost, kept aside as %s.bad: %v", owedStore.Path, err)
		owed = lostForgetOwed(owedStore)
	}
	l.forgetOwner.owed = owed
	l.forgetOwner.owedAtStart = owed.goals()
	for _, e := range restored {
		if e.Agent {
			l.forgetOwner.restored = append(l.forgetOwner.restored, e.Since)
		}
	}
	cfg.BrokerExecutors[grants.ForgetExecutor] = l.forgetOwner
	cfg.Grants.ForgetItem = l.forgetOwner.Item
	cfg.Grants.ForgetAgentItem = l.forgetOwner.AgentItem
	cfg.Settings = l.settings
	cfg.Notes = append(cfg.Notes, l.note, l.builderNote, l.guard.Status)
	cfg.Narrows = l.sched.Narrows
	cfg.HelpExtra = loops.HelpLine
	// The owner's verdicts on the agent's effects become Loop 1's cases
	// (loops L6; potency PW3 on #90). Set last, once nothing
	// can fail, so a plane that did not open has no hook (security F1).
	// The guest's task values reach the compiler from the gate, as the
	// guest wrote them, only while learning is on (W3-values; security
	// V1, UX-S3-2); a full queue drops, never holds the gate.
	l.observed = make(chan journal.Intent, maxObserved)
	cfg.Grants.Observe = func(in journal.Intent) {
		if !strings.HasPrefix(in.Origin, "guest:") || !l.learningOn() {
			return
		}
		select {
		case l.observed <- in:
		default:
			log.Printf("learning: task values not kept: queue full")
		}
	}
	// Loop 2 lists a grant it paused until the owner resumes or revokes
	// it (loops S4).
	guard := l.guard
	cfg.Grants.Unpaused = func(id string) {
		if err := guard.Resumed(loops.Target{Kind: "grant", Name: id}); err != nil {
			log.Printf("loop2: a resumed grant stays listed: %v", err)
		}
	}
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

// vaultPlaceholder is the vault redactor's mark for a secret
// (vault.Placeholder; agentosd does not link the vault).
const vaultPlaceholder = "[REDACTED]"

// journalRedacted reports a journal value a redactor wrote: the daemon's
// mark for any free text or the vault's for a secret (security C-3a-1;
// compile reads the journal's clip mark itself).
func journalRedacted(v string) bool {
	return strings.Contains(v, daemon.Redacted) || strings.Contains(v, vaultPlaceholder)
}

// noRoomNote is STATUS's line when replay evaluation was not opened for
// lack of memory (PE2; UX-114-1, potency C1 on #114). It follows the time
// check's note.
const noRoomNote = "Learning: paused, the box's memory is too small to test changes."

// noRoomOn is what turning learning back on adds then.
const noRoomOn = "Learning is on, but the box's memory is too small to test changes, so nothing new will be adopted."

func (l *learning) note() string {
	if l.noRoom.Load() {
		if l.sleep.Load() != nil {
			return sleepModeNote
		}
		return noRoomNote
	}
	return ""
}

// settings answers the owner's loop settings (loops Scheduler.Text). While
// there is no room for replay, a LEARNING ON or LOOPS ON that took effect
// says nothing new will be adopted, keeping the "if this wasn't you" line
// (security C1 on #49).
func (l *learning) settings(ctx context.Context, msg string, unlocked bool) (string, bool) {
	if _, ok := parseForget(msg); ok {
		return l.forgetOwner.Text(ctx, msg, unlocked)
	}
	reply, ok := l.sched.Text(ctx, msg, unlocked)
	r, _ := loops.ParseText(msg)
	if !ok || !l.noRoom.Load() || l.sleep.Load() != nil || r.Kind != loops.KindLoops || !r.On || (r.Loop != "" && r.Loop != loops.Improve) ||
		reply != loops.Confirm(r, l.sched.Settings()) {
		return reply, ok
	}
	if r.Loop == "" {
		return "Spare-time work is back on. " + noRoomOn + " Reply LOOPS OFF if this wasn't you.", true
	}
	return noRoomOn + " Reply LEARNING OFF if this wasn't you.", true
}

// learningOffText answers loop settings and ends HELP when the learning
// plane could not start (L3 S3 on #90). It names everything the loop texts
// cover, and a restart retries opening the plane (UX-92-1).
const learningOffText = "Spare-time work (learning, self-tests, update checks) is not running on this box. Restarting the box may fix it."

// forgetOffText answers FORGET when the learning plane could not start.
const forgetOffText = "I can't forget tasks right now: learning isn't running. Restarting the box may fix it."

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
		if _, ok := parseForget(msg); ok {
			// Never task chat for the agent (W3-forget).
			return forgetOffText, true
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

// forgetTask deletes what the learning plane keeps of one task: its text,
// its values, the Loop 1 cases harvested from it and the harvester's
// records of them (W3-tasks part 1, CAP-3), and the cascade (W3-tasks part
// 2, security C1 on #120): Loop 1's kept candidates built from it, and
// every adoption learned from it, undone with its files cleared from the
// pipeline's history (change C23). Only an authenticated owner forget may
// call it: the owner's approved FORGET (forget.go).
func (l *learning) forgetTask(goal string) error {
	if goal == "" {
		return errors.New("learning: forget needs a goal")
	}
	// Each store forgets even when another's save failed; any failure is
	// returned, so a forget is never reported done while data is at rest.
	// The tombstone first: once it holds, nothing keeps the goal again,
	// even if a deletion below fails.
	// If the tombstone did not save, nothing else is deleted: the owner is
	// told the task was not forgotten, and it stays listed for another
	// FORGET, also after a restart (security R1 on #182). The goal stays
	// tombstoned in memory until then, so nothing is learned from it.
	if err := l.forgotten.add(goal); err != nil {
		return fmt.Errorf("%w: %v", errNotTombstoned, err)
	}
	return l.forgetStores(goal)
}

// errNotTombstoned: a forget's tombstone did not save, so nothing of the
// task was deleted.
var errNotTombstoned = errors.New("learning: the forget was not saved")

// forgetStores deletes one forgotten goal from every learning store, each
// even when another's save failed. Each step is idempotent, and one that
// finds nothing saves nothing.
func (l *learning) forgetStores(goal string) error {
	_, terr := l.tasks.forget(goal)
	_, verr := l.values.forget(goal)
	l.learn.ForgetGoal(goal)
	ids, cerr := l.pipe.ForgetGoal(goal)
	herr := l.harvest.ForgetCases(ids)
	return errors.Join(terr, verr, cerr, herr)
}

// replayForgotten runs every tombstoned goal's forget again when the
// learning plane opens (L3 MUST-2 on #160). A forget writes the live tree
// before it saves the pipeline, the other stores save one by one, and the
// in-flight refusals are kept in memory only, so a crash midway would
// bring forgotten files back and let a candidate from the goal be
// adopted. It runs before the tree is marked ready, so on a failure the
// agent never gets the tree and learning stays off until a start
// succeeds.
func (l *learning) replayForgotten() error {
	var errs []error
	for _, g := range l.forgotten.goals() {
		errs = append(errs, l.forgetStores(g))
	}
	return errors.Join(errs...)
}

// forgetLogFile is the restored copy of the forget log in the learning
// plane's directory, which broker/recovery writes once the log's check
// passes (Layout.ForgetLog); its PendingSuffix marker says the check held
// the restore (W3-forget-b1; security C3).
const forgetLogFile = "forget-log.json"

// restoredForget is the part of a forget log entry the replay needs; the
// log was authenticated by the restore, which holds the vault key.
type restoredForget struct {
	Goal  string    `json:"goal"`
	Since time.Time `json:"since"`
	Agent bool      `json:"agent"`
}

// restoreHold refuses agentosd's start while dir holds the marker of a
// restore the forget log's check held: its error carries the owner's
// notice (recovery.PendingNotice, the marker's second line) and the
// reason. A marker that does not read holds the start too.
func restoreHold(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, forgetLogFile+".pending"))
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("agentosd: restore on hold: %v", err)
	}
	reason, notice, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if notice == "" {
		notice = "Restore on hold."
	}
	return fmt.Errorf("agentosd: not starting: %s (%s)", strings.TrimSpace(notice), strings.TrimSpace(reason))
}

// readRestoredForgets reads the restored forget log in dir, if any. A
// restore the log's check held, or a copy that does not read, keeps the
// learning plane closed (CAP-3 across a restore); restoreHold keeps
// agentosd from starting at all on the held one.
func readRestoredForgets(dir string) ([]restoredForget, error) {
	path := filepath.Join(dir, forgetLogFile)
	if b, err := os.ReadFile(path + ".pending"); err == nil {
		return nil, fmt.Errorf("learning: restore pending: %s", strings.TrimSpace(string(b)))
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("learning: restore pending: %v", err)
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("learning: forget log: %v", err)
	}
	var fl struct {
		Entries []restoredForget `json:"entries"`
	}
	if err := json.Unmarshal(b, &fl); err != nil {
		return nil, fmt.Errorf("learning: forget log: %v", err)
	}
	for _, e := range fl.Entries {
		if e.Goal == "" {
			return nil, errors.New("learning: forget log: an entry has no goal")
		}
	}
	return fl.Entries, nil
}

// ForgetTasks is recall's deletion reach into the learning plane
// (recalltool Cases; CAP-3, change C19): for intents it erases, the
// harvester's tombstone first, so none is harvested again and none counts
// as evidence, then the pipeline's task cases and the values kept for
// them. One method, so the parts cannot be wired apart (security F1 on
// #59). Idempotent; every part runs even when another fails.
func (l *learning) ForgetTasks(ids ...string) (int, error) {
	herr := l.harvest.ForgetIntents(ids)
	n, cerr := l.pipe.ForgetTasks(ids...)
	var verr error
	if l.values != nil {
		verr = l.values.forgetSteps(ids)
	}
	return n, errors.Join(herr, cerr, verr)
}

// attach binds the running daemon's engine and admission and starts the
// scheduler. Before it, the box reads as busy and stopped: no loop work.
func (l *learning) attach(ctx context.Context, d *daemon.Daemon) {
	eng := d.Engine()
	l.pipe.Attach(eng)
	l.sched.Attach(eng)
	if g := d.Gate(); g != nil {
		l.contain.gate.Store(&pauseGateBox{g})
		l.forgetOwner.gate.Store(&pauseGateBox{g})
		// The gate has replayed its journal: Loop 2 drops any pause that
		// ended while it could not hear it (L3 S1 on #169). This runs
		// before sched.Run below, so no pass sees the stale list.
		if err := l.guard.Reconcile(loop2Held(g.Grants())); err != nil {
			log.Printf("loop2: an ended pause stays listed: %v", err)
		}
	}
	l.notify.ch.Store(d.Owner())
	l.forgetOwner.finishOwed(ctx)
	l.eng.Store(eng)
	l.adm.Store(d.Admission())
	if l.routing != nil {
		go l.routing.run(ctx, 30*time.Second)
	}
	l.running.Add(1)
	go func() {
		defer l.running.Done()
		l.sched.Run(ctx)
	}()
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
			case in := <-l.observed:
				l.observeIntent(in)
			}
		}
	}()
}

// observeIntent keeps a guest intent's values, unless learning is off
// (again: it may have been turned off while queued, UX-S3-2) or its goal
// was forgotten.
func (l *learning) observeIntent(in journal.Intent) {
	if l.learningOn() && !l.forgotten.has(in.GoalID) {
		l.values.observe(in)
	}
}

// learningOn reports whether the owner has learning on: the Improve loop
// on and loops not all off. While it is off, nothing new is recorded from
// the owner (UX-101-1 on #101); texts already kept stay until their sweep.
func (l *learning) learningOn() bool { return l.sched.Settings().On(loops.Improve) }

// delivered keeps the owner's task text for harvesting (guest G16).
func (l *learning) delivered(goal, text string, public bool) {
	if l.learningOn() && !l.forgotten.has(goal) {
		// Task chat reaches the agent only from the owner channel, whose
		// transport is the box's SIM.
		l.tasks.put(goal, text, public, viaSMS)
	}
}

// record harvests an owner verdict as a Loop 1 case (loops L6). The goal's
// task values follow the verdict whether learning is on or not, so a NO
// drops them.
func (l *learning) record(o grants.OwnerOutcome) {
	l.values.verdict(o)
	if l.learningOn() && !l.forgotten.has(o.Intent.GoalID) {
		harvestOutcome(l.cases, l.tasks, o, log.Printf)
	}
}

func (l *learning) busy() bool {
	if sl := l.sleep.Load(); sl != nil && sl.keepsAwake() {
		return true
	}
	a := l.adm.Load()
	return a == nil || a.Busy()
}

// busyCause is admission's BusyCause for the scheduler (PE5). Before the
// daemon attaches, the box reads as busy under pressure, so a cut then
// counts.
func (l *learning) busyCause() (busy, owner, pressure bool) {
	a := l.adm.Load()
	if a == nil {
		return true, false, true
	}
	busy, owner, pressure = a.BusyCause()
	if sl := l.sleep.Load(); sl != nil && sl.keepsAwake() {
		// The agent is awake for the owner (PE7 condition 7); pressure
		// still wins.
		return true, true, pressure
	}
	return busy, owner, pressure
}

// revokedForOwner is admission's RevokedForOwner for the replay evaluator
// (PE5): before the daemon attaches there is no record, so a revoke
// counts.
func (l *learning) revokedForOwner(id string) bool {
	a := l.adm.Load()
	return a != nil && a.RevokedForOwner(id)
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
		// A revoke is the owner's only as admission recorded it (PE5).
		RevokedForOwner: l.revokedForOwner,
		Logf:            log.Printf,
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
	// sleep, if set, guards each run while the agent sleeps (PE7).
	sleep *atomic.Pointer[sleeper]
}

func (l *lateEvaluator) Run(ctx context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	e := l.e.Load()
	if e == nil {
		return nil, change.ErrNotEvaluated
	}
	var sl *sleeper
	if l.sleep != nil {
		sl = l.sleep.Load()
	}
	return sleepGuard(ctx, sl, func(ctx context.Context) ([]byte, error) { return e.Run(ctx, t, p) })
}

// lateReader is Loop 1's journal reader, empty until the engine runs.
type lateReader struct {
	e    *atomic.Pointer[journal.Engine]
	gone *forgotten // goals whose intents it skips (forgotten.go)
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

func (q lateQuality) Get(id string) (journal.Status, error) {
	if e := q.e.Load(); e != nil {
		return e.Get(id)
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

	// supersede records the owner's rule as the pipeline's routing state
	// when it still holds was, and reports whether the pipeline now holds
	// the owner's rule (change.Pipeline.Superseded); nil until the
	// pipeline exists. learned is the refused order Loop 1 proposes
	// projected onto the owner's rule, kept in learnedStore so a restart
	// still proposes it, until the pipeline adopts anything (W3-route-a).
	supersede    func(was routerule.Rule) (bool, error)
	learned      routerule.Rule
	learnedStore change.Store
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
			if inLearned[r] && k < len(kept) {
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

// projected is the projection Loop 1 proposes: only while the pipeline
// records the owner's rule (an empty active rule) after a learned order
// was refused, and only when it differs from the owner's rule.
func projected(active, learned, owner routerule.Rule) (routerule.Rule, bool) {
	if learned == nil || len(owner) == 0 || len(active) != 0 {
		return nil, false
	}
	for _, rs := range owner {
		seen := map[routerule.Route]bool{}
		for _, r := range rs {
			if seen[r] {
				return nil, false // not a rule the vault process takes (security R1 on #110)
			}
			seen[r] = true
		}
	}
	p := project(learned, owner)
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
	owe, note, supersede, learned := s.owe, s.note, s.supersede, s.learned
	s.mu.Unlock()
	if owe == nil {
		// Once the pipeline adopts anything, the learned order is done.
		if learned != nil && s.active != nil && len(s.active()) != 0 {
			s.setLearned(nil)
		}
		return
	}
	if note == nil || supersede == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	st, err := s.r.State(ctx)
	cancel()
	if err != nil {
		return // the vault process is down: tried at the next check
	}
	// The pipeline records the owner's rule from now on, so the next
	// evaluation's base is what the router runs (L3 MUST-1 on #110).
	owners, err := supersede(owe)
	if err != nil {
		s.logf("routing: the owner's rule was not recorded: %v", err)
		return
	}
	text := routingStandsInText
	if owners {
		s.setLearned(owe)
		if _, ok := projected(nil, owe, st.Owner); ok {
			text = routingProjectedText
		}
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
	if p, ok := projected(active, r.s.learnedRule(), st.Owner); ok {
		return p
	}
	return active
}

// wire binds the routing target to its pipeline: the owner's digest
// line, the owner's rule recorded on a refusal, and the learned order kept
// at learnedPath.
func (s *syncedRouting) wire(pipe *change.Pipeline, learnedPath string) {
	s.note = pipe.Notice
	s.supersede = func(was routerule.Rule) (bool, error) {
		files := pipe.Files("routing")
		if len(files) != 0 && sameRule(routerOf{pipe: pipe}.active(), was) {
			if _, err := pipe.Superseded("routing", files); err != nil {
				return false, err
			}
		}
		return len(pipe.Files("routing")) == 0, nil
	}
	s.learnedStore = change.FileStore{Path: learnedPath}
	if b, err := s.learnedStore.Load(); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &s.learned)
	}
}

func (s *syncedRouting) learnedRule() routerule.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.learned
}

// setLearned keeps the order to project, or nil once the pipeline has
// adopted anything since; a failed save keeps it in memory only.
func (s *syncedRouting) setLearned(r routerule.Rule) {
	s.mu.Lock()
	s.learned = r
	store := s.learnedStore
	s.mu.Unlock()
	if store == nil {
		return
	}
	var b []byte
	if r != nil {
		b, _ = json.Marshal(r)
	}
	if err := store.Save(b); err != nil {
		s.logf("routing: could not keep the learned order: %v", err)
	}
}
