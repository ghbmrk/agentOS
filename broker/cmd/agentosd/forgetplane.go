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
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// forgetPlane is what agentosd keeps of the old learning plane (W3) once
// the learning loop is deleted (MIG-4-untrusted-learn; SPEC HLD-4: a
// learning mechanism no v1.0 SPEC ID needs is deleted, not ported): the
// owner's FORGET (forget.go) over the task texts it lists, with its
// tombstones, owed done texts and restored forget log. The change
// pipeline, the loop scheduler, Loop 1, Loop 2's guard, LOOP-7 fuzz, the
// builder, the compiler's task values, routing sync and the spare meter
// are gone, so a forget has only the task text left to delete. #2781
// moves FORGET onto the kernel log.
type forgetPlane struct {
	tasks *taskTexts // the owner's task texts, which FORGET lists
	// forgotten tombstones the goals the owner forgot (security F1 on
	// #123): no task text is kept for them again.
	forgotten   *forgotten
	notify      ownerNotify
	forgetOwner *ownerForget
	// notErased: some old learning state or a crash-left temp did not
	// remove at this start (LOG-4: erase fails closed, owner told).
	notErased bool
}

// learnedFiles are the learning loop's state in the learn directory. The
// plane that wrote them is deleted, so FORGET can no longer reach a goal
// in them: they are removed when the forget plane opens, so nothing of a
// task stays at rest that the owner cannot forget (CAP-3). The directories
// are the pipeline's bodies (change.FileStore.Bodies).
var learnedFiles = []string{"change.json", "change.json.d", "harvest.json", "values.json",
	"loops.json", "loop2.json", "routing-learned.json"}

// learnTemp is durable.TempPrefix: durable.WriteFile's temp files carry
// it, and a crash between write and rename leaves one behind. It is
// spelled here, not imported, so agentosd's imports of the old core do
// not grow (trace.py --ratchet).
const learnTemp = ".durable-"

// sweepLearnTemp removes every learnTemp file in dir, as
// durable.SweepTemp does: one that will not go does not shield the rest.
func sweepLearnTemp(dir string) error {
	names, err := filepath.Glob(filepath.Join(dir, learnTemp+"*"))
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		if err := os.Remove(n); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sweepTemp and removeAll are removeLearned's, swapped by tests.
var (
	sweepTemp = sweepLearnTemp
	removeAll = os.RemoveAll
)

// removeLearned removes learnedFiles and the temps a crash left in dir
// (durable.WriteFile's, learnTemp, which may hold a copy of harvest.json or
// values.json and so task text; security 1 on #2801). Nothing else writes
// to dir yet. A file it cannot remove is logged by name only and tried
// again at the next start; it reports whether all went, so STATUS can
// tell the owner (LOG-4).
func removeLearned(dir string) bool {
	ok := true
	if err := sweepTemp(dir); err != nil {
		log.Printf("forget: crash-left temp files not removed: %v", err)
		ok = false
	}
	for _, name := range learnedFiles {
		if err := removeAll(filepath.Join(dir, name)); err != nil {
			log.Printf("forget: old learning state %s not removed: %v", name, err)
			ok = false
		}
	}
	return ok
}

// erasedNote is STATUS's line while old learning state is left at rest.
func (l *forgetPlane) erasedNote() string { return lineIf(l.notErased, forgetNotErased) }

// openForgetPlane opens the forget plane in dir and wires the owner's
// FORGET and settings texts into the daemon's configuration.
func openForgetPlane(dir string, cfg *daemon.Config) (*forgetPlane, error) {
	restored, err := readRestoredForgets(dir)
	if err != nil {
		return nil, err
	}
	l := &forgetPlane{notErased: !removeLearned(dir)}
	if l.tasks, err = openTaskTexts(change.FileStore{Path: filepath.Join(dir, "tasks.json")}, time.Now, log.Printf); err != nil {
		return nil, err
	}
	if l.forgotten, err = openForgotten(change.FileStore{Path: filepath.Join(dir, "forgotten.json")}, time.Now); err != nil {
		return nil, err
	}
	// The done texts the last boot owed (W3-forget-b3), opened before the
	// restored forgets are tombstoned so a restore can owe one. An owed
	// file that does not read is started afresh; its texts are lost, not
	// its forgets.
	owedPath := filepath.Join(dir, "forget-owed.json")
	owed := openOwedFile(change.FileStore{Path: owedPath}, owedPath)
	told := toldDone(restored)
	for _, e := range restored {
		if e.Done || l.forgotten.has(e.Goal) {
			continue // a done marker is not a forget
		}
		o, isOwed := owed.get(e.Goal)
		switch {
		case told[e.Goal]:
			// Its done text was sent after the backup was taken: owed no
			// second one, whether the restore would owe it or the restored
			// learn dir does (W3-forget-b2c-f1-r2 R2B).
			if isOwed && !o.Agent {
				if err := owed.drop(e.Goal); err != nil {
					log.Printf("forget: restored forget's told done text not cleared: %v", err)
				}
			}
		case !isOwed && !e.Agent && e.Since.IsZero():
			// An item 1 forget logged while it still retried (no agent, no
			// since) may hold the owner's forgetNotSaved, a promise the
			// restored learn dir does not keep: it is owed again before its
			// tombstone, as Execute owes it (W3-forget-b2c-f1-r1 R1A;
			// ASSUMPTIONS R5).
			if err := owed.owe(e.Goal, owedForget{Logged: true}); err != nil {
				log.Printf("forget: restored forget's done text not kept: %v", err)
			}
		}
		if err := l.forgotten.add(e.Goal); err != nil {
			return nil, err
		}
	}
	if err := l.replayForgotten(); err != nil {
		return nil, err
	}
	if cfg.BrokerExecutors == nil {
		cfg.BrokerExecutors = map[string]journal.Executor{}
	}
	// No learned change is left for a forget to undo, so the count FORGET
	// reports is always none.
	l.forgetOwner = &ownerForget{tasks: l.tasks, learned: func(string) int { return 0 }, forget: l.forgetTask, forgotten: l.forgotten.has,
		inform: l.notify.send, tell: l.notify.try, now: time.Now, loc: time.Local, sleep: sleepCtx}
	// The replay above has finished each owed tombstoned forget, and
	// attach texts them once the owner channel is up.
	l.forgetOwner.owed = owed
	l.forgetOwner.owedAtStart = owed.goals()
	for _, e := range restored {
		if e.Done {
			continue
		}
		if e.Agent {
			l.forgetOwner.restored = append(l.forgetOwner.restored, e.Since)
		}
	}
	cfg.BrokerExecutors[grants.ForgetExecutor] = l.forgetOwner
	cfg.Grants.ForgetItem = l.forgetOwner.Item
	cfg.Grants.ForgetAgentItem = l.forgetOwner.AgentItem
	wireSettings(cfg, l.forgetOwner)
	cfg.Notes = append(cfg.Notes, l.forgetOwner.Note, l.forgetOwner.RetryNote, l.erasedNote)
	return l, nil
}

// loopsOffText answers the owner's loop settings texts (LOOPS, LEARNING,
// SECURITY TESTS or UPDATE CHECKS OFF/ON, SPARE BUDGET, HELP LOOPS and
// the rest of loops.ParseText, the UPDATES texts among them): the box
// runs no spare-time work in this version (MIG-4-untrusted-learn; HLD-4),
// and an owner who had LEARNING OFF learns that task texts are now kept
// for FORGET's list (NL-4; security 2 on #2801).
const loopsOffText = "I don't do spare-time work (learning, self-tests, update checks) in this version, so nothing changes. I keep task texts up to 30 days for FORGET."

// forgetOffText answers FORGET when the forget plane could not open.
const forgetOffText = "I can't forget tasks right now. Restarting me may fix it."

// wireSettings answers the owner's settings texts: FORGET through f, or
// forgetOffText when f is nil (the forget plane did not open, which
// STATUS then says too), and the
// old loop settings with loopsOffText. Both are answered by the box,
// locked or not, never sent to the agent as chat, and a loop setting
// changes nothing, so it runs in a locked session.
func wireSettings(cfg *daemon.Config, f *ownerForget) {
	if f == nil {
		cfg.Notes = append(cfg.Notes, func() string { return forgetNotRunning })
	}
	cfg.Settings = func(ctx context.Context, msg string, unlocked bool) (string, bool) {
		if _, ok := parseForget(msg); ok {
			if f == nil {
				return forgetOffText, true
			}
			return f.Text(ctx, msg, unlocked)
		}
		if _, ok := loops.ParseText(msg); ok {
			return loopsOffText, true
		}
		return "", false
	}
	cfg.Narrows = func(msg string) bool {
		_, ok := loops.ParseText(msg)
		return ok
	}
}

// forgetTask deletes what the box keeps of one task outside the agent's
// memory: its text (W3-tasks part 1, CAP-3), after its tombstone. Only an
// authenticated owner forget may call it: the owner's approved FORGET
// (forget.go).
func (l *forgetPlane) forgetTask(goal string) error {
	if goal == "" {
		return errors.New("forget: forget needs a goal")
	}
	// The tombstone first: once it holds, nothing keeps the goal again,
	// even if the deletion below fails. If the tombstone did not save,
	// nothing else is deleted: the owner is told the task was not
	// forgotten, and it stays listed for another FORGET, also after a
	// restart (security R1 on #182). The goal stays tombstoned in memory
	// until then.
	if err := l.forgotten.add(goal); err != nil {
		return fmt.Errorf("%w: %v", errNotTombstoned, err)
	}
	_, err := l.tasks.forget(goal)
	return err
}

// errNotTombstoned: a forget's tombstone did not save, so nothing of the
// task was deleted.
var errNotTombstoned = errors.New("forget: the forget was not saved")

// replayForgotten runs every tombstoned goal's forget again when the plane
// opens (L3 MUST-2 on #160), so a crash between the tombstone and the
// deletion leaves no task text behind.
func (l *forgetPlane) replayForgotten() error {
	var errs []error
	for _, g := range l.forgotten.goals() {
		_, err := l.tasks.forget(g)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// forgetLogFile is the restored copy of the forget log in the forget
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
	Done  bool      `json:"done"`
}

// toldDone is the goals whose last forget in the restored log is followed
// by a done marker: their done text was sent (R2B).
func toldDone(restored []restoredForget) map[string]bool {
	told := map[string]bool{}
	for _, e := range restored {
		told[e.Goal] = e.Done
	}
	return told
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
// forget plane closed (CAP-3 across a restore); restoreHold keeps
// agentosd from starting at all on the held one.
func readRestoredForgets(dir string) ([]restoredForget, error) {
	path := filepath.Join(dir, forgetLogFile)
	if b, err := os.ReadFile(path + ".pending"); err == nil {
		return nil, fmt.Errorf("forget: restore pending: %s", strings.TrimSpace(string(b)))
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("forget: restore pending: %v", err)
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("forget: forget log: %v", err)
	}
	var fl struct {
		Entries []restoredForget `json:"entries"`
	}
	if err := json.Unmarshal(b, &fl); err != nil {
		return nil, fmt.Errorf("forget: forget log: %v", err)
	}
	for _, e := range fl.Entries {
		if e.Goal == "" {
			return nil, errors.New("forget: forget log: an entry has no goal")
		}
	}
	return fl.Entries, nil
}

// attachOwner gives the forget plane the owner channel o, which may be
// nil.
func (l *forgetPlane) attachOwner(o *owner.Channel) { l.notify.ch.Store(o) }

// attach binds the running daemon's gate and owner channel and texts the
// done texts the last boot owed.
func (l *forgetPlane) attach(ctx context.Context, d *daemon.Daemon) {
	if g := d.Gate(); g != nil {
		l.forgetOwner.gate.Store(&pauseGateBox{g})
	}
	l.attachOwner(d.Owner())
	l.forgetOwner.finishOwed(ctx)
}

// delivered keeps the owner's task text for FORGET's list (guest G16),
// unless its goal was forgotten.
func (l *forgetPlane) delivered(goal, text string, public bool) {
	if !l.forgotten.has(goal) {
		// Task chat reaches the agent only from the owner channel, whose
		// transport is the box's SIM.
		l.tasks.put(goal, text, public, viaSMS)
	}
}

// openOwedFile opens the owed done texts saved by store at path. One that
// does not read is kept aside, not read again, and the owner told (L3 B2
// on #425). The aside is a hard link, and the fresh file owing the notice
// is then saved over path, so path holds the bad file or the fresh one,
// never nothing: a crash between the two repeats both at the next start
// (security S1 on #425).
func openOwedFile(store change.Store, path string) *forgetOwed {
	owed, err := openForgetOwed(store)
	if err == nil {
		return owed
	}
	aside := path + ".bad"
	if rerr := os.Remove(aside); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		log.Printf("forget: old unreadable owed file not removed: %v", rerr)
	}
	kept := os.Link(path, aside)
	owed = lostForgetOwed(store)
	if kept != nil {
		log.Printf("forget: owed done texts lost, unreadable file not kept aside: %v: %v", err, kept)
	} else {
		log.Printf("forget: owed done texts lost, kept aside as %s: %v", aside, err)
	}
	return owed
}

// retiredExecutor settles an intent for an executor this version no
// longer has (change and loops, deleted with the learning loop): nothing
// runs, so every attempt is not applied, and an open approval (a pending
// LOOPS ON or SPARE BUDGET) or a parked attempt settles on YES or RETRY
// instead of failing with journal.ErrNoExecutor (NL-8). The kernel's log
// replaces the journal (#2781).
type retiredExecutor struct{}

func (retiredExecutor) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "retired in this version"}
}

func (r retiredExecutor) Reconcile(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	return r.Execute(ctx, in, n)
}

// registerRetired registers retiredExecutor for the deleted executors.
func registerRetired(cfg *daemon.Config) {
	if cfg.BrokerExecutors == nil {
		cfg.BrokerExecutors = map[string]journal.Executor{}
	}
	for _, name := range []string{change.Executor, loops.Executor} {
		cfg.BrokerExecutors[name] = retiredExecutor{}
	}
}
