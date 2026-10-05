package vm

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// WorkerPrefix starts the IDs of worker machines (CAP-8): machines with no
// agent runtime, built from a base image and driven by the guest that made
// them through broker tools. Only CreateWorker makes them, and only a
// worker forks into one. A worker gets no guest services.
const WorkerPrefix = "wk-"

// ErrNoExec means the runtime cannot run commands in a machine.
var ErrNoExec = errors.New("vm: this runtime cannot run commands in a machine")

// Execer is a Runtime that can run a command in a running machine.
type Execer interface {
	Exec(ctx context.Context, id string, c Command) (ExecResult, error)
}

// Command is one command run in a machine.
type Command struct {
	Argv  []string
	Stdin []byte
	// MaxOutput caps each of stdout and stderr; output past it is dropped
	// and Truncated set.
	MaxOutput int
	// As is the data label of the machine the command runs for. Under the
	// worker's lock, Exec raises the worker to it before the command
	// writes anything (A14), and refuses a worker labelled above it, whose
	// output the caller may not read (REV-5).
	As Label
	// Hold, when set, is asked under the worker's lock once the command
	// can be ended (EndCommands reaches it): true refuses it with ErrHeld.
	// The owner's STOP holds commands through it, so one queued on the
	// lock cannot start after STOP (OP-6).
	Hold func() bool
}

// ErrHeld refuses a command while its Hold says so.
var ErrHeld = errors.New("vm: commands are held")

// WorkerFull refuses a command or snapshot of a worker whose files are
// over its layer cap (Config.WorkerLayerBytes). It is an ErrQuota.
type WorkerFull struct {
	ID         string
	Bytes, Cap int64
}

func (e *WorkerFull) Error() string {
	return fmt.Sprintf("vm: worker %s holds %d bytes of files, over its cap of %d", e.ID, e.Bytes, e.Cap)
}

func (e *WorkerFull) Unwrap() error { return ErrQuota }

// ErrBusy refuses to park a worker that is in use.
var ErrBusy = errors.New("vm: worker is busy")

// ErrLabel refuses a command whose caller may not read the worker.
var ErrLabel = errors.New("vm: that worker holds private data; a public machine cannot read it")

// ExecGrace is how long past its timeout Exec waits for a runtime that
// does not end a command, before it gives up on the command and lets the
// worker's lock go. A var so tests can shorten it.
var ExecGrace = 15 * time.Second

// ExecResult is a finished command. A command that ran and exited
// non-zero is a result, not an error.
type ExecResult struct {
	ExitCode       int
	Stdout, Stderr []byte
	Truncated      bool
	TimedOut       bool
}

// CreateWorker admits and starts a worker machine in lineage, which must
// be a live machine's: the worker inherits the creator's lineage, so its
// snapshots stay in that lineage's custody and deletion reach (CAP-3)
// takes it back with the rest. The caller sets the inherited class,
// budget and label in s (CAP-8, REV-5).
func (m *Manager) CreateWorker(ctx context.Context, id, lineage string, s Spec) (Machine, error) {
	if !strings.HasPrefix(id, WorkerPrefix) {
		return Machine{}, fmt.Errorf("vm: worker ids start %q", WorkerPrefix)
	}
	if lineage == "" || !m.lineageLive(lineage) {
		return Machine{}, fmt.Errorf("%w: lineage %q", ErrUnknown, lineage)
	}
	return m.create(ctx, id, s, nil, lineage)
}

// lineageLive reports whether a machine other than a worker holds lineage.
// A lineage is fixed when a machine is reserved, so it is read under the
// table's lock alone (as ForgetSince does); taking a machine's lock here
// would invert the order capture uses.
func (m *Manager) lineageLive(lineage string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, mc := range m.machines {
		if !strings.HasPrefix(id, WorkerPrefix) && mc.Lineage == lineage {
			return true
		}
	}
	return false
}

// Workers lists the IDs of lineage's workers, ones still being made
// included. Like lineageLive it reads the table alone, so it never waits
// behind a worker's command.
func (m *Manager) Workers(lineage string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for id, mc := range m.machines {
		if strings.HasPrefix(id, WorkerPrefix) && mc.Lineage == lineage {
			out = append(out, id)
		}
	}
	return out
}

// setForkBase sets mc's ForkBase. The caller holds mc.mu; the write also
// takes the table lock, so ForkSiblings can read it without mc.mu.
func (m *Manager) setForkBase(mc *machine, base string) {
	m.mu.Lock()
	mc.ForkBase = base
	m.mu.Unlock()
}

// ForkSiblings returns the snapshot worker id was forked from and the
// other workers of its lineage forked from it. Like Workers it reads the
// table alone, so it never waits behind a worker's command (CAP-1 keep).
func (m *Manager) ForkSiblings(id string) (string, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.machines[id]
	if !ok {
		return "", nil, fmt.Errorf("%w: machine %s", ErrUnknown, id)
	}
	var sibs []string
	if mc.ForkBase != "" {
		for oid, o := range m.machines {
			if oid != id && strings.HasPrefix(oid, WorkerPrefix) && o.Lineage == mc.Lineage && o.ForkBase == mc.ForkBase {
				sibs = append(sibs, oid)
			}
		}
	}
	sort.Strings(sibs)
	return mc.ForkBase, sibs, nil
}

// TryGet returns machine id, or false when it is unknown or busy (its lock
// is held by a command, snapshot or start), without waiting.
func (m *Manager) TryGet(id string) (Machine, bool) {
	mc, err := m.get(id)
	if err != nil || !mc.mu.TryLock() {
		return Machine{}, false
	}
	defer mc.mu.Unlock()
	return mc.Machine, true
}

// Exec runs c in worker id and waits up to timeout. It holds the machine's
// lock, so no snapshot, rollback or fork of the worker runs meanwhile;
// preemption does not wait for the lock and ends the command with the
// machine; erasure, rollback and destroy end the command first. Only
// workers take commands: an agent machine is driven by its
// own runtime, never by the broker on a guest's behalf.
func (m *Manager) Exec(ctx context.Context, id string, c Command, timeout time.Duration) (ExecResult, error) {
	if !strings.HasPrefix(id, WorkerPrefix) {
		return ExecResult{}, fmt.Errorf("vm: %s is not a worker", id)
	}
	ex, ok := m.cfg.Runtime.(Execer)
	if !ok {
		return ExecResult{}, ErrNoExec
	}
	if len(c.Argv) == 0 {
		return ExecResult{}, errors.New("vm: exec needs a command")
	}
	mc, err := m.get(id)
	if err != nil {
		return ExecResult{}, err
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.State == Preempted {
		return ExecResult{}, fmt.Errorf("%w: %s", ErrPreempted, id)
	}
	if mc.State != Running {
		return ExecResult{}, fmt.Errorf("%w: %s is %s", ErrState, id, mc.State)
	}
	if c.As > mc.Label {
		mc.Label = c.As
		if err := m.saveMachine(mc); err != nil {
			return ExecResult{}, err
		}
	}
	if mc.Label > c.As {
		return ExecResult{}, ErrLabel
	}
	if m.cfg.WorkerLayerBytes > 0 {
		if _, err := m.checkCaps(id, m.launch(mc).Upper); err != nil {
			return ExecResult{}, fmt.Errorf("%s: %w", id, err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	mc.execCancel.Store(&cancel)
	defer mc.execCancel.Store(nil)
	if c.Hold != nil && c.Hold() {
		return ExecResult{}, ErrHeld
	}
	r, err := m.awaitExec(ctx, ex, id, c)
	if mc.preempting.Load() {
		// Preempt ended the command with the machine: it has no result,
		// not a failed exit (potency R1 on #158).
		return ExecResult{}, fmt.Errorf("%w: %s: the command did not finish", ErrPreempted, id)
	}
	if err != nil && ctx.Err() == context.Canceled {
		return ExecResult{}, fmt.Errorf("vm: %s: command ended before it finished", id)
	}
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return ExecResult{TimedOut: true, Stdout: r.Stdout, Stderr: r.Stderr, Truncated: r.Truncated, ExitCode: -1}, nil
	}
	return r, err
}

// awaitExec runs the command and returns when the runtime does, or
// ExecGrace after ctx ends if the runtime has not: a runtime that ignores
// cancellation must not hold the worker's lock, and with it erasure
// (F1), past that bound. The abandoned call finishes on its own.
func (m *Manager) awaitExec(ctx context.Context, ex Execer, id string, c Command) (ExecResult, error) {
	type done struct {
		r   ExecResult
		err error
	}
	ch := make(chan done, 1)
	go func() {
		r, err := ex.Exec(ctx, id, c)
		ch <- done{r, err}
	}()
	select {
	case d := <-ch:
		return d.r, d.err
	case <-ctx.Done():
	}
	t := time.NewTimer(ExecGrace)
	defer t.Stop()
	select {
	case d := <-ch:
		return d.r, d.err
	case <-t.C:
		log.Printf("vm: %s: the runtime did not end a cancelled command; abandoning it", id)
		return ExecResult{}, ctx.Err()
	}
}

// Park checkpoints a running worker, memory included, and stops it,
// handing its memory back to admission (UX-146-1). The checkpoint becomes
// the worker's newest snapshot; rolling back to it revives the worker as
// it was. A busy worker (a command holds its lock) is refused with
// ErrBusy at once, so Reap never waits out a command. A worker over its
// layer cap is stopped without a checkpoint (the zero Snapshot): it
// revives by rollback to an earlier snapshot.
func (m *Manager) Park(ctx context.Context, id string) (Snapshot, error) {
	if !strings.HasPrefix(id, WorkerPrefix) {
		return Snapshot{}, fmt.Errorf("vm: %s is not a worker", id)
	}
	mc, err := m.get(id)
	if err != nil {
		return Snapshot{}, err
	}
	// A worker whose lock is held is in use (a command runs): parking
	// would wait out the command, so it is refused instead.
	if !mc.mu.TryLock() {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrBusy, id)
	}
	if mc.State != Running {
		mc.mu.Unlock()
		return Snapshot{}, fmt.Errorf("%w: %s is %s", ErrState, id, mc.State)
	}
	s, err := m.takeLocked(ctx, mc, Full)
	var full *WorkerFull
	if errors.As(err, &full) {
		// Over its layer cap no snapshot can be taken, but its memory
		// must still go back: stop it as it is. It revives by rollback
		// to an earlier snapshot, which also brings it under the cap.
		s, err = Snapshot{}, nil
	}
	if err == nil {
		err = m.stopRuntime(ctx, mc)
		if serr := m.saveMachine(mc); err == nil {
			err = serr
		}
	}
	stopped := mc.State != Running
	mc.mu.Unlock()
	if stopped {
		m.cfg.Admit.Release(id)
	}
	return s, err
}

// EndCommands ends every worker command in flight (STOP, security R2 on
// #146). The workers keep running; their commands report an error.
func (m *Manager) EndCommands() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, mc := range m.machines {
		if !strings.HasPrefix(id, WorkerPrefix) {
			continue
		}
		if c := mc.execCancel.Load(); c != nil {
			(*c)()
			n++
		}
	}
	return n
}

// Deletion asks for files to be removed from a worker's layer (CAP-8c):
// the one change allowed while a worker is over its layer cap, and it
// runs no code from the worker.
type Deletion struct {
	Paths     []string // absolute guest paths, at most MaxDeletePaths
	Recursive bool
	As        Label       // the caller's label, as for Command.As
	Hold      func() bool // the owner's STOP, as for Command.Hold
}

// DeleteReport is what DeleteFiles did.
type DeleteReport struct {
	overlay.DeleteResult
	Over      bool // the layer is still over the worker's cap
	Restarted bool // the worker was running, and runs again
}

// MaxDeletePaths bounds one Deletion's paths (security R-DEL1).
const MaxDeletePaths = 64

// deleteEntries bounds the entries one Deletion removes (security
// R-DEL2); tests lower it.
var deleteEntries = 100_000

// DeleteFiles removes paths from worker id's upper layer with the worker
// stopped, under its lock, with the same label rule and STOP hold as
// Exec (security R-DEL2, R-DEL4 on CAP-8c). It then measures the layer
// again: under its cap, the worker starts again on the same layer, spec
// and label (one that was stopped is admitted afresh, as by Resume);
// still over it, it stays stopped with its memory released (R-DEL6).
func (m *Manager) DeleteFiles(ctx context.Context, id string, d Deletion) (DeleteReport, error) {
	if !strings.HasPrefix(id, WorkerPrefix) {
		return DeleteReport{}, fmt.Errorf("vm: %s is not a worker", id)
	}
	if len(d.Paths) == 0 || len(d.Paths) > MaxDeletePaths {
		return DeleteReport{}, fmt.Errorf("vm: a deletion takes 1 to %d paths", MaxDeletePaths)
	}
	mc, err := m.get(id)
	if err != nil {
		return DeleteReport{}, err
	}
	// A refused deletion ends nothing: STOP and the label rule are
	// checked before a command in the worker is ended (L3 SHOULD-2 on
	// #166), and again under the lock, since either may change meanwhile.
	if held(d) {
		return DeleteReport{}, ErrHeld
	}
	if Label(mc.label.Load()) > d.As {
		return DeleteReport{}, ErrLabel
	}
	// A command in the worker ends: the deletion stops the worker anyway
	// (L3 nit on #166).
	mc.lockEndingExec()
	was := mc.State
	rep, stopped, err := m.deleteLocked(ctx, mc, d)
	mc.mu.Unlock()
	// What the guest sees names no host path or errno: any failure other
	// than the guards' is logged here and returned as the fixed
	// overlay.ErrDeleteFailed (L3 S1, security F3 on #166).
	if err != nil && !errors.Is(err, ErrLabel) && !errors.Is(err, ErrHeld) && !errors.Is(err, ErrUnknown) && !errors.Is(err, overlay.ErrDeleteFailed) {
		log.Printf("vm: %s: deleting files: %v", id, err)
		err = fmt.Errorf("%s: %w", id, overlay.ErrDeleteFailed)
	}
	if stopped {
		m.cfg.Admit.Release(id)
	}
	// A preempted worker waits for its own resume, not a deletion's
	// (security R2 on #166). Admission may have no room now, or STOP may
	// have come meanwhile; the worker then stays stopped and the deletion
	// still stands (security F1 on #166).
	if err == nil && !rep.Over && was == Stopped && !held(d) {
		rep.Restarted = m.Resume(ctx, id) == nil
	}
	return rep, err
}

// deleteLocked is DeleteFiles under mc's lock; stopped says it stopped a
// running worker and left it stopped.
func (m *Manager) deleteLocked(ctx context.Context, mc *machine, d Deletion) (DeleteReport, bool, error) {
	if d.As > mc.Label {
		mc.Label = d.As
		if err := m.saveMachine(mc); err != nil {
			return DeleteReport{}, false, err
		}
	}
	if mc.Label > d.As {
		return DeleteReport{}, false, ErrLabel
	}
	if d.Hold != nil && d.Hold() {
		return DeleteReport{}, false, ErrHeld
	}
	running := mc.State == Running
	if running {
		if err := m.stopRuntime(ctx, mc); err != nil {
			return DeleteReport{}, false, err
		}
		if err := m.saveMachine(mc); err != nil {
			return DeleteReport{}, true, err
		}
	}
	l := m.launch(mc)
	var rep DeleteReport
	var err error
	rep.DeleteResult, err = overlay.Delete(l.Upper, l.Lower, d.Paths, d.Recursive, deleteEntries)
	if rep.Fault != nil {
		log.Printf("vm: %s: deleting files: %v", mc.ID, rep.Fault)
	}
	if err != nil {
		return rep, running, fmt.Errorf("%s: %w", mc.ID, err)
	}
	// A deletion never depends on measuring the layer: one that cannot
	// be measured (too deep for the host, say) counts as over the cap, so
	// the deletion stands and the worker stays stopped (security M4,
	// SR2-3i on #174).
	if _, cerr := m.checkCaps(mc.ID, l.Upper); errors.Is(cerr, ErrQuota) {
		rep.Over = true
	} else if cerr != nil {
		log.Printf("vm: %s: measuring after a deletion: %v", mc.ID, cerr)
		rep.Over = true
	}
	if !running || rep.Over || held(d) {
		return rep, running, nil
	}
	// A failed start leaves the worker stopped; the deletion and its
	// codes still stand, so they are answered rather than lost (L3 nit
	// on #166).
	if err := m.restartLocked(ctx, mc, keepLayer); err != nil {
		log.Printf("vm: %s: starting again after a deletion: %v", mc.ID, err)
		return rep, true, nil
	}
	rep.Restarted = true
	return rep, false, nil
}

func held(d Deletion) bool { return d.Hold != nil && d.Hold() }
