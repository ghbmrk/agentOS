package vm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
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
}

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

// Exec runs c in worker id and waits up to timeout. It holds the machine's
// lock, so no snapshot, rollback or fork of the worker runs meanwhile;
// preemption does not wait for the lock and ends the command with the
// machine. Only workers take commands: an agent machine is driven by its
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
	if mc.State != Running {
		return ExecResult{}, fmt.Errorf("%w: %s is %s", ErrState, id, mc.State)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r, err := ex.Exec(ctx, id, c)
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return ExecResult{TimedOut: true, Stdout: r.Stdout, Stderr: r.Stderr, Truncated: r.Truncated, ExitCode: -1}, nil
	}
	return r, err
}
