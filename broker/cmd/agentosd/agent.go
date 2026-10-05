package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// The agent machine's STATUS lines (UX-56-1): fixed words only; raw errors
// go to the log.
const (
	agentWaiting = "Agent: starting, waiting for memory."
	agentFailed  = "Agent: starting, last try failed."
	agentNotSet  = "Agent: not set up; the box needs an update or a restart."
)

// liveMachines is the part of the machine manager that keeps the owner's
// agent machine up.
type liveMachines interface {
	Get(id string) (vm.Machine, error)
	Create(ctx context.Context, id string, s vm.Spec) (vm.Machine, error)
	Resume(ctx context.Context, id string) error
}

// keeper keeps the machine that receives the owner's task chat running
// (ARC-4, RES-1). On a first start it creates the machine, labelled public
// until owner data reaches it (REV-5: an owner message not marked public
// raises it). After a broker restart, or if the machine is found stopped or
// preempted, it resumes it on its layer; the guest plane then hands it the
// unanswered owner messages again (guest G5). A machine that already exists
// keeps its image: moving it to a new one is the update path's, not this.
// The machine is created without a seed: the managed tree reaches only
// private machines (vm.ErrSeedLabel, compile K7).
type keeper struct {
	m     liveMachines
	id    string
	spec  vm.Spec
	every time.Duration
	logf  func(format string, args ...any)

	mu     sync.Mutex
	status string // STATUS line while not running; empty once it runs
}

// Status is the keeper's STATUS line: empty while the machine runs.
func (k *keeper) Status() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.status
}

func (k *keeper) setStatus(err error) {
	line := ""
	switch {
	case err == nil:
	case errors.Is(err, admission.ErrNoRoom), errors.Is(err, admission.ErrPressure):
		line = agentWaiting
	default:
		line = agentFailed
	}
	k.mu.Lock()
	k.status = line
	k.mu.Unlock()
}

// ensure brings the machine to running, or says why it is not.
func (k *keeper) ensure(ctx context.Context) error {
	mc, err := k.m.Get(k.id)
	switch {
	case errors.Is(err, vm.ErrUnknown):
		_, err = k.m.Create(ctx, k.id, k.spec)
		return err
	case err != nil:
		return err
	case mc.State == vm.Running:
		return nil
	default:
		return k.m.Resume(ctx, k.id)
	}
}

// maxBackoff caps the wait after repeated start failures, as a multiple of
// every.
const maxBackoff = 16

// run calls ensure now and again until ctx ends. Admission may refuse while
// other work holds memory, so that is retried every k.every; admission
// refused, so nothing was preempted. Any other failure came after
// admission, which as foreground may have preempted experiments, so the
// wait doubles each time, up to maxBackoff times every, and a machine that
// cannot start does not preempt experiments every tick. The log gets each
// distinct failure once, and the recovery.
func (k *keeper) run(ctx context.Context) {
	last := ""
	backoff := 1
	for {
		err := k.ensure(ctx)
		k.setStatus(err)
		switch {
		case err != nil && err.Error() != last:
			last = err.Error()
			k.logf("agent machine %s not running: %v", k.id, err)
		case err == nil && last != "":
			last = ""
			k.logf("agent machine %s running", k.id)
		}
		var wait time.Duration
		wait, backoff = nextWait(k.every, backoff, err)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// nextWait is how long run waits after err, and the backoff factor after it.
func nextWait(every time.Duration, backoff int, err error) (time.Duration, int) {
	if err == nil || errors.Is(err, admission.ErrNoRoom) || errors.Is(err, admission.ErrPressure) {
		return every, 1
	}
	wait := time.Duration(backoff) * every
	if backoff < maxBackoff {
		backoff *= 2
	}
	return wait, backoff
}

// errLaunchWritable refuses a launch file someone other than root or
// agentosd could have written.
var errLaunchWritable = errors.New("launch file is writable by others")

// launchSpec reads how the agent machine starts (vm.Spec Argv and Env),
// as guest/openclaw/launch.json records it. It sets what a foreground
// guest runs, so it must come from the signed host image's read-only root
// filesystem: a symlink, a file that is not regular, one owned by anyone
// but root or agentosd, or one writable by group or others is refused
// (L3 R2 on #56).
func launchSpec(path string) (argv, env []string, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 || st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return nil, nil, fmt.Errorf("%s: %w (mode %v)", path, errLaunchWritable, fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	var l struct{ Argv, Env []string }
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(l.Argv) == 0 {
		return nil, nil, fmt.Errorf("%s: no argv", path)
	}
	return l.Argv, l.Env, nil
}
