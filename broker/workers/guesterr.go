package workers

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/guesterr"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// said is error text the workers package wrote for the guest: fixed words,
// and only values typed as safe to show it (sayArg). It wraps nothing, so
// no cause's text can ride along. Every error a worker tool answers is a
// said: Call passes each through guestErr (SR2-3f, security R1 on #174).
type said struct{ s string }

func (e said) Error() string { return e.s }

// GuestText lets said through the guest plane's filter (SR2-3g): the
// workers family's entry on guesterr's allowlist.
func (e said) GuestText() string { return e.s }

// sayArg is a value say may put in a guest's error text. Only these types
// implement it, and TestWorkerErrorsAreBuiltOnlyFromSafeText checks that
// no conversion to them takes an error or a host value (security F1 on
// SR2-3f).
type sayArg interface{ sayArg() }

type (
	named string // a name the guest gave and nameRE or the tools checked
	guest string // other text from the guest: a path it asked for, its command's stderr
	num   int64  // a count or size
)

func (named) sayArg() {}
func (guest) sayArg() {}
func (num) sayArg()   {}
func (said) sayArg()  {}

// say is the one way the workers package makes an error; format must be a
// literal.
func say(format string, args ...sayArg) said {
	vs := make([]any, len(args))
	for i, a := range args {
		vs[i] = a
	}
	return said{fmt.Sprintf(format, vs...)}
}

// guestErr is what the guest sees of err from tool, called by machine:
// the workers package's own text as it is; a known sentinel as a fixed
// text written here, never the error's own text, which may carry host
// paths and internal IDs; anything else as a ref, with the detail only
// in the broker's log, which no agent machine can read (security F4).
func guestErr(machine, tool string, err error) error {
	if s, ok := err.(said); ok {
		return s
	}
	if s, ok := sentinel(err); ok {
		return said{tool + ": " + s.s}
	}
	return said{tool + " " + logged(machine, tool, err).s}
}

// logged writes err to the broker's log under a fresh ref and says only
// the ref (guesterr.Logged, shared with the guest plane's filter).
func logged(machine, tool string, err error) said {
	return said{guesterr.Logged("workers", machine, tool, err)}
}

// panicked is a recovered tool panic; guestErr answers it as a ref
// (security F2 on SR2-3f).
type panicked struct {
	v     any
	stack []byte
}

func (p panicked) Error() string { return fmt.Sprint("panic: ", p.v, "\n", string(p.stack)) }

func recovered(v any) error { return panicked{v, debug.Stack()} }

// sentinel is the fixed text for the errors the guest can act on. An
// unknown machine and a machine of another lineage read the same (no
// such worker), so the text says nothing of machines the caller cannot
// see (security F3 on SR2-3f).
func sentinel(err error) (said, bool) {
	var full *vm.WorkerFull
	switch {
	case errors.As(err, &full):
		return say("holds more files than its %d MB cap; delete files with worker_delete, roll it back to a snapshot, or destroy it", num((full.Cap+1<<20-1)>>20)), true
	case errors.Is(err, vm.ErrQuota) && errors.Is(err, overlay.ErrTooDeep):
		return say("disk budget exceeded: directories nest more than %d deep, or a path is too long; flatten them with worker_delete, or roll the worker back", num(overlay.MaxTreeDepth)), true
	case errors.Is(err, vm.ErrQuota):
		return said{"disk budget exceeded: snapshot refused; delete files with worker_delete or roll the worker back, then retry"}, true
	case errors.Is(err, vm.ErrDiskFull):
		return said{"not enough disk for this worker now; destroy a worker, then retry"}, true
	case errors.Is(err, admission.ErrNoRoom), errors.Is(err, admission.ErrPressure):
		return said{"no room for a worker now: destroy a worker, or ask for less memory with mem_mb"}, true
	case errors.Is(err, vm.ErrBusy):
		return said{"the worker is busy with another command; retry when it returns"}, true
	case errors.Is(err, vm.ErrHeld):
		return errStopped, true
	case errors.Is(err, vm.ErrExecNotStarted):
		return said{"the command did not start; retry it"}, true
	case errors.Is(err, vm.ErrExecNoProgram):
		return said{"the command did not start: its program was not found or cannot run; check its path and that it is executable, since a retry fails the same way"}, true
	case errors.Is(err, vm.ErrExecFailed):
		return said{"the runtime failed after the command started, so it may have run; check what it changed before running it again"}, true
	case errors.Is(err, vm.ErrPreempted):
		return said{"preempted, retry: the worker was stopped for higher-priority work; roll it back with worker_rollback, or destroy and recreate it"}, true
	case errors.Is(err, vm.ErrState):
		return said{"the worker is not in a state that allows this; worker_list shows its state, and worker_rollback revives a stopped worker"}, true
	case errors.Is(err, vm.ErrLabel):
		return said{"that worker holds private data; a public machine cannot read it"}, true
	case errors.Is(err, vm.ErrUnknown):
		return errNoWorker, true
	case errors.Is(err, vm.ErrLineage):
		return said{"that snapshot is not in this worker's lineage"}, true
	case errors.Is(err, vm.ErrExists):
		return said{"a worker of that name already exists"}, true
	case errors.Is(err, vm.ErrContained):
		return said{"this agent holds a record the owner deleted; no fork until that is settled"}, true
	case errors.Is(err, vm.ErrNoExec):
		return said{"this box cannot run commands in workers"}, true
	case errors.Is(err, overlay.ErrDeleteFailed):
		return said{"the deletion could not finish; try again, or roll back or destroy the worker"}, true
	case errors.Is(err, overlay.ErrUnsafe):
		return said{"an unsafe path or object in the worker's files; delete it with worker_delete, or roll back"}, true
	}
	return said{}, false
}

// joined is parts joined by sep.
func joined(parts []said, sep string) said {
	ss := make([]string, len(parts))
	for i, p := range parts {
		ss[i] = p.s
	}
	return said{strings.Join(ss, sep)}
}
