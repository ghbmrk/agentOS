package provagent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: OP-6

// A run asked for under STOP starts nothing: no seed, no worker, and its
// reason is stopped, which CAP-9 does not answer with another route.
func TestARunUnderStopStartsNothing(t *testing.T) {
	g := newRig(ok("the answer"))
	q := req("b")
	q.Hold = func() bool { return true }
	_, err := g.r.Run(context.Background(), q)
	if reasonOf(err) != Stopped {
		t.Fatalf("err = %v, want stopped", err)
	}
	if FallsBack(err) {
		t.Error("a stopped run falls back to another route")
	}
	if len(g.h.created) != 0 || len(g.sd.calls) != 0 {
		t.Errorf("STOP still made %v workers, %v seeds", g.h.created, g.sd.calls)
	}
}

// Both commands the run execs carry the owner's STOP, so the VM manager
// refuses either one that reaches Exec after STOP at once (vm.ErrHeld)
// instead of the reaper ending it on its next tick.
func TestBothRunCommandsCarryTheOwnersStop(t *testing.T) {
	var stopped atomic.Bool
	var reads []vm.Command
	g := newRig(ok("the answer"))
	g.h.onRead = func(c vm.Command) { reads = append(reads, c) }
	q := req("b")
	q.Hold = stopped.Load
	if _, err := g.r.Run(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if len(g.h.runs) != 1 || len(reads) != 1 {
		t.Fatalf("%d CLI runs, %d reads", len(g.h.runs), len(reads))
	}
	for _, c := range []vm.Command{g.h.runs[0], reads[0]} {
		if c.Hold == nil || c.Hold() {
			t.Fatalf("%v: hold missing or set before STOP", c.Argv)
		}
	}
	stopped.Store(true)
	if !g.h.runs[0].Hold() || !reads[0].Hold() {
		t.Error("a command's hold does not read the owner's STOP")
	}
}

// A CLI that STOP ends (or holds) mid-run answers stopped, not failed, and
// the worker is still destroyed.
func TestACLIEndedByStopIsStopped(t *testing.T) {
	var stopped atomic.Bool
	g := newRig(func(c vm.Command, s *stub) vm.ExecResult { stopped.Store(true); return vm.ExecResult{ExitCode: -1} })
	g.h.execErr = errors.New("command ended before it finished")
	q := req("b")
	q.Hold = stopped.Load
	_, err := g.r.Run(context.Background(), q)
	if reasonOf(err) != Stopped || FallsBack(err) {
		t.Fatalf("err = %v, want stopped with no fallback", err)
	}
	if len(g.h.created) != 1 || len(g.h.destroyed) != 1 {
		t.Errorf("worker lifecycle: %v %v", g.h.created, g.h.destroyed)
	}
}

// A STOP between the CLI and the result read: the read is held, and the
// run answers stopped.
func TestAResultReadHeldByStopIsStopped(t *testing.T) {
	var stopped atomic.Bool
	g := newRig(func(c vm.Command, s *stub) vm.ExecResult {
		s.write("/work/.result", "the answer")
		stopped.Store(true)
		return vm.ExecResult{}
	})
	g.h.readErr = vm.ErrHeld
	q := req("b")
	q.Hold = stopped.Load
	if _, err := g.r.Run(context.Background(), q); reasonOf(err) != Stopped {
		t.Fatalf("err = %v, want stopped", err)
	}
}

// Without STOP an Exec error is still failed: stopped is STOP's only.
func TestAnExecErrorWithoutStopIsStillFailed(t *testing.T) {
	g := newRig(ok("x"))
	g.h.execErr = errors.New("boom")
	q := req("b")
	q.Hold = func() bool { return false }
	if _, err := g.r.Run(context.Background(), q); reasonOf(err) != Failed {
		t.Fatalf("err = %v, want failed", err)
	}
}
