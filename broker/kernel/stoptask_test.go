package kernel_test

// REQ: KRN-5, KRN-7, KEY-8

// KRN-stop-task (#5064): a STOP or a task's end cancels its plans' unsent
// steps in its own fold, so nothing folded after it (a RESUME before the
// next tick, a window ending) sends a step it stopped.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A held unsubscribe, STOP, then RESUME before any tick: the window ends with
// no POST sent (KRN-7, KEY-8). The control, a tick between STOP and RESUME,
// ends the same way.
func TestStopThenResumeBeforeATickSendsNothing(t *testing.T) {
	for name, between := range map[string]bool{"resume at once": false, "tick between": true} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.plan("p1", r.derive(key.LimitHold(hour, hour)), st(key.Unsubscribe, "list-a"))
			must(t, r.tick(0))
			must(t, r.k.Stop(60_000))
			if r.status("p1") != kernel.SCancelled {
				t.Fatalf("the STOP's fold left the held plan %s", r.status("p1"))
			}
			if between {
				must(t, r.tick(90_000))
			}
			must(t, r.k.Resume(120_000, r.k.State().Stops))
			must(t, r.tick(hour))
			must(t, r.tick(2*hour))
			if p := r.k.State().Plans["p1"]; p.Status != kernel.SCancelled || p.Cancel != key.RStopped || len(r.mail.Effects()) != 0 {
				t.Fatalf("status %s %s, %d effects", p.Status, p.Cancel, len(r.mail.Effects()))
			}
			r.replays()
		})
	}
}

// A step in flight at the STOP still reconciles (KRN-8), but its plan sends
// no further step after a RESUME.
func TestAStepInFlightAtSTOPReconcilesAndItsPlanStops(t *testing.T) {
	r := newRig(t)
	lost := 1
	r.mail.Fault = func(op string, _ kernel.Request) string {
		if op == "do" && lost > 0 {
			lost--
			return clerk.FaultLostAck
		}
		return ""
	}
	r.plan("p1", r.ck, st(key.Trash, "m1"), st(key.Organize, "m2"))
	must(t, r.tick(0))
	must(t, r.k.Stop(1))
	must(t, r.k.Resume(2, r.k.State().Stops))
	must(t, r.tick(kernel.ProbeEvery))
	p := r.k.State().Plans["p1"]
	if p.Steps[0].Phase != kernel.PDone || p.Steps[1].Phase != kernel.PCancelled || p.Status != kernel.SCancelled || p.Cancel != key.RStopped {
		t.Fatalf("phases %s %s, status %s %s", p.Steps[0].Phase, p.Steps[1].Phase, p.Status, p.Cancel)
	}
	if len(r.mail.Effects()) != 1 {
		t.Fatalf("%d effects, want the reconciled one only", len(r.mail.Effects()))
	}
	// Next refuses the second step itself: it is never even logged in flight.
	for _, e := range r.k.Log().Entries() {
		if e.Type == kernel.TStepDispatch && strings.Contains(string(e.Body), `"index":1`) {
			t.Fatalf("entry %d dispatched the stopped plan's second step", e.Seq)
		}
	}
	r.replays()
}

// A dispatch Calls handed out before a STOP is not sent after a RESUME: the
// send check refuses it, as Next would (KRN-7).
func TestSendRefusesADispatchStoppedSinceCalls(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	c := r.calls(1, 1)[0]
	must(t, r.k.Stop(2))
	must(t, r.k.Resume(3, r.k.State().Stops))
	ok, err := r.k.Send(4, c)
	must(t, err)
	if ok || r.status("p1") != kernel.SCancelled || len(r.mail.Effects()) != 0 {
		t.Fatalf("sent %v, status %s", ok, r.status("p1"))
	}
	r.replays()
}

// A hold longer than its task: the scheduler logs the task's end at the
// first tick past its timeout, before any step at that time, and the end
// cancels the held step (KRN-5, KEY-8).
func TestAHoldLongerThanItsTaskIsCancelledAtTheTimeout(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	r.plan("p1", r.serve("t1", key.LimitHold(30*hour, 30*hour)), st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	must(t, r.tick(31*hour))
	if p := r.k.State().Plans["p1"]; p.Status != kernel.SCancelled || p.Cancel != kernel.CTask || len(r.mail.Effects()) != 0 {
		t.Fatalf("status %s %s, %d effects", p.Status, p.Cancel, len(r.mail.Effects()))
	}
	es := r.k.Log().Entries()
	if e := es[len(es)-1]; e.Type != kernel.TTaskEnded || e.At != 31*hour {
		t.Fatalf("last entry %s at %d, want the task's end at the tick", e.Type, e.At)
	}
	n := r.k.Log().Len()
	must(t, r.tick(32*hour))
	if r.k.Log().Len() != n {
		t.Fatal("a task's end was logged twice")
	}
	r.replays()
}

// At its very timeout every task due ends, each in its own entry, before
// any step is scheduled.
func TestEveryTaskDueEndsAtItsTimeout(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	must(t, r.k.OpenTask(0, "t2", 0))
	must(t, r.k.OpenTask(1, "t3", 0))
	n := r.k.Log().Len()
	must(t, r.tick(kernel.TaskTimeout))
	es := r.k.Log().Entries()[n:]
	if len(es) != 2 || es[0].Type != kernel.TTaskEnded || es[1].Type != kernel.TTaskEnded ||
		string(es[0].Body) != `{"task":"t1"}` || string(es[1].Body) != `{"task":"t2"}` {
		t.Fatalf("at the timeout the log took %+v, want t1's and t2's ends", es)
	}
	if _, ok := r.k.State().Task("t3", kernel.TaskTimeout); !ok {
		t.Fatal("a task not yet due ended")
	}
	r.replays()
}

// A dispatch Calls handed out just before the task's timeout is not sent
// after it: the send check reads the task's life on its own clock.
func TestSendRefusesAStepWhoseTaskTimedOutSinceCalls(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	at := kernel.TaskTimeout - 1
	must(t, r.k.Submit(at, r.sign(kernel.Plan{ID: "p1", Key: r.serve("t1"), Steps: []kernel.PlanStep{st(key.Trash, "m1")}})))
	c := r.calls(at, 1)[0]
	ok, err := r.k.Send(kernel.TaskTimeout, c)
	must(t, err)
	if p := r.k.State().Plans["p1"]; ok || p.Status != kernel.SCancelled || p.Cancel != kernel.CTask || len(r.mail.Effects()) != 0 {
		t.Fatalf("sent %v, status %s %s", ok, p.Status, p.Cancel)
	}
	r.replays()
}

// RETRY outlives the task (KRN-5): a step parked when its task ends may still
// be sent again at the owner's word, and only that step.
func TestARetryOfAParkedStepOutlivesItsTask(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	at := r.park(r.serve("t1"))
	must(t, r.k.EndTask(at+1, "t1"))
	if p := r.k.State().Plans["p1"]; p.Status != kernel.SActive || p.Ended != kernel.CTask {
		t.Fatalf("the parked plan at the end: %s, ended %q", p.Status, p.Ended)
	}
	must(t, r.tick(at+2))
	if len(r.mail.Effects()) != 0 {
		t.Fatal("a parked step was sent without a RETRY")
	}
	must(t, r.k.Retry(at+3, "p1", 0, r.phase("p1").Attempt))
	must(t, r.tick(at+4))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("after the RETRY: status %s, %d effects", r.status("p1"), len(r.mail.Effects()))
	}
	r.replays()
}

// stopCancel is the cancel Next logged after a STOP before the fix.
func stopCancel(plan string) any {
	return struct {
		Plan   string `json:"plan"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}{plan, key.RStopped, "stop is in force"}
}

// A log written before the fix carries the scheduler's cancel after each
// STOP; Rederive accepts it as already applied. Any other cancel the fold did
// not give, and a task's end no rule gives, still diverge.
func TestRederiveAcceptsTheOldStopShapeOnly(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.derive(key.LimitHold(hour, hour)), st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	must(t, r.k.Stop(1))
	must(t, kernel.Emit(r.k, 2, kernel.TPlanCancel, stopCancel("p1")))
	r.replays()

	for name, forge := range map[string]func(*rig) error{
		"a stop's cancel of a plan the owner cancelled": func(r *rig) error {
			must(r.t, r.k.Cancel(1, "p1"))
			return kernel.Emit(r.k, 2, kernel.TPlanCancel, stopCancel("p1"))
		},
		"an end of a task already ended": func(r *rig) error {
			must(r.t, r.k.OpenTask(1, "t1", 0))
			must(r.t, r.k.EndTask(2, "t1"))
			return kernel.Emit(r.k, 3, kernel.TTaskEnded, map[string]string{"task": "t1"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.plan("p1", r.derive(key.LimitHold(hour, hour)), st(key.Unsubscribe, "list-a"))
			must(t, r.tick(0))
			must(t, forge(r))
			var d *kernel.Divergence
			if _, err := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries()); !errors.As(err, &d) {
				t.Fatalf("rederive: %v", err)
			}
		})
	}
}
