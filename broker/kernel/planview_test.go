package kernel_test

// REQ: PLN-4, PLN-5

import (
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A rejected plan's view names the failing check's code, from the log, so a
// rebuild from the log reads the same (PLN-4, KRN-1).
func TestPlanViewNamesTheRejection(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Draft, "m1")) // the key reaches no draft
	v := r.k.State().PlanView("p1")
	if v.Status != kernel.SRejected || v.Reject != key.RVerb || len(v.Steps) != 0 {
		t.Fatalf("view %+v: want rejected with code %q and no steps", v, key.RVerb)
	}
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if got := re.PlanView("p1"); !reflect.DeepEqual(got, v) {
		t.Fatalf("rebuilt view %+v, live %+v", got, v)
	}
	if v := r.k.State().PlanView("none"); v.Status != "" {
		t.Fatalf("no such plan: %+v", v)
	}
}

// failing is a clerk that refuses every step with a fixed code.
type failing struct{}

func (failing) Do(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "failed", Detail: "claim"}
}
func (failing) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "notdone"}
}

// An accepted plan's view gives each step's phase, the clerk's answer and
// whether it was undone (PLN-5 (b)); an accepted plan has no rejection code.
func TestPlanViewGivesEachStepsResult(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"), st(key.Organize, "m2"))
	must(t, r.tick(10))
	must(t, r.tick(20))
	must(t, r.k.Undo(30, "p1", 0))
	v := r.k.State().PlanView("p1")
	want := kernel.PlanView{Status: kernel.SDone, Steps: []kernel.StepView{
		{Phase: kernel.PDone, Undone: true}, {Phase: kernel.PDone}}}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("view %+v, want %+v", v, want)
	}

	// The same log under a clerk that refuses: the step's answer is read.
	l, err := kernel.Open(cfg(r))
	must(t, err)
	r.k, err = kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{"mail": failing{}}, 40)
	must(t, err)
	r.plan("p2", r.ck, st(key.Trash, "m3"), st(key.Organize, "m4"))
	must(t, r.k.Tick(50))
	v = r.k.State().PlanView("p2")
	want = kernel.PlanView{Status: kernel.SFailed, Steps: []kernel.StepView{
		{Phase: kernel.PFailed, Result: "claim"}, {Phase: kernel.PQueued}}}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("view %+v, want %+v", v, want)
	}
}
