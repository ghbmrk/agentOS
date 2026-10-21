package kernel_test

// REQ: KRN-5, CLK-3, KEY-3, D-147

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const site, first = "shop.example", "https://shop.example/cart"

func approval(id string, by pair) kernel.TaskApproval {
	return kernel.TaskApproval{Site: site, First: first, By: key.Approve(by.priv, kernel.TaskHash(id, site, first))}
}

// serve is a key for task id, narrowed from the clerk's key.
func (r *rig) serve(id string, c ...key.Caveat) key.Key { return r.derive(append(c, key.LimitTask(id))...) }

func (r *rig) replays() {
	r.t.Helper()
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(r.t, err)
	if !reflect.DeepEqual(re, r.k.State()) {
		r.t.Fatal("replay differs from the live state (KRN-1)")
	}
}

func (r *rig) admits(id string, k key.Key, at int64) *key.Refusal {
	p := r.sign(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{st(key.Trash, id)}})
	_, _, rf := kernel.Admit(r.k.State(), p, at)
	return rf
}

// A task's plans and re-plans run under keys that carry it: a failed plan,
// a rejected one or a cancel leaves the task open for the next (KRN-5).
func TestATaskRunsItsPlansAndRePlans(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", kernel.TaskTimeout))
	r.mail.Fault = func(string, kernel.Request) string { return clerk.FaultFail }
	r.plan("p1", r.serve("t1"), st(key.Trash, "m1"))
	must(t, r.tick(1))
	r.mail.Fault = nil
	r.plan("p2", r.serve("t1"), st(key.Send, "m2"))
	r.plan("p3", r.serve("t1"), st(key.Trash, "m3"), st(key.Unsubscribe, "m3"))
	must(t, r.k.Cancel(2, "p3"))
	r.plan("p4", r.serve("t1", key.LimitUses(1)), st(key.Trash, "m4"))
	must(t, r.tick(3))
	if r.status("p1") != kernel.SFailed || r.status("p2") != kernel.SRejected || r.status("p4") != kernel.SDone {
		t.Fatalf("statuses %s %s %s", r.status("p1"), r.status("p2"), r.status("p4"))
	}
	if _, ok := r.k.State().Task("t1", 4); !ok {
		t.Fatal("a failed, rejected or cancelled plan ended the task")
	}
	r.replays()
}

func TestATaskKeyServesOnlyALiveTask(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", kernel.TaskTimeout))
	if _, err := key.Derive(r.serve("t1"), r.holder.priv, r.holder.pub, key.LimitTask("t2")); !errors.Is(err, key.ErrLoosens) {
		t.Fatalf("a key moved to another task: %v", err)
	}
	if _, err := key.Derive(r.ck, r.holder.priv, r.holder.pub, key.Caveat{Kind: key.KTask, Set: []string{"t1", "t2"}}); !errors.Is(err, key.ErrMalformed) {
		t.Fatalf("a key for two tasks: %v", err)
	}
	if rf := r.admits("p1", r.serve("t9"), 1); rf == nil || rf.Code != kernel.CTask {
		t.Fatalf("a task never opened: %v", rf)
	}
	if rf := r.admits("p2", r.serve("t1"), kernel.TaskTimeout); rf == nil || rf.Code != kernel.CTask {
		t.Fatalf("a task past its timeout: %v", rf)
	}
	if rf := r.admits("p3", r.ck, 1); rf != nil {
		t.Fatalf("a key with no task: %v", rf)
	}
	for name, err := range map[string]error{
		"a second open":          r.k.OpenTask(0, "t1", kernel.TaskTimeout),
		"an empty id":            r.k.OpenTask(0, "", kernel.TaskTimeout),
		"a timeout already past": r.k.OpenTask(5, "t2", 5),
	} {
		if err != kernel.ErrTaskOpen {
			t.Errorf("%s: %v", name, err)
		}
	}
	wrong := approval("t1", r.owner)
	wrong.Site = "other.example"
	for name, a := range map[string]kernel.TaskApproval{
		"a passkey not enrolled": approval("t1", gen(20)),
		"another site":           wrong,
		"another task's":         approval("t9", r.owner),
	} {
		if err := r.k.ApproveTask(0, "t1", a); err != kernel.ErrTaskApproval {
			t.Errorf("%s: %v", name, err)
		}
	}
	forged := approval("t1", r.owner)
	forged.At = -5
	must(t, r.k.ApproveTask(7, "t1", forged))
	if tk, _ := r.k.State().Task("t1", 8); tk.Approval.At != 7 {
		t.Errorf("the approval's time is the log's, not the caller's: %d", tk.Approval.At)
	}
	if err := r.k.ApproveTask(0, "t1", approval("t1", r.spare)); err != kernel.ErrTaskApproval {
		t.Errorf("a second approval: %v", err)
	}
	if err := r.k.ApproveTask(0, "t5", approval("t5", r.owner)); err != kernel.ErrTask {
		t.Errorf("an approval of a task never opened: %v", err)
	}
	must(t, r.k.Stop(1))
	if err := r.k.OpenTask(2, "t6", kernel.TaskTimeout); err != kernel.ErrTaskOpen {
		t.Errorf("an open under STOP: %v", err)
	}
	r.replays()
}

// Each end ends the task and what it holds for good: the view stops
// answering, no new plan may serve it, and a replay agrees.
func TestEachEndEndsTheTask(t *testing.T) {
	for name, end := range map[string]func(*rig) int64{
		"final result": func(r *rig) int64 { must(r.t, r.k.EndTask(1, "t1")); return 2 },
		"stop": func(r *rig) int64 {
			must(r.t, r.k.Stop(1))
			must(r.t, r.k.Resume(2))
			return 3
		},
		"timeout": func(r *rig) int64 { return hour },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			must(t, r.k.OpenTask(0, "t1", hour))
			must(t, r.k.ApproveTask(0, "t1", approval("t1", r.owner)))
			// A revoke of a key the task's plans used ends nothing.
			must(t, r.k.Revoke(0, r.serve("t1", key.LimitUses(1)).Tip()))
			at := end(r)
			if _, ok := r.k.State().Task("t1", at); ok {
				t.Fatal("still live")
			}
			if rf := r.admits("late", r.serve("t1"), at); rf == nil || rf.Code != kernel.CTask {
				t.Fatalf("a plan served an ended task: %v", rf)
			}
			if err := r.k.EndTask(at, "t1"); err != kernel.ErrTask {
				t.Fatalf("an ended task ends again: %v", err)
			}
			r.replays()
		})
	}
}

// Cutting off the passkey that approved a task ends the approval at once;
// the task stays open, and a new approval needs a passkey still enrolled
// (CLK-3, KEY-4).
func TestCuttingOffTheSignerEndsTheApproval(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone.pub)))
	must(t, r.k.OpenTask(0, "t1", hour))
	must(t, r.k.ApproveTask(0, "t1", approval("t1", phone)))
	must(t, r.k.Unenroll(1, gen(21).pub))
	if tk, _ := r.k.State().Task("t1", 1); tk.Approval == nil {
		t.Fatal("cutting off another passkey ended the approval")
	}
	must(t, r.k.Unenroll(2, phone.pub))
	tk, ok := r.k.State().Task("t1", 2)
	if !ok || tk.Approval != nil {
		t.Fatalf("after the cut-off: live %v, approval %v", ok, tk.Approval)
	}
	if err := r.k.ApproveTask(3, "t1", approval("t1", phone)); err != kernel.ErrTaskApproval {
		t.Fatalf("the cut-off passkey approved again: %v", err)
	}
	must(t, r.k.ApproveTask(3, "t1", approval("t1", r.owner)))
	r.replays()
}

// An admitted plan, and its reconciliation, outlive its task: the end stops
// new plans, not the steps already admitted (KRN-8).
func TestAnAdmittedPlanOutlivesItsTask(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", hour))
	r.plan("p1", r.serve("t1", key.LimitHold(hour, hour)), st(key.Unsubscribe, "m1"))
	must(t, r.tick(0))
	must(t, r.k.EndTask(1, "t1"))
	must(t, r.tick(2*hour))
	if r.status("p1") != kernel.SDone {
		t.Fatalf("the admitted plan: %s", r.status("p1"))
	}
}
