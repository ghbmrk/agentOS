package kernel_test

// REQ: KRN-5, CLK-3, KEY-3, D-147

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const site, first = "shop.example", "https://shop.example/cart"

func approval(id string, n int, by pair) kernel.TaskApproval {
	return kernel.TaskApproval{Site: site, First: first, N: n, By: key.Approve(by.priv, kernel.TaskHash(id, n, site, first))}
}

// serve is a key for task id, narrowed from the clerk's key.
func (r *rig) serve(id string, c ...key.Caveat) key.Key {
	return r.derive(append(c, key.LimitTask(id))...)
}

func (r *rig) replays() {
	r.t.Helper()
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(r.t, err)
	if !reflect.DeepEqual(re, r.k.State()) {
		r.t.Fatal("replay differs from the live state (KRN-1)")
	}
	_, err = kernel.Rederive(r.anchors(), r.k.Log().Entries())
	must(r.t, err)
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
	must(t, r.k.OpenTask(0, "t1"))
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
	if tk, ok := r.k.State().Task("t1", 4); !ok || tk.At != 0 || tk.Until != kernel.TaskTimeout {
		t.Fatalf("a failed, rejected or cancelled plan ended the task, or its times are not the log's: %+v %v", tk, ok)
	}
	r.replays()
}

func TestATaskKeyServesOnlyALiveTask(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
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
		"a second open": r.k.OpenTask(0, "t1"),
		"an empty id":   r.k.OpenTask(0, ""),
	} {
		if err != kernel.ErrTaskOpen {
			t.Errorf("%s: %v", name, err)
		}
	}
	wrong := approval("t1", 0, r.owner)
	wrong.Site = "other.example"
	for name, a := range map[string]kernel.TaskApproval{
		"a passkey not enrolled": approval("t1", 0, gen(20)),
		"another site":           wrong,
		"another task's":         approval("t9", 0, r.owner),
	} {
		if err := r.k.ApproveTask(0, "t1", a); err != kernel.ErrTaskApproval {
			t.Errorf("%s: %v", name, err)
		}
	}
	forged := approval("t1", 0, r.owner)
	forged.At = -5
	must(t, r.k.ApproveTask(7, "t1", forged))
	if tk, _ := r.k.State().Task("t1", 8); tk.Approvals[site].At != 7 {
		t.Errorf("the approval's time is the log's, not the caller's: %d", tk.Approvals[site].At)
	}
	if err := r.k.ApproveTask(0, "t5", approval("t5", 0, r.owner)); err != kernel.ErrTask {
		t.Errorf("an approval of a task never opened: %v", err)
	}
	must(t, r.k.Stop(1))
	if err := r.k.OpenTask(2, "t6"); err != kernel.ErrTaskOpen {
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
		"timeout": func(r *rig) int64 { return kernel.TaskTimeout },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			must(t, r.k.OpenTask(0, "t1"))
			must(t, r.k.ApproveTask(0, "t1", approval("t1", 0, r.owner)))
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
	must(t, r.k.OpenTask(0, "t1"))
	must(t, r.k.ApproveTask(0, "t1", approval("t1", 0, phone)))
	must(t, r.k.Unenroll(1, gen(21).pub))
	if tk, _ := r.k.State().Task("t1", 1); len(tk.Approvals) != 1 {
		t.Fatal("cutting off another passkey ended the approval")
	}
	must(t, r.k.Unenroll(2, phone.pub))
	tk, ok := r.k.State().Task("t1", 2)
	if !ok || len(tk.Approvals) != 0 {
		t.Fatalf("after the cut-off: live %v, approvals %v", ok, tk.Approvals)
	}
	if err := r.k.ApproveTask(3, "t1", approval("t1", 1, phone)); err != kernel.ErrTaskApproval {
		t.Fatalf("the cut-off passkey approved again: %v", err)
	}
	must(t, r.k.ApproveTask(3, "t1", approval("t1", 1, r.owner)))
	r.replays()
}

// An admitted plan, and its reconciliation, outlive its task: the end stops
// new plans, not the steps already admitted (KRN-8).
func TestAnAdmittedPlanOutlivesItsTask(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
	r.plan("p1", r.serve("t1", key.LimitHold(hour, hour)), st(key.Unsubscribe, "m1"))
	must(t, r.tick(0))
	must(t, r.k.EndTask(1, "t1"))
	must(t, r.tick(2*hour))
	if r.status("p1") != kernel.SDone {
		t.Fatalf("the admitted plan: %s", r.status("p1"))
	}
}

// A task approval widens, so it anchors at once: one whose anchor failed
// breaks the log and does not come back after a restart (KRN-7).
func TestAnUnanchoredTaskApprovalDoesNotSurvive(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
	must(t, r.k.Log().Anchor())
	r.anchor.down = true
	if err := r.k.ApproveTask(1, "t1", approval("t1", 0, r.owner)); err == nil {
		t.Fatal("an approval whose anchor failed must be refused")
	}
	r.anchor.down = false
	r.boot(2)
	if tk, ok := r.k.State().Task("t1", 3); !ok || len(tk.Approvals) != 0 {
		t.Fatalf("after restart: live %v, approvals %v", ok, tk.Approvals)
	}
}

// A task holds one approval per site: an approval on another site adds to
// it, and a new one on the same site, as the clerk asks for after a card
// fill, replaces the earlier one (CLK-3).
func TestATaskHoldsOneApprovalPerSite(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone.pub)))
	must(t, r.k.OpenTask(0, "t1"))
	must(t, r.k.ApproveTask(1, "t1", approval("t1", 0, r.owner)))
	other := kernel.TaskApproval{Site: "other.example", First: "https://other.example/"}
	other.N, other.By = 1, key.Approve(r.owner.priv, kernel.TaskHash("t1", 1, other.Site, other.First))
	must(t, r.k.ApproveTask(2, "t1", other))
	must(t, r.k.ApproveTask(3, "t1", approval("t1", 2, phone)))
	tk, _ := r.k.State().Task("t1", 4)
	if len(tk.Approvals) != 2 || tk.Approvals[site].At != 3 || !bytes.Equal(tk.Approvals[site].By.By, phone.pub) || tk.Approvals[other.Site].At != 2 {
		t.Fatalf("approvals %+v", tk.Approvals)
	}
	delete(tk.Approvals, other.Site) // the answer is a copy
	must(t, r.k.Unenroll(5, phone.pub))
	if tk, _ := r.k.State().Task("t1", 6); len(tk.Approvals) != 1 || tk.Approvals[other.Site].At != 2 {
		t.Fatalf("after the cut-off: %+v", tk.Approvals)
	}
	r.replays()
}

// Each approval signs its place in the task, so a co-signature seen once
// cannot be logged again: a replay neither revives a replaced approval nor
// moves its time (CLK-3).
func TestATaskApprovalCannotBeReplayed(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
	a := approval("t1", 0, r.owner)
	must(t, r.k.ApproveTask(1, "t1", a))
	must(t, r.k.ApproveTask(10, "t1", approval("t1", 1, r.spare)))
	again := a
	again.N = 2
	for name, b := range map[string]kernel.TaskApproval{"as logged": a, "renumbered": again, "ahead": approval("t1", 3, r.owner)} {
		if err := r.k.ApproveTask(20, "t1", b); err != kernel.ErrTaskApproval {
			t.Errorf("a replay %s: %v", name, err)
		}
	}
	tk, _ := r.k.State().Task("t1", 21)
	if got := tk.Approvals[site]; got.At != 10 || got.N != 1 || tk.Taps != 2 {
		t.Fatalf("after the replays: %+v, %d taps", got, tk.Taps)
	}
	r.replays()
}

// A task's per-task cap spans its re-plans: a plan's steps and metered calls
// are charged under the task its key serves, not under the plan, and a plan
// for another task has its own (KRN-5, LOG-7, #2902).
func TestATasksSpendCapSpansItsRePlans(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
	must(t, r.k.OpenTask(0, "t2"))
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	serve := func(task string) key.Key {
		s, err := key.Derive(k, r.holder.priv, r.holder.pub, key.LimitTask(task))
		must(t, err)
		return s
	}
	modelPlan(r, "p1", serve("t1"))
	modelPlan(r, "p2", serve("t1"))
	modelPlan(r, "p3", serve("t2"))
	must(t, r.meter(1, "p1", "api", 8, "provider"))
	if rf := r.admit(2, "p2", 3); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("a re-plan started a fresh per-task budget: %v", rf)
	}
	if rf := r.admit(2, "p2", 2); rf != nil {
		t.Fatalf("the task's last 2: %v", rf)
	}
	if rf := r.admit(2, "p3", 10); rf != nil {
		t.Fatalf("another task's budget: %v", rf)
	}
	r.replays()
}

// A plan whose key serves no task is charged as itself, never as a task it
// is named like: the planner chooses plan ids, so a plan named "t1" spends
// none of task t1's budget, and no task opens under the plans' prefix
// (KRN-5, LOG-7, #2927 L3 fix-list 1).
func TestAPlanNamedLikeATaskSpendsNoneOfIt(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	t1, err := key.Derive(k, r.holder.priv, r.holder.pub, key.LimitTask("t1"))
	must(t, err)
	modelPlan(r, "t1", k)
	modelPlan(r, "p2", t1)
	must(t, r.meter(1, "t1", "api", 10, "provider"))
	if rf := r.admit(2, "p2", 10); rf != nil {
		t.Fatalf("a plan named like the task drained it: %v", rf)
	}
	if rf := r.admit(2, "t1", 1); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("the plan's own cap: %v", rf)
	}
	if err := r.k.OpenTask(3, key.PlanPrefix+"t1"); err == nil {
		t.Fatal("a task opened under the plans' prefix")
	}
	r.replays()
}
