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

func approval(id string, n int, by pair) kernel.TaskApproval {
	return kernel.TaskApproval{Site: site, First: first, N: n, By: key.Approve(by.pass, kernel.TaskHash(id, n, site, first))}
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
	_, err = kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries())
	must(r.t, err)
}

func (r *rig) admits(id string, k key.Key, at int64) *kernel.Refusal {
	p := r.sign(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{st(key.Trash, id)}})
	_, _, rf := kernel.Admit(r.k.State(), p, at)
	return rf
}

// A task's plans and re-plans run under keys that carry it: a failed plan,
// a rejected one or a cancel leaves the task open for the next (KRN-5).
func TestATaskRunsItsPlansAndRePlans(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
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
	must(t, r.k.OpenTask(0, "t1", 0))
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
		"a second open": r.k.OpenTask(0, "t1", 0),
		"an empty id":   r.k.OpenTask(0, "", 0),
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
	if err := r.k.OpenTask(2, "t6", 0); err != kernel.ErrTaskOpen {
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
			must(r.t, r.k.Resume(2, r.k.State().Stops))
			return 3
		},
		"timeout": func(r *rig) int64 { return kernel.TaskTimeout },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			must(t, r.k.OpenTask(0, "t1", 0))
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
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	must(t, r.k.OpenTask(0, "t1", 0))
	must(t, r.k.ApproveTask(0, "t1", approval("t1", 0, phone)))
	must(t, r.k.Unenroll(1, key.Unenroll(r.owner.pass, gen(21).pk)))
	if tk, _ := r.k.State().Task("t1", 1); len(tk.Approvals) != 1 {
		t.Fatal("cutting off another passkey ended the approval")
	}
	must(t, r.k.Unenroll(2, key.Unenroll(r.owner.pass, phone.pk)))
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

// What is bound to a task ends with it: its end cancels a held step of its
// plans in the end's own fold (KRN-5). A step already sent still reconciles,
// and the owner may still RETRY a parked one (KRN-8), but no other step of
// that plan is sent.
func TestATasksEndCancelsItsPlansUnsentSteps(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	r.plan("p1", r.serve("t1", key.LimitHold(hour, hour)), st(key.Unsubscribe, "m1"))
	must(t, r.tick(0))
	must(t, r.k.EndTask(1, "t1"))
	if p := r.k.State().Plans["p1"]; p.Status != kernel.SCancelled || p.Cancel != kernel.CTask {
		t.Fatalf("the held plan at the end's fold: %s %s", p.Status, p.Cancel)
	}
	must(t, r.tick(2*hour))
	if len(r.mail.Effects()) != 0 {
		t.Fatal("a held step outlived its task")
	}
	r.replays()
}

// A task approval widens, so it anchors at once: one whose anchor failed
// breaks the log and does not come back after a restart (KRN-7).
func TestAnUnanchoredTaskApprovalDoesNotSurvive(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
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
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	must(t, r.k.OpenTask(0, "t1", 0))
	must(t, r.k.ApproveTask(1, "t1", approval("t1", 0, r.owner)))
	other := kernel.TaskApproval{Site: "other.example", First: "https://other.example/"}
	other.N, other.By = 1, key.Approve(r.owner.pass, kernel.TaskHash("t1", 1, other.Site, other.First))
	must(t, r.k.ApproveTask(2, "t1", other))
	must(t, r.k.ApproveTask(3, "t1", approval("t1", 2, phone)))
	tk, _ := r.k.State().Task("t1", 4)
	if len(tk.Approvals) != 2 || tk.Approvals[site].At != 3 || tk.Approvals[site].By.By != phone.pk || tk.Approvals[other.Site].At != 2 {
		t.Fatalf("approvals %+v", tk.Approvals)
	}
	delete(tk.Approvals, other.Site) // the answer is a copy
	must(t, r.k.Unenroll(5, key.Unenroll(r.owner.pass, phone.pk)))
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
	must(t, r.k.OpenTask(0, "t1", 0))
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
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	must(t, r.k.OpenTask(0, "t1", 0))
	must(t, r.k.OpenTask(0, "t2", 0))
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
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	must(t, r.k.OpenTask(0, "t1", 0))
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
	if err := r.k.OpenTask(3, key.PlanPrefix+"t1", 0); err == nil {
		t.Fatal("a task opened under the plans' prefix")
	}
	r.replays()
}

// A task ends once Latest reaches its timeout: a plan under it is refused,
// EndTask finds it ended, and the scheduler logs its end, which Rederive
// derives from the entry's Latest (TIM-1, KRN-5).
// REQ: TIM-1, KRN-5
func TestTIM1ATaskEndsOnLatest(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	must(t, r.k.OpenTask(0, "t2", 0))
	span(r, kernel.TaskTimeout-hour, kernel.TaskTimeout)
	r.plan("p1", r.serve("t1"), st(key.Trash, "m1"))
	if p := r.k.State().Plans["p1"]; p.Status != kernel.SRejected || p.Reject != kernel.CTask {
		t.Fatalf("a plan under a task past its timeout by Latest: %s %s", p.Status, p.Reject)
	}
	if err := r.k.EndTask(0, "t2"); !errors.Is(err, kernel.ErrTask) {
		t.Fatalf("EndTask of a task past its timeout by Latest: %v", err)
	}
	must(t, r.tick(kernel.TaskTimeout-hour))
	n := 0
	for _, e := range r.k.Log().Entries() {
		if e.Type == kernel.TTaskEnded {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d tasks ended by the scheduler, want 2", n)
	}
	r.replays()
	if rd, _ := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries()); rd.Checked[kernel.TTaskEnded] != 2 {
		t.Fatalf("Rederive checked %d ends as the scheduler's, want 2", rd.Checked[kernel.TTaskEnded])
	}
}

// A task's step is sent only while Latest is short of the task's timeout:
// Send refuses one at a reading whose Latest reached it, and Rederive finds
// a dispatch logged with such a Latest (TIM-1, KRN-5).
// REQ: TIM-1, KRN-5
func TestTIM1ATaskStepsStopOnLatest(t *testing.T) {
	const end = kernel.TaskTimeout
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	span(r, end-hour, end-hour)
	r.plan("p1", r.serve("t1"), st(key.Organize, "a"))
	cs := r.calls(0, 1)
	span(r, end-hour, end)
	if ok, err := r.k.Send(0, cs[0]); err != nil || ok {
		t.Fatalf("a step sent once Latest reached its task's timeout: %v, %v", ok, err)
	}
	if p := r.k.State().Plans["p1"]; p.Status != kernel.SCancelled || p.Cancel != kernel.CTask {
		t.Fatalf("p1: %s %s, want cancelled with its task", p.Status, p.Cancel)
	}
	r.replays()

	r = newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	span(r, end-1, end-1)
	r.plan("p1", r.serve("t1"), st(key.Organize, "a"))
	must(t, r.tick(0))
	if r.status("p1") != kernel.SDone {
		t.Fatalf("p1: %s", r.status("p1"))
	}
	bad := append([]kernel.Entry(nil), r.k.Log().Entries()...)
	i := len(bad) - 1
	for bad[i].Type != kernel.TStepDispatch {
		i--
	}
	late := end
	bad[i].Late = &late
	var d *kernel.Divergence
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), bad); !errors.As(err, &d) || d.Seq != bad[i].Seq {
		t.Fatalf("a dispatch logged with a Latest at its task's timeout: want a divergence at seq %d, got %v", bad[i].Seq, err)
	}
}

// A dispatched step's spend and a completed effect's repeat line both run a
// day from the reading's Latest, whether the answer came at once or a probe
// found the effect done (TIM-1, KRN-8).
//
// REQ: TIM-1, KRN-8, KEY-3
func TestTIM1AStepUseAgesFromLatest(t *testing.T) {
	r := newRig(t)
	buy := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "w3"}), 100)
	var now kernel.Reading
	r.k.UseClock(func() kernel.Reading { return now })
	at := func(e, l int64) int64 { now = kernel.Reading{Earliest: e, Latest: l}; return e }
	shop := func(id, amount string) kernel.Plan {
		s := st(key.Buy, "shop")
		s.Args["amount"] = amount
		return r.sign(kernel.Plan{ID: id, Key: buy, Steps: []kernel.PlanStep{s}})
	}
	must(t, r.k.Submit(at(0, 0), shop("a", "60")))
	must(t, r.tick(at(0, 0)))
	must(t, r.tick(at(hour, 2*hour)))
	if len(r.mail.Effects()) != 1 {
		t.Fatalf("%d effects, want the held buy sent at 1 h", len(r.mail.Effects()))
	}
	end := 2*hour + key.DayMS
	must(t, r.k.Submit(at(end-1, end-1+hour), shop("bw", "50")))
	if r.status("bw") != kernel.SRejected {
		t.Fatalf("bw: %s; a day's spend counts back from Earliest, not Latest", r.status("bw"))
	}
	must(t, r.k.Submit(at(end-1, end-1), shop("b", "50")))
	if r.status("b") != kernel.SRejected {
		t.Fatalf("b: %s; a spend sent on [1 h, 2 h] aged out of its day before Latest + a day", r.status("b"))
	}
	must(t, r.k.Submit(at(end, end), shop("c", "50")))
	if r.status("c") != kernel.SActive {
		t.Fatalf("c: %s; the spend ages out a day after Latest", r.status("c"))
	}

	for _, lost := range []bool{false, true} {
		r := newRig(t)
		r.k.UseClock(func() kernel.Reading { return now })
		if lost {
			r.mail.Fault = func(op string, _ kernel.Request) string {
				if op == "do" {
					return clerk.FaultLostAck
				}
				return ""
			}
		}
		must(t, r.k.Submit(at(0, 0), r.sign(kernel.Plan{ID: "p1", Key: r.ck, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-a")}})))
		done := int64(0)
		if lost {
			must(t, r.tick(at(0, 0)))
		}
		if lost {
			done = kernel.ProbeEvery
		}
		must(t, r.tick(at(done, done+hour)))
		if r.status("p1") != kernel.SDone {
			t.Fatalf("lost %v: p1 %s", lost, r.status("p1"))
		}
		end := done + hour + key.DayMS
		must(t, r.k.Submit(at(end-1, end-1+hour), r.sign(kernel.Plan{ID: "p2w", Key: r.ck, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-a")}})))
		if r.status("p2w") != kernel.SRejected {
			t.Fatalf("lost %v: p2w %s; the repeat line counts back from Earliest", lost, r.status("p2w"))
		}
		must(t, r.k.Submit(at(end-1, end-1), r.sign(kernel.Plan{ID: "p2", Key: r.ck, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-a")}})))
		if r.status("p2") != kernel.SRejected {
			t.Fatalf("lost %v: p2 %s; an effect done on [%d, %d] repeats before Latest + a day", lost, r.status("p2"), done, done+hour)
		}
		must(t, r.k.Submit(at(end, end), r.sign(kernel.Plan{ID: "p3", Key: r.ck, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-a")}})))
		if r.status("p3") != kernel.SActive {
			t.Fatalf("lost %v: p3 %s; the repeat line ends a day after Latest", lost, r.status("p3"))
		}
	}
}

// A task takes an approval only while it is live on the reading's Latest,
// where its timeout fires (KRN-5, #5395): a reading whose Earliest is short
// of the timeout and whose Latest is past it refuses, live and in the fold.
// Mutant: approve on now.Earliest in ApproveTask and the late approval logs;
// fold it on e.At and the forged one folds.
func TestATaskApprovalNeedsTheTaskLiveOnLatest(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", 0))
	r.k.UseClock(func() kernel.Reading {
		return kernel.Reading{Earliest: kernel.TaskTimeout - 30, Latest: kernel.TaskTimeout - 1}
	})
	must(t, r.k.ApproveTask(0, "t1", approval("t1", 0, r.owner)))
	r.k.UseClock(func() kernel.Reading {
		return kernel.Reading{Earliest: kernel.TaskTimeout - 20, Latest: kernel.TaskTimeout}
	})
	n := r.k.Log().Len()
	if err := r.k.ApproveTask(0, "t1", approval("t1", 1, r.owner)); !errors.Is(err, kernel.ErrTask) {
		t.Fatalf("an approval past the timeout on Latest: %v", err)
	}
	if r.k.Log().Len() != n {
		t.Fatal("a refused approval was logged")
	}
	r.replays()
	late := kernel.TaskTimeout + 10
	forged := entryAt(t, uint64(n+1), kernel.TaskTimeout-20, kernel.TTaskApproved, map[string]any{"task": "t1", "approval": approval("t1", 1, r.owner)})
	forged.Late = &late
	es := r.k.Log().Entries()
	st, err := kernel.Replay(r.anchors(), append(es[:len(es):len(es)], forged))
	must(t, err)
	if tk, _ := st.Task("t1", kernel.TaskTimeout-20); tk.Taps != 1 {
		t.Fatalf("an approval logged past the timeout on Latest folded: %d taps", tk.Taps)
	}
}
