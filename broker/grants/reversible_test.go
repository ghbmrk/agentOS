package grants

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/reversible"
)

// REQ: REV-3, CH-16, REV-2

// hold does what the owner channel does when the owner approves an item
// with an undo window: it queues the hold and returns the decision.
func (f *fakeOwner) hold(req string, item int, it owner.Item) owner.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := owner.Queued{ID: fmt.Sprintf("H%d", len(f.due)+len(f.queued)+1), SendAt: f.now().Add(it.UndoWindow),
		Reply: owner.AutoReply{Ref: it.Ref}, Held: true}
	f.due = append(f.due, q)
	return owner.Decision{Request: req, Item: item, Ref: it.Ref, Approved: true, Why: "owner", Hold: q.ID, Until: q.SendAt}
}

// approveHeld approves the newest request; every item with an undo
// window is held, as the owner channel does. It returns the hold IDs.
func (r *rig) approveHeld() []string {
	r.t.Helper()
	req, items := r.own.last(r.t)
	var ids []string
	for i, it := range items {
		d := owner.Decision{Request: req, Item: i + 1, Ref: it.Ref, Approved: true, Why: "owner"}
		if it.UndoWindow > 0 {
			d = r.own.hold(req, i+1, it)
			ids = append(ids, d.Hold)
		}
		r.g.Decide(d)
	}
	r.g.Wait()
	return ids
}

func withForms(forms map[string]reversible.Form) func(*Config) {
	return func(c *Config) {
		c.Declared["mail"]["draft.discard"] = "draft"
		c.Forms = map[string]map[string]reversible.Form{"mail": forms}
	}
}

// TestApprovedEffectRunsOnlyAfterItsUndoWindow: an irreversible operation
// whose adapter declares a delay form is asked with its undo window
// stated; once approved it is held, not run, and the guest is told until
// when; it runs when the owner channel releases it after the window.
func TestApprovedEffectRunsOnlyAfterItsUndoWindow(t *testing.T) {
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": {}}))
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	st := r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	if st.State != journal.Pending {
		t.Fatalf("not asked: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	if _, items := r.own.last(t); items[0].UndoWindow != reversible.DefaultWindow {
		t.Fatalf("approval item shows no undo window: %+v", items[0])
	}
	r.approveHeld()
	st = r.state("agent/s1")
	if st.State != journal.Pending || st.Permission.Reason != "approved; held for the owner's undo window until 09:10 UTC" || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("held: %s %q, ran %d", st.State, st.Permission.Reason, r.exec.runs("agent/s1"))
	}
	// The guest cannot run it early, and asking again asks nothing.
	if st, _ := r.g.Authorize(context.Background(), "agent/s1"); st.State != journal.Pending {
		t.Fatalf("authorize during hold: %s", st.State)
	}
	if _, err := r.g.Dispatch(context.Background(), "agent/s1"); err == nil || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("dispatch during hold: %v", err)
	}
	r.advance(9 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	if r.exec.runs("agent/s1") != 0 {
		t.Fatal("ran inside the undo window")
	}
	r.advance(time.Minute)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("agent/s1"); st.State != journal.Succeeded || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("released: %s %q", st.State, st.Permission.Reason)
	}
}

// TestUndoCancelsAHeldEffect: UNDO inside the window closes the intent
// as denied and nothing runs, and a restart does the same.
func TestUndoCancelsAHeldEffect(t *testing.T) {
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": {}}))
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	h := r.approveHeld()
	r.g.Decide(owner.Decision{Request: h[0], Item: 1, Ref: "agent/s1", Why: "undo"})
	r.g.Wait()
	if st := r.state("agent/s1"); st.State != journal.Denied || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("undone: %s", st.State)
	}

	// Held across a restart: the owner channel's Boot cancels it.
	r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	h = r.approveHeld()
	r.open()
	if st := r.state("agent/s2"); st.State != journal.Pending {
		t.Fatalf("after restart: %s", st.State)
	}
	r.g.Decide(owner.Decision{Request: h[0], Item: 1, Ref: "agent/s2", Why: "restart"})
	r.g.Wait()
	if st := r.state("agent/s2"); st.State != journal.Denied || r.exec.runs("agent/s2") != 0 {
		t.Fatalf("restart: %s", st.State)
	}
}

// TestStagedEffectIsStagedAtApprovalAndUnstagedOnUndo: an operation with
// a stage form (send as a draft first) runs the stage as soon as the owner
// approves; at the window's end the operation itself runs and nothing is
// unstaged; on UNDO the inverse runs with the stage's evidence.
func TestStagedEffectIsStagedAtApprovalAndUnstagedOnUndo(t *testing.T) {
	form := reversible.Form{Stage: "draft.save", Inverse: "draft.discard"}
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": form}))
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())

	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.approveHeld()
	st := r.state("agent/s1/stage")
	if st.State != journal.Succeeded || st.Intent.Action != "draft.save" || st.Intent.Origin != reversible.Origin ||
		r.exec.params["agent/s1/stage"][reversible.ParamParent] != "agent/s1" || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("stage: %s %+v", st.State, st.Intent)
	}
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("agent/s1"); st.State != journal.Succeeded {
		t.Fatalf("released: %s", st.State)
	}
	if _, err := r.g.Get("agent/s1/unstage"); err == nil {
		t.Fatal("unstaged a released effect")
	}

	r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	h := r.approveHeld()
	r.g.Decide(owner.Decision{Request: h[0], Item: 1, Ref: "agent/s2", Why: "undo"})
	r.g.Wait()
	st = r.state("agent/s2/unstage")
	if st.State != journal.Succeeded || st.Intent.Action != "draft.discard" ||
		r.exec.params["agent/s2/unstage"][reversible.ParamStaged] != "done:agent/s2/stage" || r.exec.runs("agent/s2") != 0 {
		t.Fatalf("unstage: %s %+v", st.State, st.Intent)
	}
	if st := r.state("agent/s2"); st.State != journal.Denied {
		t.Fatalf("undone parent: %s", st.State)
	}
	if len(r.own.notes) != 1 {
		t.Fatalf("a clean unstage texted the owner: %q", r.own.notes)
	}
}

// TestUnstageThatFindsChangesLeavesThemAndSaysSo: an inverse the adapter
// does not apply (the draft changed since, say) leaves the staged copy and the
// owner is told in fixed wording; a stage that failed is never unstaged,
// and its effect still runs after the window as the owner approved.
func TestUnstageThatFindsChangesLeavesThemAndSaysSo(t *testing.T) {
	form := reversible.Form{Stage: "draft.save", Inverse: "draft.discard"}
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": form}))
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.exec.fail = map[string]bool{"agent/s1/unstage": true, "agent/s2/stage": true}

	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	h := r.approveHeld()
	r.g.Decide(owner.Decision{Request: h[0], Item: 1, Ref: "agent/s1", Why: "undo"})
	r.g.Wait()
	if st := r.state("agent/s1/unstage"); st.State != journal.NotApplied {
		t.Fatalf("unstage: %s", st.State)
	}
	if n := r.own.notes; len(n) != 2 || n[1] != "UNDO "+h[0]+": it did not run, but its draft or staged copy could not be removed, so it was left as is." {
		t.Fatalf("notes %q", r.own.notes)
	}

	r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.approveHeld()
	if st := r.state("agent/s2/stage"); st.State != journal.NotApplied {
		t.Fatalf("failed stage: %s", st.State)
	}
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("agent/s2"); st.State != journal.Succeeded {
		t.Fatalf("effect after a failed stage: %s", st.State)
	}
}

// TestDerivedIntentsComeOnlyFromTheGate: an intent that claims the
// broker's derived origin but was not submitted by the gate for a held
// effect is denied, whatever its params say; so is a guest intent naming
// a parent. The stage and inverse need no grant of their own: the owner
// approved the effect they belong to.
func TestDerivedIntentsComeOnlyFromTheGate(t *testing.T) {
	form := reversible.Form{Stage: "draft.save", Inverse: "draft.discard"}
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": form}))
	s := mailGrant()
	delete(s.Ops, "draft.save")
	r.grant(s)
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()

	// Before any hold: a forged stage, and a forged inverse.
	p, _ := r.g.Get("agent/s1")
	for _, in := range []journal.Intent{reversible.Stage(p.Intent, form), reversible.Inverse(p.Intent, form, "x")} {
		if st := r.submit(in); st.State != journal.Denied || r.exec.runs(in.ID) != 0 {
			t.Fatalf("forged %s: %s", in.ID, st.State)
		}
	}

	r.effect("agent/s3", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.approveHeld()
	if st := r.state("agent/s3/stage"); st.State != journal.Succeeded {
		t.Fatalf("stage without a draft grant: %s %q", st.State, st.Permission.Reason)
	}
	// A guest naming the held parent gets nothing new: draft.save is not
	// granted to it.
	st := r.effect("agent/x", "draft.save", map[string]any{"record": "inv-1042", reversible.ParamParent: "agent/s3"})
	if st.State != journal.Denied {
		t.Fatalf("guest stage: %s", st.State)
	}
}

// TestFormsNeverReachPreAllowancesSecretsOrBadDeclarations: a
// pre-allowed effect runs at once with no hold (ADP-9: without
// notification); a secret is never held; an invalid form is dropped, so
// its operation is asked with no undo window; and a verifier's undo
// window is not trusted.
func TestFormsNeverReachPreAllowancesSecretsOrBadDeclarations(t *testing.T) {
	var logs []string
	r := newRig(t, func(c *Config) {
		withForms(map[string]reversible.Form{"invoice.send": {}, "key.create": {}, "message.send": {Stage: "draft.save"}})(c)
		c.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	})
	if len(logs) != 2 || !strings.Contains(strings.Join(logs, "\n"), "key.create") || !strings.Contains(strings.Join(logs, "\n"), "message.send") {
		t.Fatalf("invalid forms not logged: %q", logs)
	}
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{}, AmountCap: 50000, PerRecord: 1, PerDay: 5}})
	r.ver.set("inv-1042", sam())
	if st := r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("pre-allowed: %s %q", st.State, st.Permission.Reason)
	}

	v := sam()
	v.Item.UndoWindow = 5 * time.Minute
	v.Record = "msg-1"
	r.ver.set("msg-1", v)
	r.effect("agent/m1", "message.send", map[string]any{"record": "msg-1"}, "sam@example.com")
	r.effect("agent/k1", "key.create", map[string]any{"record": "msg-1"})
	r.g.Flush()
	for _, id := range []string{"agent/m1", "agent/k1"} {
		var it *owner.Item
		for _, req := range r.own.order {
			for _, x := range r.own.reqs[req] {
				if x.Ref == id {
					x := x
					it = &x
				}
			}
		}
		if it == nil || it.UndoWindow != 0 {
			t.Fatalf("%s item: %+v", id, it)
		}
	}
}
