package kernel_test

// REQ: PLN-4, EVL-3, HLD-5

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// logged is the plan.rejected entry for plan id, with its index in the log.
func (r *rig) logged(id string) (int, map[string]json.RawMessage) {
	r.t.Helper()
	for i, e := range r.k.Log().Entries() {
		var b map[string]json.RawMessage
		if e.Type == kernel.TPlanRejected && json.Unmarshal(e.Body, &b) == nil && string(b["plan"]) == `"`+id+`"` {
			return i, b
		}
	}
	r.t.Fatalf("no rejection logged for %s", id)
	return 0, nil
}

// A rejected plan is logged with its session and its failing step, beside
// the failing check and the submission that binds its hash, so a session's
// rejections can be read as a signal (PLN-4, EVL-3, HLD-5). A plan that fails
// whole names no step; a key that serves no task names no session.
func TestARejectionNamesItsSessionAndStep(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
	r.plan("step1", r.serve("t1"), st(key.Trash, "m1"), st(key.Send, "m2"), st(key.Trash, "m3"))
	r.plan("whole", r.serve("t2"), st(key.Trash, "m1"))
	r.plan("step0", r.ck, st(key.Send, "m1"))
	r.plan("unknown", r.ck, st(key.Trash, "m1"), st("nope", "m2"))
	r.plan("twice", r.ck, st(key.Unsubscribe, "list-a"), st(key.Unsubscribe, "list-a"))
	for _, tc := range []struct {
		plan, code, session, step string
		at                        *int
	}{
		{"step1", key.RVerb, `"t1"`, "1", ptr(1)},
		{"whole", kernel.CTask, `"t2"`, "", nil},
		{"step0", key.RVerb, "", "0", ptr(0)},
		{"unknown", kernel.CPlan, "", "1", ptr(1)},
		{"twice", kernel.CDuplicate, "", "1", ptr(1)},
	} {
		_, b := r.logged(tc.plan)
		if string(b["code"]) != `"`+tc.code+`"` || string(b["session"]) != tc.session || string(b["step"]) != tc.step {
			t.Errorf("%s: logged code %s session %s step %s, want %s %s %s", tc.plan, b["code"], b["session"], b["step"], tc.code, tc.session, tc.step)
		}
		if got := r.k.State().Plans[tc.plan].RejectStep; (got == nil) != (tc.at == nil) || got != nil && *got != *tc.at {
			t.Errorf("%s: folded step %v, want %v", tc.plan, got, tc.at)
		}
	}
	_, _, rf := kernel.Admit(r.k.State(), r.sign(kernel.Plan{ID: "again", Key: r.serve("t1"), Steps: []kernel.PlanStep{st(key.Trash, "m4"), st(key.Send, "m5")}}), 1)
	if rf == nil || rf.Step == nil || *rf.Step != 1 {
		t.Fatalf("Admit must name the failing step: %+v", rf)
	}
	r.replays()
}

// A rejection's session and step are derived again on replay: a log that
// moves the step, drops the session or names another one diverges (KRN-1).
func TestARejectionsSessionAndStepAreRederived(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1"))
	r.plan("bad", r.serve("t1"), st(key.Trash, "m1"), st(key.Send, "m2"))
	i, _ := r.logged("bad")
	es := r.k.Log().Entries()
	for name, edit := range map[string]func(map[string]any){
		"step moved":      func(m map[string]any) { m["step"] = 0 },
		"step dropped":    func(m map[string]any) { delete(m, "step") },
		"session dropped": func(m map[string]any) { delete(m, "session") },
		"session changed": func(m map[string]any) { m["session"] = "t2" },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			must(t, json.Unmarshal(es[i].Body, &m))
			edit(m)
			bad := append([]kernel.Entry(nil), es...)
			b, err := json.Marshal(m)
			must(t, err)
			bad[i].Body = b
			_, err = kernel.Rederive(r.anchors(), r.k.Box(), bad)
			var d *kernel.Divergence
			if !errors.As(err, &d) || d.Seq != es[i].Seq {
				t.Fatalf("want a divergence at seq %d, got %v", es[i].Seq, err)
			}
		})
	}
}

func ptr(i int) *int { return &i }
