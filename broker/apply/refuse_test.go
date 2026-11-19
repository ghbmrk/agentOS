package apply

// REQ: CLK-2, KRN-4

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// A step the clerk's own check refuses fails with the check's code, not a
// later check's, and activates nothing (CLK-2, #6023).
func TestAStepTheCheckRefusesFailsWithItsCode(t *testing.T) {
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	st := Step(r.a.rel)
	st.Clerk = "elsewhere"
	p := kernel.SignPlan(kernel.Plan{ID: "upd:apply:1:n9", Key: r.upkey, Steps: []kernel.PlanStep{st}}, r.holder)
	if res := r.a.Do(kernel.Request{Plan: p}, r.k.State()); res.Outcome != "failed" || res.Detail != "clerk" || len(r.act.installed) != 0 {
		t.Fatalf("%+v, %d installed", res, len(r.act.installed))
	}
}
