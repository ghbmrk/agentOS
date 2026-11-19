package line

// REQ: CLK-2

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A send the clerk is handed with no view, or that its own check refuses
// (here: the log has it in flight nowhere), fails with the check's code and
// reaches no line (CLK-2, #6023).
func TestASendTheCheckRefusesSendsNothing(t *testing.T) {
	r := newRig(t, true)
	p := kernel.SignPlan(kernel.Plan{ID: "c1", Key: r.planner, Steps: []kernel.PlanStep{{Verb: key.Send, Clerk: Name, Args: map[string]string{"to": shopNum, "msg": "hi"}}}}, r.priv)
	for name, v := range map[string]kernel.View{"no view": nil, "not in flight": r.k.State()} {
		if res := r.c.DoContext(context.Background(), kernel.Request{Plan: p}, v); res.Outcome != "failed" || res.Detail != "dispatch" {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if n := len(r.line.texts()); n != 0 {
		t.Fatalf("sent %d", n)
	}
}
