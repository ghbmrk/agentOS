package line

// REQ: CLK-2, KRN-8

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// elsewhere is a view no check here reads: the step names another clerk.
type elsewhere struct{ kernel.View }

// A send already sent is answered done, and one handed to the line with its
// answer lost may have been sent, both before any check; a send with no
// view, or one the clerk's own check refuses (here: another clerk's step),
// fails with the check's code and never reaches the line or the account
// (CLK-2, KRN-8, #6023).
func TestASendTheCheckRefusesSendsNothing(t *testing.T) {
	c := &Clerk{cfg: Config{Clock: func() int64 { return 1 }}, steps: map[string]state{}}
	r := kernel.Request{Plan: kernel.Plan{ID: "c1", Steps: []kernel.PlanStep{{Verb: key.Send, Clerk: "elsewhere", Args: map[string]string{"to": "1", "msg": "hi"}}}}}
	for _, tc := range []struct {
		name    string
		was     state
		v       kernel.View
		outcome string
		detail  string
	}{
		{"no view", 0, nil, "failed", "dispatch"},
		{"another clerk's step", 0, elsewhere{}, "failed", "clerk"},
		{"already sent", sent, nil, "ok", "already done"},
		{"answer lost", handed, nil, "unknown", RMaybeSent},
		{"lost twice", maybe, nil, "unknown", RMaybeSent},
	} {
		c.steps[r.Idem()] = tc.was
		if res := c.DoContext(context.Background(), r, tc.v); res.Outcome != tc.outcome || res.Detail != tc.detail {
			t.Errorf("%s: %+v", tc.name, res)
		}
	}
}
