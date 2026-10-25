package guest

// SR2-3j: what the kernel's seam answers reaches the guest only as fixed
// text; its detail goes to a broker-log line (PLN-4).
//
// REQ: RES-4, CAP-8, OP-2, PLN-4

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// denialCanary is a synthetic host path; it is no real path on any box.
const denialCanary = "/var/lib/agentos-canary-7f3a/kernel.sock"

// brokenKernel fails every call with text naming the canary.
type brokenKernel struct{}

func (brokenKernel) Submit(context.Context, kernel.Plan) error {
	return errors.New("dial " + denialCanary)
}

func (brokenKernel) Plan(context.Context, string) (string, []string, bool, error) {
	return "", nil, false, errors.New("dial " + denialCanary)
}

func TestKernelFailuresReachTheGuestOnlyAsFixedText(t *testing.T) {
	var logged []string
	r := newRig(t, func(c *Config) {
		c.Kernel = brokenKernel{}
		c.Logf = func(f string, a ...any) { logged = append(logged, strings.TrimSpace(f)) }
	})
	st, e := r.tool("m1", "plan", send("r1"))
	if e != "" || st.State != "unknown" || st.Reason != reasonLost || strings.Contains(st.Reason, "canary") {
		t.Fatalf("%+v %q", st, e)
	}
	if len(logged) == 0 {
		t.Fatal("the broker's log has no line for the failure")
	}
}

// A plan the kernel's key check rejects says so in fixed words, and no step
// runs (PLN-4): here a verb the machine's key does not reach.
func TestPLN4ARejectedPlanSaysSoAndRunsNothing(t *testing.T) {
	r := newRig(t, nil)
	a := send("r-send")
	a["steps"].([]map[string]any)[0]["verb"] = "send"
	a["steps"].([]map[string]any)[0]["args"] = map[string]string{"to": "a@example.test", "msg": "hi"}
	st, e := r.tool("m1", "plan", a)
	if e != "" || st.State != kernel.SRejected || st.Reason != reasonRejected || r.kern.ran("m1/r-send") != 0 {
		t.Fatalf("%+v %q", st, e)
	}
}

// R16 (OP-2): under STOP the kernel takes a plan and rejects it, so nothing
// runs; after RESUME a new request_id runs (PLN-4: a rejected plan is not
// tried again).
func TestOP2APlanUnderStopRunsNothing(t *testing.T) {
	r := newRig(t, nil)
	r.kern.stop()
	st, e := r.tool("m1", "plan", send("r-held"))
	if e != "" || st.State != kernel.SRejected || r.kern.ran("m1/r-held") != 0 {
		t.Fatalf("under STOP: %+v %q", st, e)
	}
	r.kern.resume()
	if st, e := r.tool("m1", "plan", send("r-held")); e != "" || st.State != kernel.SRejected {
		t.Fatalf("a repeat after RESUME: %+v %q", st, e)
	}
	if st, e := r.tool("m1", "plan", send("r-after")); e != "" || st.State != kernel.SDone || r.kern.ran("m1/r-after") != 1 {
		t.Fatalf("after RESUME: %+v %q", st, e)
	}
}
