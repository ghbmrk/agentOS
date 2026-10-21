package kernel_test

// REQ: KRN-7, KRN-8, OWN-17, OWN-18

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func (r *rig) calls(at int64, want int) []kernel.Call {
	r.t.Helper()
	cs, err := r.k.Calls(at)
	must(r.t, err)
	if len(cs) != want {
		r.t.Fatalf("at %d: %d calls, want %d: %+v", at, len(cs), want, cs)
	}
	return cs
}

func (r *rig) phase(id string) kernel.StepState { return r.k.State().Plans[id].Steps[0] }

// A step whose clerk was not reached was not sent: it is listed in STATUS by
// its clerk, sent again after UnsentWait under the same idempotency key, and
// charged once (KRN-7, OWN-17).
func TestAnUnsentStepIsSentAgainAfterItsWait(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	c := r.calls(1, 1)[0]
	if c.Kind != kernel.ActDispatch || c.Clerk != "mail" {
		t.Fatalf("call %+v", c)
	}
	r.calls(1, 0) // handed out once until answered
	must(t, r.k.Answer(1, c, kernel.Result{Outcome: kernel.OUnsent, Detail: "unreachable"}))
	if s := r.k.State().Status(); len(s) != 1 || s[0].Phase != kernel.PUnsent || s[0].Clerk != "mail" || s[0].Retry {
		t.Fatalf("STATUS %+v", s)
	}
	r.calls(kernel.UnsentWait, 0)
	again := r.calls(1+kernel.UnsentWait, 1)[0]
	if again.Req.Idem() != c.Req.Idem() || r.phase("p1").Attempt != 2 {
		t.Fatalf("sent again as %q, attempt %d", again.Req.Idem(), r.phase("p1").Attempt)
	}
	if n := len(r.k.State().Ledger().Uses(r.ck.Tip())); n != 1 {
		t.Fatalf("charged %d times", n)
	}
	must(t, r.k.Answer(2+kernel.UnsentWait, again, kernel.Result{Outcome: "ok"}))
	if r.status("p1") != kernel.SDone {
		t.Fatalf("status %s", r.status("p1"))
	}
	r.replays()
}

// The owner can cancel a step that was never sent.
func TestAnUnsentStepCancels(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.k.Answer(1, r.calls(1, 1)[0], kernel.Result{Outcome: kernel.OUnsent}))
	must(t, r.k.Cancel(2, "p1"))
	if r.phase("p1").Phase != kernel.PCancelled {
		t.Fatalf("phase %s", r.phase("p1").Phase)
	}
	r.calls(1+kernel.UnsentWait, 0)
}

// A probe that could not reach its clerk made no check, so a clerk that is
// down never parks a step (OWN-17, KRN-8).
func TestAnUnreachedProbeCountsNoCheck(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.k.Answer(1, r.calls(1, 1)[0], kernel.Result{Outcome: "unknown"}))
	at := int64(1)
	for i := 0; i < 2*kernel.MaxChecks; i++ {
		at += kernel.ProbeEvery
		p := r.calls(at, 1)[0]
		if p.Kind != kernel.ActProbe {
			t.Fatalf("call %+v", p)
		}
		r.calls(at, 0)
		must(t, r.k.Answer(at, p, kernel.Result{Outcome: kernel.OUnreached}))
	}
	if st := r.phase("p1"); st.Phase != kernel.PUnknown || st.Checks != 0 {
		t.Fatalf("after unreached probes: %+v", st)
	}
	at += kernel.ProbeEvery
	must(t, r.k.Answer(at, r.calls(at, 1)[0], kernel.Result{Outcome: "unknown"}))
	if r.phase("p1").Checks != 1 {
		t.Fatal("a probe that reached the clerk counts")
	}
	r.replays()
}
