package kernel_test

// REQ: KRN-7, KRN-8, OWN-17, OWN-18

import (
	"strings"
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

// A dispatch is checked again just before it goes to its clerk: a STOP,
// revoke or cancel logged since Calls cancels it unsent, and a pause leaves
// it unsent until the key resumes. Nothing reaches the clerk (KRN-7).
func TestADispatchStoppedSinceCallsIsNotSent(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*rig) error
		phase  string
		status string
	}{
		"stop":   {func(r *rig) error { return r.k.Stop(1) }, kernel.PCancelled, kernel.SCancelled},
		"revoke": {func(r *rig) error { return r.k.Revoke(1, r.ck.Tip()) }, kernel.PCancelled, kernel.SCancelled},
		"cancel": {func(r *rig) error { return r.k.Cancel(1, "p1") }, kernel.PCancelled, kernel.SCancelled},
		"pause":  {func(r *rig) error { return r.k.Pause(1, r.ck.Tip()) }, kernel.PUnsent, kernel.SActive},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.plan("p1", r.ck, st(key.Trash, "m1"))
			c := r.calls(1, 1)[0]
			must(t, tc.change(r))
			ok, err := r.k.Send(1, c)
			must(t, err)
			if ok || r.phase("p1").Phase != tc.phase || r.status("p1") != tc.status || len(r.mail.Effects()) != 0 {
				t.Fatalf("sent %v, phase %s, status %s", ok, r.phase("p1").Phase, r.status("p1"))
			}
			n := len(r.k.Log().Entries())
			if ok, err := r.k.Send(1, c); ok || err != nil || len(r.k.Log().Entries()) != n {
				t.Fatalf("a call sent again after its refusal: %v %v", ok, err)
			}
			r.calls(1+kernel.UnsentWait, 0)
			r.replays()
		})
	}
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	ok, err := r.k.Send(1, r.calls(1, 1)[0])
	if err != nil || !ok {
		t.Fatalf("an unchanged dispatch: %v %v", ok, err)
	}
}

// While a step is unsent its effect may still happen once its clerk is back,
// so a second plan with the same irreversible effect is refused (KRN-8).
func TestAnUnsentStepBlocksTheSameEffect(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Answer(1, r.calls(1, 1)[0], kernel.Result{Outcome: kernel.OUnsent}))
	r.plan("p2", r.ck, st(key.Unsubscribe, "list-a"))
	if r.status("p2") != kernel.SRejected {
		t.Fatalf("a second plan for an unsent effect: %s", r.status("p2"))
	}
}

// The wait before an unsent step is sent again doubles at each attempt, up
// to MaxUnsentWait, so a clerk that stays down does not fill the log.
func TestTheUnsentWaitBacksOff(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	at, wait := int64(1), int64(kernel.UnsentWait)
	for i := 0; i < 8; i++ {
		must(t, r.k.Answer(at, r.calls(at, 1)[0], kernel.Result{Outcome: kernel.OUnsent}))
		r.calls(at+wait-1, 0)
		at += wait
		wait = min(2*wait, kernel.MaxUnsentWait)
	}
	if wait != kernel.MaxUnsentWait {
		t.Fatalf("the wait never reached its cap: %d", wait)
	}
	r.replays()
}

// The fold refuses a covered line not shown, whatever the log holds
// (CLK-3): Answer drops one first, so only a raw entry reaches the fold.
func TestTheFoldListsNoLineNotShown(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	c := r.calls(1, 1)[0]
	_, err := r.k.Log().Append(1, kernel.TStepResult, 1, map[string]any{"plan": c.Req.Plan.ID, "index": c.Req.Index,
		"idem": kernel.Idem(c.Req.Plan.ID, c.Req.Index), "outcome": "ok", "covered": "bad\nline"})
	must(t, err)
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if p := re.Plans["p1"]; p.Steps[0].Phase != kernel.PDone || len(re.Covered(1)) != 0 {
		t.Fatalf("a logged line not shown was listed: %+v", re.Covered(1))
	}
}

// STATUS lists each covered submit once sent, in the clerk's fixed wording,
// for as long as a task approval lives; a line the owner could not be shown
// as one line is not listed (CLK-3, #2705).
func TestStatusListsCoveredSubmits(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"), st(key.Trash, "m2"))
	r.plan("p2", r.ck, st(key.Trash, "m3"))
	r.plan("p3", r.ck, st(key.Trash, "m4"))
	r.plan("p4", r.ck, st(key.Trash, "m5"))
	r.plan("p5", r.ck, st(key.Trash, "m6"))
	lines := map[string]string{"m1": "Sent on shop.example: Continue, 00:00 UTC", "m2": "Sent on shop.example: Place order, 00:01 UTC",
		"m3": "Sent on other.example: Pay, 00:00 UTC", "m4": "bad\nline", "m5": strings.Repeat("x", kernel.MaxShown+1),
		"m6": "Sent on shop.example: \u202eyaP"}
	for at := int64(1); at <= 3; at++ {
		cs, err := r.k.Calls(at)
		must(t, err)
		for _, c := range cs {
			var id string
			for _, v := range c.Req.Step().Args {
				id = v.Value
			}
			must(t, r.k.Answer(at, c, kernel.Result{Outcome: "ok", Covered: lines[id]}))
		}
	}
	got := r.k.State().Covered(3)
	if len(got) != 3 || got[0].Line != lines["m1"] || got[1].Line != lines["m3"] || got[2].Line != lines["m2"] || got[0].Clerk != "mail" {
		t.Fatalf("covered %+v", got)
	}
	if n := len(r.k.State().Covered(got[2].At + kernel.TaskTimeout)); n != 0 {
		t.Fatalf("%d lines listed past a task approval's life", n)
	}
	for _, e := range r.k.Log().Entries() { // a line not shown is not logged either
		if strings.Contains(string(e.Body), lines["m5"]) {
			t.Fatal("an overlong line reached the log")
		}
	}
	r.replays()
}
