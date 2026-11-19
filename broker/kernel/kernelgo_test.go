package kernel_test

// REQ: KRN-1, KRN-5, KRN-8, LOG-7, KEY-6

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// kgCode is a refusal's code, read from its text ("code: detail").
func kgCode(r *key.Refusal) string {
	if r == nil {
		return ""
	}
	c, _, _ := strings.Cut(r.Error(), ": ")
	return c
}

// kgErrCode is kgCode of the refusal err is, or "" when it is none.
func kgErrCode(err error) string {
	var r *key.Refusal
	if !errors.As(err, &r) {
		return ""
	}
	return kgCode(r)
}

// kgStore is the rig's store with appends that fail once left runs out
// (left < 0 never fails).
type kgStore struct {
	*kernel.MemStore
	left int
}

func (f *kgStore) Append(b []byte) error {
	if f.left == 0 {
		return errors.New("store down")
	}
	f.left--
	return f.MemStore.Append(b)
}

// kgReboot boots r's log again over fs, with c as the mail clerk.
func kgReboot(r *rig, fs *kgStore, c kernel.Clerk) {
	r.t.Helper()
	cf := cfg(r)
	cf.Store = fs
	l, err := kernel.Open(cf)
	must(r.t, err)
	r.k, err = kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{"mail": c}, 0)
	must(r.t, err)
}

// kgHangClerk is the mail clerk whose first call runs hang as it returns.
type kgHangClerk struct {
	*clerk.Mail
	hung  bool
	hang  func()
	calls int
}

func (h *kgHangClerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	h.calls++
	res := h.Mail.Do(r, v)
	if !h.hung {
		h.hung = true
		h.hang()
	}
	return res
}

// kgLostClerk answers every call unknown and every probe unreached, counting
// the probes; past a bound it answers done, so a loop that would not stop
// ends there.
type kgLostClerk struct{ probes int }

func (c *kgLostClerk) Do(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "unknown"}
}

func (c *kgLostClerk) Probe(kernel.Request, kernel.View) kernel.Result {
	c.probes++
	if c.probes > 8*kernel.MaxSteps {
		return kernel.Result{Outcome: "done"}
	}
	return kernel.Result{Outcome: kernel.OUnreached}
}

// A plan of exactly MaxSteps steps is admitted (KRN-5).
func TestKernelGoAPlanOfMaxStepsIsAdmitted(t *testing.T) {
	r := newRig(t)
	steps := make([]kernel.PlanStep, kernel.MaxSteps)
	for i := range steps {
		steps[i] = st(key.Organize, fmt.Sprintf("m%d", i))
	}
	r.plan("full", r.ck, steps...)
	if r.status("full") != kernel.SActive {
		t.Fatalf("a plan of MaxSteps steps: %s %s", r.status("full"), r.k.State().Plans["full"].Reject)
	}
}

// An irreversible step with no hold is admitted at the task's own rung: no
// owner approval is assumed for it (CH-3).
func TestKernelGoAnUnheldIrreversibleStepClaimsNoApproval(t *testing.T) {
	r := newRig(t)
	r.plan("u", r.derive(key.LimitRung(key.P1)), st(key.Unsubscribe, "list-a"))
	if p := r.k.State().Plans["u"]; p.Status != kernel.SRejected || !strings.HasPrefix(fmt.Sprint(p.Reject), "rung") {
		t.Fatalf("an unheld unsubscribe under a rung key: %s %s", p.Status, p.Reject)
	}
}

// Admission counts a plan's earlier steps against its later ones: a key
// with one use admits no plan of two steps (KRN-5).
func TestKernelGoAdmissionChargesThePlansOwnSteps(t *testing.T) {
	r := newRig(t)
	one := r.derive(key.LimitUses(1))
	r.plan("two", one, st(key.Organize, "m1"), st(key.Organize, "m2"))
	if r.status("two") != kernel.SRejected {
		t.Fatalf("two steps under one use: %s", r.status("two"))
	}
	r.plan("one", one, st(key.Organize, "m1"))
	if r.status("one") != kernel.SActive {
		t.Fatalf("one step under one use: %s %s", r.status("one"), r.k.State().Plans["one"].Reject)
	}
}

// Two plans with the same irreversible effect admitted before either ran
// run it once; another root's plan with that effect in flight is no
// duplicate (KRN-8).
func TestKernelGoTheSameEffectRunsOnceUnderOneRoot(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Unsubscribe, "list-a"))
	r.plan("p2", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	if n, p2 := len(r.mail.Effects()), r.k.State().Plans["p2"]; n != 1 || p2.Status != kernel.SCancelled || fmt.Sprint(p2.Cancel) != "duplicate" {
		t.Fatalf("%d effects, p2 %s %s", n, p2.Status, p2.Cancel)
	}

	r = newRig(t)
	other := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Unsubscribe}, Serial: "r2"}), 1<<40)
	r.plan("a", r.ck, st(key.Unsubscribe, "list-a"))
	if cs, err := r.k.Calls(0); err != nil || len(cs) != 1 {
		t.Fatalf("%d calls, %v", len(cs), err)
	}
	r.plan("b", other, st(key.Unsubscribe, "list-a"))
	if r.status("b") != kernel.SActive {
		t.Fatalf("another root's step in flight made b %s %s", r.status("b"), r.k.State().Plans["b"].Reject)
	}
}

// Next waits on a held step until its window ends, and gives an ended plan
// nothing to do (KRN-5).
func TestKernelGoNextWaitsOnAHoldAndIgnoresAnEndedPlan(t *testing.T) {
	r := newRig(t)
	r.plan("h", r.derive(key.LimitHold(hour, hour)), st(key.Unsubscribe, "list-a"))
	cs, err := r.k.Calls(0)
	if err != nil || len(cs) != 0 {
		t.Fatalf("calls at once: %d, %v", len(cs), err)
	}
	st := r.k.State().Plans["h"].Steps[0]
	if st.Phase != kernel.PHeld {
		t.Fatalf("step %s", st.Phase)
	}
	if a := kernel.Next(r.k.State(), "h", 1); a.Kind != kernel.ActNone || a.WakeAt <= 1 {
		t.Fatalf("a held step: %+v", a)
	}
	must(t, r.k.Cancel(2, "h"))
	if a := kernel.Next(r.k.State(), "h", 3*hour); a != (kernel.Act{}) {
		t.Fatalf("a cancelled plan: %+v", a)
	}
}

// Next names when an unsent step may go again, and when an unknown one is
// next probed (KRN-8).
func TestKernelGoNextNamesWhenAWaitingStepIsDue(t *testing.T) {
	r := newRig(t)
	r.plan("p", r.ck, st(key.Organize, "m1"))
	cs, err := r.k.Calls(0)
	must(t, err)
	must(t, r.k.Answer(1, cs[0], kernel.Result{Outcome: kernel.OUnsent}))
	s := r.k.State().Plans["p"].Steps[0]
	if s.Phase != kernel.PUnsent || s.NextProbe <= 2 {
		t.Fatalf("an unsent step: %s at %d", s.Phase, s.NextProbe)
	}
	if a := kernel.Next(r.k.State(), "p", 2); a.Kind != kernel.ActNone || a.WakeAt != s.NextProbe {
		t.Fatalf("an unsent step before its wait ends: %+v, want a wake at %d", a, s.NextProbe)
	}

	r = newRig(t)
	r.plan("p", r.ck, st(key.Organize, "m1"))
	cs, err = r.k.Calls(0)
	must(t, err)
	must(t, r.k.Answer(1, cs[0], kernel.Result{Outcome: "unknown"}))
	s = r.k.State().Plans["p"].Steps[0]
	if s.Phase != kernel.PUnknown || s.NextProbe <= 2 {
		t.Fatalf("an unknown step: %s at %d", s.Phase, s.NextProbe)
	}
	if a := kernel.Next(r.k.State(), "p", 2); a.Kind != kernel.ActNone || a.WakeAt != s.NextProbe {
		t.Fatalf("an unknown step before its probe: %+v, want a wake at %d", a, s.NextProbe)
	}
}

// Next and Send cancel a one-off under a phone's bare root once the phone
// is unenrolled: its plan no longer verifies (D-146, KEY-6).
func TestKernelGoAPlanThatNoLongerVerifiesIsNotSent(t *testing.T) {
	for _, dispatched := range []bool{false, true} {
		r := newRig(t)
		phone := gen(8)
		must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
		root := key.Issue(phone.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Organize}, Serial: "phone"})
		must(t, r.issue(0, root))
		at := kernel.GrantHold + 1
		must(t, r.k.Submit(at, kernel.SignPlan(kernel.Plan{ID: "p", Key: root, Steps: []kernel.PlanStep{st(key.Organize, "m1")}}, phone.priv)))
		if r.status("p") != kernel.SActive {
			t.Fatalf("p: %s %s", r.status("p"), r.k.State().Plans["p"].Reject)
		}
		var cs []kernel.Call
		if dispatched {
			var err error
			cs, err = r.k.Calls(at)
			must(t, err)
		}
		must(t, r.k.Unenroll(at, key.Unenroll(r.owner.pass, phone.pk)))
		if dispatched {
			if ok, err := r.k.Send(at, cs[0]); ok || err != nil {
				t.Fatalf("sent after the phone was unenrolled: %v %v", ok, err)
			}
			if p := r.k.State().Plans["p"]; fmt.Sprint(p.Cancel) != "key" {
				t.Fatalf("the plan was cancelled %q", p.Cancel)
			}
		} else if a := kernel.Next(r.k.State(), "p", at); a.Kind != kernel.ActCancel || kgCode(a.Refusal) != "key" {
			t.Fatalf("next after the phone was unenrolled: %+v", a)
		}
	}
}

// A first attempt is checked against every use logged before it: two plans
// admitted under a key's one use, before either ran, run one (KRN-5).
func TestKernelGoAFirstAttemptCountsEveryEarlierUse(t *testing.T) {
	r := newRig(t)
	one := r.derive(key.LimitUses(1))
	r.plan("p1", one, st(key.Organize, "m1"))
	r.plan("p2", one, st(key.Organize, "m2"))
	if r.status("p2") != kernel.SActive {
		t.Fatalf("p2 was not admitted: %s", r.status("p2"))
	}
	must(t, r.tick(1))
	if n := len(r.mail.Effects()); n != 1 || r.status("p2") != kernel.SCancelled {
		t.Fatalf("%d effects under one use; p2 %s", n, r.status("p2"))
	}
}

// A request outside the plan's steps is the zero step, never a panic.
func TestKernelGoARequestOutsideThePlanIsTheZeroStep(t *testing.T) {
	p := kernel.Plan{ID: "p", Steps: []kernel.PlanStep{st(key.Trash, "m1")}}
	for _, i := range []int{-1, 1} {
		if s := (kernel.Request{Plan: p, Index: i}).Step(); s.Verb != "" || s.Clerk != "" {
			t.Fatalf("index %d: %+v", i, s)
		}
	}
	if s := (kernel.Request{Plan: p, Index: 0}).Step(); s.Verb != key.Trash {
		t.Fatalf("index 0: %+v", s)
	}
}

// Boot reconciles the steps in flight of every plan, past a rejected plan
// that has no steps to reconcile (KRN-8).
func TestKernelGoBootPassesARejectedPlan(t *testing.T) {
	r := newRig(t)
	r.plan("gone", r.derive(key.LimitTask("nope")), st(key.Trash, "m1"))
	if p := r.k.State().Plans["gone"]; p.Status != kernel.SRejected || len(p.Steps) != 0 {
		t.Fatalf("gone: %s with %d steps", p.Status, len(p.Steps))
	}
	r.plan("p", r.ck, st(key.Organize, "m1"))
	_, err := r.k.Calls(0)
	must(t, err)
	r.boot(1)
	if ph := r.k.State().Plans["p"].Steps[0].Phase; ph != kernel.PUnknown {
		t.Fatalf("a step in flight at boot is %s", ph)
	}
}

// fmt prints a kernel as its name only, in every verb (DECOY-b-8).
func TestKernelGoAKernelPrintsAsItsName(t *testing.T) {
	r := newRig(t)
	if got := fmt.Sprintf("%v|%+v|%s|%d", r.k, r.k, *r.k, r.k); got != "kernel|kernel|kernel|kernel" {
		t.Fatalf("printed %q", got)
	}
}

// An entry the log took but the state cannot fold is an error to the
// caller, not a move made (KRN-1).
func TestKernelGoAnEntryThatDoesNotFoldIsAnError(t *testing.T) {
	r := newRig(t)
	s := r.k.State()
	body, err := json.Marshal(map[string]string{"plan": "none", "code": "owner", "detail": ""})
	must(t, err)
	must(t, s.Apply(kernel.Entry{Seq: s.Seq + 1, Type: kernel.TPlanCancel, V: 1, Body: body}))
	if err := r.k.Cancel(1, "none"); !errors.Is(err, kernel.ErrCorrupt) || !strings.Contains(err.Error(), "does not fold") {
		t.Fatalf("an entry the state is past: %v", err)
	}
}

// A metered call is refused when its admission cannot be logged, and a
// broken log admits nothing whatever the caps say (KRN-5).
func TestKernelGoASpendAdmissionNeedsTheLog(t *testing.T) {
	r := newRig(t)
	fs := &kgStore{MemStore: r.store, left: -1}
	kgReboot(r, fs, r.mail)
	modelPlan(r, "p", modelKey(r, "m1", key.LimitSpendTask(10)))
	fs.left = 0
	if a, rf := r.k.AdmitSpend(1, "p", 1); kgCode(rf) != "log-broken" || a != (kernel.Admitted{}) {
		t.Fatalf("an admission the store refused: %+v %v", a, rf)
	}
	fs.left = -1
	if _, rf := r.k.AdmitSpend(1, "p", 11); kgCode(rf) != "log-broken" {
		t.Fatalf("an admission over its cap on a broken log: %v", rf)
	}
}

// A plan whose own key a cut-off passkey narrowed funds no metered call,
// even through an extension still live (KEY-6, LOG-7).
func TestKernelGoAnExtensionDoesNotOutliveTheCitedKey(t *testing.T) {
	r := newRig(t)
	env := envelope(r, 500, 800)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	k, err := key.Narrow(r.derive(key.LimitHold(hour, hour), key.LimitSpendTask(10)), phone.pass, key.LimitUses(5))
	must(t, err)
	r.plan("p", k, st(key.Unsubscribe, "list-a"))
	if r.status("p") != kernel.SActive {
		t.Fatalf("p: %s %s", r.status("p"), r.k.State().Plans["p"].Reject)
	}
	exhaust(r, "p", 10)
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(100)), "p"))
	if _, rf := r.k.AdmitSpend(4, "p", 1); rf != nil {
		t.Fatalf("an extended plan: %v", rf)
	}
	must(t, r.k.Unenroll(5, key.Unenroll(r.owner.pass, phone.pk)))
	if _, rf := r.k.AdmitSpend(6, "p", 1); kgCode(rf) != "cut-off" {
		t.Fatalf("a plan its cut-off narrower approved: %v", rf)
	}
}

// An extension needs a per-task cap of its own: a day cap alone extends
// nothing (LOG-7).
func TestKernelGoAnExtensionNeedsATaskCap(t *testing.T) {
	r := newRig(t)
	env := envelope(r, 500, 800)
	day := modelKey(r, "day", key.LimitSpendDay(50))
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	exhaust(r, "t1", 100)
	if err := r.k.Extend(3, day, "t1"); kgErrCode(err) != "extension" {
		t.Fatalf("an extension with no task cap of its own: %v", err)
	}
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(50)), "t1"))
}

// Tick sends no call its send check refuses, though Next allowed it a
// moment before, and returns the error when that refusal cannot be logged
// (KRN-5).
func TestKernelGoTickSendsNothingItsSendCheckRefuses(t *testing.T) {
	for _, down := range []bool{false, true} {
		r := newRig(t)
		var now int64
		fs := &kgStore{MemStore: r.store, left: -1}
		h := &kgHangClerk{Mail: r.mail, hang: func() {
			now = hour
			if down {
				fs.left = 1 // the hung call's answer is logged, nothing after it
			}
		}}
		kgReboot(r, fs, h)
		r.k.UseClock(func() kernel.Reading { return kernel.At(now) })
		r.plan("first", r.ck, st(key.Organize, "a"))
		r.plan("second", r.derive(key.LimitExpires(hour/2)), st(key.Organize, "b"))
		err := r.k.Tick(0)
		if down != (err != nil) {
			t.Fatalf("store down %v: tick %v", down, err)
		}
		if n := len(r.mail.Effects()); n != 1 || h.calls != 1 {
			t.Fatalf("store down %v: %d effects from %d calls, want only the first plan's", down, n, h.calls)
		}
		if p := r.k.State().Plans["second"]; !down && (p.Steps[0].Phase == kernel.PInflight || p.Status != kernel.SCancelled) {
			t.Fatalf("a refused send left its plan %s, step %s", p.Status, p.Steps[0].Phase)
		}
	}
}

// A hold or a cancel Next decides that cannot be logged stops Calls with
// the error (KRN-5).
func TestKernelGoCallsReturnsAMoveTheLogCannotTake(t *testing.T) {
	for _, hold := range []bool{true, false} {
		r := newRig(t)
		fs := &kgStore{MemStore: r.store, left: -1}
		kgReboot(r, fs, r.mail)
		k := r.derive(key.LimitHold(hour, hour))
		r.plan("p", k, st(key.Unsubscribe, "list-a"))
		if !hold {
			must(t, r.k.Revoke(0, k.Tip()))
		}
		fs.left = 0
		if cs, err := r.k.Calls(0); err == nil || len(cs) != 0 {
			t.Fatalf("hold %v: %d calls, %v", hold, len(cs), err)
		}
	}
}

// A step that can never settle bounds the work of one Tick and one Calls:
// Tick runs exactly 4*MaxSteps rounds against a clerk that is never
// reached, and Calls makes exactly 4*MaxSteps decisions, each on a fresh
// reading, when no clerk the kernel holds can probe the step (KRN-8).
func TestKernelGoAStepThatNeverSettlesBoundsTickAndCalls(t *testing.T) {
	r := newRig(t)
	c := &kgLostClerk{}
	kgReboot(r, &kgStore{MemStore: r.store, left: -1}, c)
	var now int64
	r.k.UseClock(func() kernel.Reading { now += kernel.ProbeEvery; return kernel.At(now) })
	r.plan("p", r.ck, st(key.Organize, "m1"))
	must(t, r.k.Tick(0))
	if c.probes != 4*kernel.MaxSteps-1 {
		t.Fatalf("%d probes in one tick, want %d", c.probes, 4*kernel.MaxSteps-1)
	}

	l, err := kernel.Open(cfg(r))
	must(t, err)
	k, err := kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{}, 0)
	must(t, err)
	reads, at := 0, now+kernel.ProbeEvery
	k.UseClock(func() kernel.Reading {
		if reads++; reads > 8*kernel.MaxSteps {
			panic("Calls did not stop") // fails the test at once, not at its timeout
		}
		return kernel.At(at)
	})
	if cs, err := k.Calls(at); err != nil || len(cs) != 0 {
		t.Fatalf("a probe no clerk can make: %d calls, %v", len(cs), err)
	}
	if reads != 1+4*kernel.MaxSteps {
		t.Fatalf("%d readings, want one for the ends due and %d decisions", reads, 4*kernel.MaxSteps)
	}
}

// Calls stops at a plan's first call: it reads the clock once for the ends
// due and once per decision, and makes no decision past the call.
func TestKernelGoCallsStopsAtAPlansCall(t *testing.T) {
	r := newRig(t)
	r.plan("p", r.ck, st(key.Organize, "m1"), st(key.Organize, "m2"))
	reads := 0
	r.k.UseClock(func() kernel.Reading { reads++; return kernel.At(1) })
	cs, err := r.k.Calls(1)
	must(t, err)
	if len(cs) != 1 || cs[0].Req.Index != 0 {
		t.Fatalf("calls %+v", cs)
	}
	if reads != 2 {
		t.Fatalf("%d readings for one call, want 2", reads)
	}
}

// A probe's answer is logged once, as a probe, never also as a result.
func TestKernelGoAProbeAnswerIsOneEntry(t *testing.T) {
	r := newRig(t)
	r.plan("p", r.ck, st(key.Organize, "m1"))
	cs, err := r.k.Calls(0)
	must(t, err)
	must(t, r.k.Answer(0, cs[0], kernel.Result{Outcome: "unknown"}))
	ps, err := r.k.Calls(kernel.ProbeEvery)
	must(t, err)
	if len(ps) != 1 || ps[0].Kind != kernel.ActProbe {
		t.Fatalf("calls at the probe time: %+v", ps)
	}
	n := len(r.k.Log().Entries())
	must(t, r.k.Answer(kernel.ProbeEvery, ps[0], kernel.Result{Outcome: "done"}))
	es := r.k.Log().Entries()
	if len(es) != n+1 || es[n].Type != kernel.TStepProbed {
		t.Fatalf("a probe answer logged %d entries, the first %s", len(es)-n, es[n].Type)
	}
}

// Send refuses a dispatch of a step not in flight, and releases the step,
// so a later Calls hands its own call out again (KRN-7).
func TestKernelGoSendReleasesAStepNotInFlight(t *testing.T) {
	r := newRig(t)
	r.plan("p", r.ck, st(key.Organize, "m1"))
	cs, err := r.k.Calls(0)
	must(t, err)
	must(t, r.k.Answer(0, cs[0], kernel.Result{Outcome: "unknown"}))
	ps, err := r.k.Calls(kernel.ProbeEvery)
	must(t, err)
	if len(ps) != 1 || ps[0].Kind != kernel.ActProbe {
		t.Fatalf("calls at the probe time: %+v", ps)
	}
	if again, err := r.k.Calls(kernel.ProbeEvery); err != nil || len(again) != 0 {
		t.Fatalf("a probe handed out twice: %d, %v", len(again), err)
	}
	forged := ps[0]
	forged.Kind = kernel.ActDispatch
	if ok, err := r.k.Send(kernel.ProbeEvery, forged); ok || err != nil {
		t.Fatalf("a dispatch of an unknown step was sent: %v %v", ok, err)
	}
	if again, err := r.k.Calls(kernel.ProbeEvery); err != nil || len(again) != 1 || again[0].Kind != kernel.ActProbe {
		t.Fatalf("after the refused send: %+v, %v", again, err)
	}
}

// A step is checked against the ledger before its first dispatch only once
// it is a redo: at attempt 0 every use logged counts, its own earlier
// dispatch's among them, whatever the log says that dispatch was (KRN-5).
func TestKernelGoAFirstAttemptIsChargedItsEarlierDispatch(t *testing.T) {
	r := newRig(t)
	r.plan("p", r.derive(key.LimitUses(1)), st(key.Organize, "m1"))
	cs, err := r.k.Calls(0)
	must(t, err)
	if len(cs) != 1 {
		t.Fatalf("%d calls", len(cs))
	}
	must(t, r.k.Answer(1, cs[0], kernel.Result{Outcome: kernel.OUnsent}))
	idem := cs[0].Req.Idem()
	_, err = r.k.Log().Append(2, kernel.TStepDispatch, 1, map[string]any{"plan": "p", "index": 0, "attempt": 0, "idem": idem})
	must(t, err)
	_, err = r.k.Log().Append(3, kernel.TStepResult, 1, map[string]any{"plan": "p", "index": 0, "idem": idem, "outcome": kernel.OUnsent, "detail": ""})
	must(t, err)
	s, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	ss := s.Plans["p"].Steps[0]
	if ss.Phase != kernel.PUnsent || ss.Attempt != 0 {
		t.Fatalf("the step is %s at attempt %d", ss.Phase, ss.Attempt)
	}
	if a := kernel.Next(s, "p", ss.NextProbe); a.Kind != kernel.ActCancel || kgCode(a.Refusal) != "uses" {
		t.Fatalf("a first attempt under a key whose one use is spent: %+v", a)
	}
}
