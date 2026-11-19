package kernel_test

// REQ: KRN-1, KRN-5, KRN-8, LOG-7, CH-4

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Every fold refuses an entry whose body does not decode, rather than
// folding the zero value in its place (KRN-1).
func TestEveryFoldRefusesABodyItCannotRead(t *testing.T) {
	for _, typ := range []string{kernel.TKeyIssued, kernel.TEnrolled, kernel.TSpendReserved, kernel.TModelUsed,
		kernel.TPlanSubmit, kernel.TPlanAccepted, kernel.TPlanRejected, kernel.TPlanCancel, kernel.TStepHeld,
		kernel.TStepDispatch, kernel.TStepResult, kernel.TTaskOpened, kernel.TCodeApproved, kernel.TUnenrolled,
		kernel.TKeyRevoked, kernel.TSpendHeld, kernel.TSpendExtend, kernel.TPoolRead, kernel.TPoolReset, kernel.TReserveUp, kernel.TStepProbed} {
		_, err := kernel.Replay(nil, []kernel.Entry{{Seq: 1, Type: typ, Body: json.RawMessage(`"x"`)}})
		if !errors.Is(err, kernel.ErrCorrupt) {
			t.Errorf("%s with an unreadable body: %v", typ, err)
		}
	}
}

// A plan is text: a step's clerk, content or label that is not UTF-8 is
// refused as an argument is (#4719).
func TestEveryPlanFieldMustBeUTF8(t *testing.T) {
	r := newRig(t)
	bad := []func(*kernel.PlanStep){
		func(s *kernel.PlanStep) { s.Clerk = "m\xff" },
		func(s *kernel.PlanStep) { s.Content = "c\xff" },
		func(s *kernel.PlanStep) { s.Labels = []string{"ok", "l\xff"} },
	}
	for i, f := range bad {
		s := st(key.Organize, "m1")
		f(&s)
		p := r.sign(kernel.Plan{ID: "p1", Key: r.ck, Steps: []kernel.PlanStep{s}})
		if _, err := kernel.VerifyPlan(p, []key.PublicKey{r.owner.pk}); !errors.Is(err, kernel.ErrNotText) {
			t.Errorf("field %d: %v, want ErrNotText", i, err)
		}
	}
}

// A step's shape does not depend on the order its labels were written in, so
// relabelling cannot make a seen shape novel again (KEY-8).
func TestAShapeSortsItsLabels(t *testing.T) {
	a := kernel.Shape(key.Step{Verb: key.Organize, Labels: []string{"b", "a"}})
	if b := kernel.Shape(key.Step{Verb: key.Organize, Labels: []string{"a", "b"}}); a != b {
		t.Fatalf("%q != %q", a, b)
	}
}

// A request past the plan's last step is the zero step, never a panic.
func TestARequestPastTheLastStepIsTheZeroStep(t *testing.T) {
	p := kernel.Plan{ID: "p", Steps: []kernel.PlanStep{st(key.Trash, "m1")}}
	for _, i := range []int{-1, 1} {
		if s := (kernel.Request{Plan: p, Index: i}).Step(); s.Verb != "" || s.Clerk != "" {
			t.Fatalf("index %d: %+v", i, s)
		}
	}
}

// A plan of exactly MaxSteps steps is admitted; one more is not (KRN-5).
func TestAPlanOfMaxStepsIsAdmitted(t *testing.T) {
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

// Admission counts a plan's earlier steps against its later ones: a key with
// one use left admits no plan of two steps (KRN-5).
func TestAdmissionCountsAPlansOwnEarlierSteps(t *testing.T) {
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

// A line exactly MaxShown long is shown and listed (CLK-3).
func TestALineOfMaxShownIsListed(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	line := strings.Repeat("x", kernel.MaxShown)
	cs, err := r.k.Calls(1)
	must(t, err)
	if len(cs) != 1 {
		t.Fatalf("%d calls", len(cs))
	}
	must(t, r.k.Answer(1, cs[0], kernel.Result{Outcome: "ok", Covered: line}))
	if got := r.k.State().Covered(1); len(got) != 1 || got[0].Line != line {
		t.Fatalf("covered %d lines", len(got))
	}
	sent := r.k.State().Covered(1)[0].At
	if n, m := len(r.k.State().Covered(sent+kernel.TaskTimeout-1)), len(r.k.State().Covered(sent+kernel.TaskTimeout)); n != 1 || m != 0 {
		t.Fatalf("listed %d just inside a task approval's life and %d at its end", n, m)
	}
}

// The one-off line is the line times the largest daily cap, exact up to the
// largest cap the product holds, and saturates only past it (CH-4).
func TestTheOneOffLineIsExactAtItsLargestCap(t *testing.T) {
	r := newRig(t)
	day := int64(1<<63-1) / kernel.DefaultLine
	root := trashRoot(r, "big", r.owner)
	r.grant(root, day)
	if got, want := r.k.State().OneOffLine(root.Tip(), 0), day*kernel.DefaultLine/100; got != want {
		t.Fatalf("one-off line %d, want %d", got, want)
	}
	over := trashRoot(r, "over", r.owner)
	r.grant(over, day+1)
	if got := r.k.State().OneOffLine(over.Tip(), 0); got != 1<<63-1 {
		t.Fatalf("one-off line past the largest cap %d, want it saturated", got)
	}
}

// An approval of no step, and one of exactly MaxCodeSteps held steps, are
// judged on their steps: the first is refused, the second releases all
// (CH-4).
func TestACodeApprovalOfNoneOrMaxCodeSteps(t *testing.T) {
	r := newRig(t)
	checker := gen(40)
	r.k.PinChecker(checker.pub)
	if err := r.k.ApproveCode(10, kernel.SignCode(checker.priv, nil)); !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("an approval of no step: %v", err)
	}
	steps, ids := map[string]kernel.PlanStep{}, []string{}
	for i := range kernel.MaxCodeSteps {
		id := fmt.Sprintf("p%d", i)
		steps[id], ids = st(key.Unsubscribe, "list-"+id), append(ids, id)
	}
	r.held(r.derive(key.LimitHold(hour, hour)), steps)
	must(t, r.k.ApproveCode(10, kernel.SignCode(checker.priv, r.codeSteps(ids...))))
	for _, id := range ids {
		if !r.k.State().Plans[id].Steps[0].Approved {
			t.Fatalf("%s not approved", id)
		}
	}
}

// Next says when a held step is next due, and gives an ended plan nothing
// to do (KRN-5).
func TestNextOnAHeldStepAndAnEndedPlan(t *testing.T) {
	r := newRig(t)
	r.held(r.derive(key.LimitHold(hour, hour)), map[string]kernel.PlanStep{"h": st(key.Unsubscribe, "list-a")})
	if a := kernel.Next(r.k.State(), "h", 1); a.Kind != kernel.ActNone || a.WakeAt <= 1 {
		t.Fatalf("a held step: %+v", a)
	}
	must(t, r.k.Cancel(2, "h"))
	if a := kernel.Next(r.k.State(), "h", 3*hour); a != (kernel.Act{}) {
		t.Fatalf("a cancelled plan: %+v", a)
	}
}

// Two plans with the same irreversible effect, both admitted before either
// ran, run it once: the second is cancelled as a duplicate when it comes
// due (KRN-8). Another root's plan in flight with the same effect is not a
// duplicate.
func TestTheSameEffectAdmittedTwiceRunsOnce(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Unsubscribe, "list-a"))
	r.plan("p2", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	if n := len(r.mail.Effects()); n != 1 || r.status("p2") != kernel.SCancelled || r.k.State().Plans["p2"].Cancel != kernel.CDuplicate {
		t.Fatalf("%d effects, p2 %s %s", n, r.status("p2"), r.k.State().Plans["p2"].Cancel)
	}

	r = newRig(t)
	other := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Unsubscribe}, Serial: "r2"}), 1<<40)
	r.plan("a", r.ck, st(key.Unsubscribe, "list-a"))
	cs, err := r.k.Calls(0)
	must(t, err)
	if len(cs) != 1 {
		t.Fatalf("%d calls", len(cs))
	}
	r.plan("b", other, st(key.Unsubscribe, "list-a"))
	if r.status("b") != kernel.SActive {
		t.Fatalf("another root's step in flight made b %s %s", r.status("b"), r.k.State().Plans["b"].Reject)
	}
}

// downStore is the rig's store with appends that fail once left runs out
// (left < 0 never fails).
type downStore struct {
	*kernel.MemStore
	left int
}

func (f *downStore) Append(b []byte) error {
	if f.left == 0 {
		return errors.New("store down")
	}
	f.left--
	return f.MemStore.Append(b)
}

// hangClerk is the mail clerk whose first call hangs: when it returns, the
// clock has moved to then and the store has after appends left.
type hangClerk struct {
	*clerk.Mail
	hung  bool
	hang  func()
	calls int
}

func (h *hangClerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	h.calls++
	res := h.Mail.Do(r, v)
	if !h.hung {
		h.hung = true
		h.hang()
	}
	return res
}

// rebootWith boots r's log again over fs, with c as the mail clerk.
func rebootWith(r *rig, fs *downStore, c kernel.Clerk) {
	r.t.Helper()
	cf := cfg(r)
	cf.Store = fs
	l, err := kernel.Open(cf)
	must(r.t, err)
	r.k, err = kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{"mail": c}, 0)
	must(r.t, err)
}

// Tick sends no call its send check refuses, though Next allowed it a
// moment before (a clerk call before it hung past the key's expiry), and
// returns the error when the refusal cannot be logged (KRN-5).
func TestTickSendsNothingItsSendCheckRefuses(t *testing.T) {
	for _, down := range []bool{false, true} {
		r := newRig(t)
		var now int64
		fs := &downStore{MemStore: r.store, left: -1}
		h := &hangClerk{Mail: r.mail, hang: func() {
			now = hour
			if down {
				fs.left = 1 // the hung call's answer is logged, nothing after it
			}
		}}
		rebootWith(r, fs, h)
		r.k.UseClock(func() kernel.Reading { return kernel.At(now) })
		r.plan("first", r.ck, st(key.Organize, "a"))
		r.plan("second", r.derive(key.LimitExpires(hour/2)), st(key.Organize, "b"))
		err := r.k.Tick(0)
		if down != (err != nil) || errors.Is(err, kernel.ErrBroken) {
			t.Fatalf("store down %v: tick %v", down, err)
		}
		if n := len(r.mail.Effects()); n != 1 || h.calls != 1 {
			t.Fatalf("store down %v: %d effects from %d calls, want only the first plan's", down, n, h.calls)
		}
		if ph := r.k.State().Plans["second"].Steps[0].Phase; !down && ph == kernel.PInflight {
			t.Fatal("a refused send left its step in flight")
		}
	}
}

// A metered call's admission that cannot be logged is refused, and a broken
// log admits nothing whatever the caps say (KRN-5).
func TestASpendAdmissionTheLogCannotTakeIsRefused(t *testing.T) {
	r := newRig(t)
	fs := &downStore{MemStore: r.store, left: -1}
	rebootWith(r, fs, r.mail)
	modelPlan(r, "p", modelKey(r, "m1", key.LimitSpendTask(10)))
	fs.left = 0
	if _, rf := r.k.AdmitSpend(1, "p", 1); rf == nil || rf.Code != kernel.CBroken {
		t.Fatalf("an admission the store refused: %v", rf)
	}
	if _, rf := r.k.AdmitSpend(1, "p", 11); rf == nil || rf.Code != kernel.CBroken {
		t.Fatalf("an admission over its cap on a broken log: %v", rf)
	}
}

// Next and Send cancel a one-off under a phone's bare root once the phone
// is unenrolled: a cut-off phone taps nothing (D-146, KEY-6).
func TestAOneOffUnderAnUnenrolledPhoneIsCancelled(t *testing.T) {
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
		var err error
		if dispatched {
			cs, err = r.k.Calls(at)
			must(t, err)
		}
		must(t, r.k.Unenroll(at, key.Unenroll(r.owner.pass, phone.pk)))
		if dispatched {
			if ok, err := r.k.Send(at, cs[0]); ok || err != nil {
				t.Fatalf("sent after the phone was unenrolled: %v %v", ok, err)
			}
		} else if a := kernel.Next(r.k.State(), "p", at); a.Kind != kernel.ActCancel || a.Refusal.Code != kernel.CKey {
			t.Fatalf("next after the phone was unenrolled: %+v", a)
		}
	}
}

// A first attempt is checked against every use logged before it: two plans
// admitted under a key's one use, before either ran, run one (KRN-5).
func TestAFirstAttemptCountsEveryEarlierUse(t *testing.T) {
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

// A hold or a cancel Next decides that cannot be logged stops Calls with the
// error, and no call goes out after it (KRN-5).
func TestCallsReturnsAHoldOrCancelTheLogCannotTake(t *testing.T) {
	for _, hold := range []bool{true, false} {
		r := newRig(t)
		fs := &downStore{MemStore: r.store, left: -1}
		rebootWith(r, fs, r.mail)
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

// A plan whose own key a cut-off passkey narrowed funds no metered call,
// even through an extension still live (KEY-6, LOG-7).
func TestAnExtendedPlanStopsWhenItsNarrowerIsCutOff(t *testing.T) {
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
	must(t, r.k.Unenroll(4, key.Unenroll(r.owner.pass, phone.pk)))
	if _, rf := r.k.AdmitSpend(5, "p", 1); rf == nil || rf.Code != kernel.CCutOff {
		t.Fatalf("a plan its cut-off narrower approved: %v", rf)
	}
}

// divergesAt reports whether Rederive refuses r's log with extra appended
// at at, as a Divergence.
func divergesAt(r *rig, at int64, typ string, v int, body any) bool {
	r.t.Helper()
	_, err := r.k.Log().Append(at, typ, v, body)
	must(r.t, err)
	_, err = kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries())
	var d *kernel.Divergence
	return errors.As(err, &d)
}

// Rederive derives a pool reset again from the state, refuses an accept no
// pending plan's admission gives, and allows a cancel after a send only for
// an unsent answer (KRN-1, RES-5).
func TestRederiveChecksResetsAcceptsAndSendCancels(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	must(t, read(r, 2, "p", 950, 1_000))
	if rf := r.k.AdmitPool(1_000, "p"); rf != nil {
		t.Fatal(rf)
	}
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries()); err != nil {
		t.Fatalf("a due reset: %v", err)
	}

	r = newRig(t)
	r.plan("p1", r.ck, st(key.Organize, "m1"))
	es := r.k.Log().Entries()
	accepted := es[len(es)-1]
	if accepted.Type != kernel.TPlanAccepted {
		t.Fatalf("last entry %s", accepted.Type)
	}
	if !divergesAt(r, 1, kernel.TPlanAccepted, accepted.V, accepted.Body) {
		t.Fatal("a second accept of an active plan was not refused")
	}
	r = newRig(t)
	if !divergesAt(r, 1, kernel.TPlanAccepted, 1, map[string]any{"plan": "none", "cause": 1}) {
		t.Fatal("an accept of no plan was not refused")
	}

	type cancel struct {
		Plan   string `json:"plan"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	r = newRig(t)
	k := r.derive(key.LimitExpires(hour / 2))
	r.plan("p", k, st(key.Organize, "a"))
	r.plan("twin", k, st(key.Organize, "b"))
	late := kernel.Next(r.k.State(), "twin", hour)
	if late.Kind != kernel.ActCancel {
		t.Fatalf("twin at an hour: %+v", late)
	}
	cs, err := r.k.Calls(0)
	must(t, err)
	must(t, r.k.Answer(hour, cs[0], kernel.Result{Outcome: "ok"}))
	if !divergesAt(r, hour, kernel.TPlanCancel, 1, cancel{"p", late.Refusal.Code, late.Refusal.Detail}) {
		t.Fatal("a cancel after a sent step's answer was not refused")
	}
}

// lostClerk answers every call unknown and every probe unreached, counting
// the probes; past a bound no Tick reaches it answers done, so a Tick that
// would not stop ends there rather than growing the log without end.
type lostClerk struct{ probes int }

func (c *lostClerk) Do(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "unknown"}
}

func (c *lostClerk) Probe(kernel.Request, kernel.View) kernel.Result {
	c.probes++
	if c.probes > 8*kernel.MaxSteps {
		return kernel.Result{Outcome: "done"}
	}
	return kernel.Result{Outcome: kernel.OUnreached}
}

// A step that can never settle bounds the work of one Tick and one Calls:
// Tick runs at most 4*MaxSteps rounds against a clerk that is never
// reached, and Calls returns at once when no clerk the kernel holds can
// probe the step (KRN-8).
func TestAStepThatNeverSettlesBoundsTickAndCalls(t *testing.T) {
	r := newRig(t)
	c := &lostClerk{}
	rebootWith(r, &downStore{MemStore: r.store, left: -1}, c)
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
}

// A probe's answer is logged and folded only for a step awaiting one: done
// settles an unknown step, unreached waits ProbeEvery from the answer, and a
// probe answer for a step in flight changes nothing (KRN-8).
func TestAProbeAnswerSettlesOnlyAnUnknownStep(t *testing.T) {
	r := newRig(t)
	r.plan("p", r.ck, st(key.Organize, "m1"))
	cs, err := r.k.Calls(0)
	must(t, err)
	must(t, r.k.Answer(0, kernel.Call{Kind: kernel.ActProbe, Clerk: "mail", Req: cs[0].Req}, kernel.Result{Outcome: "done"}))
	if ph := r.k.State().Plans["p"].Steps[0].Phase; ph != kernel.PInflight {
		t.Fatalf("a probe answer for a step in flight made it %s", ph)
	}
	must(t, r.k.Answer(0, cs[0], kernel.Result{Outcome: "unknown"}))
	at := int64(kernel.ProbeEvery)
	ps, err := r.k.Calls(at)
	must(t, err)
	if len(ps) != 1 || ps[0].Kind != kernel.ActProbe {
		t.Fatalf("calls at the probe time: %+v", ps)
	}
	must(t, r.k.Answer(at+5, ps[0], kernel.Result{Outcome: kernel.OUnreached}))
	if a := kernel.Next(r.k.State(), "p", at+5); a.WakeAt != at+5+kernel.ProbeEvery {
		t.Fatalf("after an unreached probe: %+v", a)
	}
	ps, err = r.k.Calls(at + 5 + kernel.ProbeEvery)
	must(t, err)
	must(t, r.k.Answer(at+5+kernel.ProbeEvery, ps[0], kernel.Result{Outcome: "done"}))
	if r.status("p") != kernel.SDone {
		t.Fatalf("a done probe: %s", r.status("p"))
	}
}

// Boot reconciles the steps in flight of every plan, a rejected plan with
// no steps among them (KRN-8).
func TestBootSkipsARejectedPlan(t *testing.T) {
	r := newRig(t)
	r.plan("gone", r.derive(key.LimitTask("nope")), st(key.Trash, "m1"))
	r.plan("p", r.ck, st(key.Organize, "m1"))
	_, err := r.k.Calls(0)
	must(t, err)
	r.boot(1)
	if ph := r.k.State().Plans["p"].Steps[0].Phase; ph != kernel.PUnknown {
		t.Fatalf("a step in flight at boot is %s", ph)
	}
}

// An extension needs a per-task cap of its own: a day cap alone extends
// nothing (LOG-7).
func TestAnExtensionWithoutATaskCapIsRefused(t *testing.T) {
	r := newRig(t)
	day := modelKey(r, "day")
	modelPlan(r, "p", modelKey(r, "m1", key.LimitSpendTask(10)))
	exhaust(r, "p", 10)
	if err := r.k.Extend(3, day, "p"); err == nil {
		t.Fatal("an extension with no per-task cap")
	}
}

// Rederive names what it derived in place of an entry it refuses.
func TestADivergenceNamesTheDerivedEntry(t *testing.T) {
	r := newRig(t)
	r.plan("p", r.ck, st(key.Organize, "m1"))
	_, err := r.k.Log().Append(0, kernel.TStepDispatch, 1, map[string]any{"plan": "p", "index": 0, "attempt": 7})
	must(t, err)
	_, err = kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries())
	var d *kernel.Divergence
	if !errors.As(err, &d) || d.Derived == "nothing" || d.Derived == "" {
		t.Fatalf("divergence %v", err)
	}
}

// A reading the fold cannot take as a share of the pool is skipped, and
// windows due together reset in their names' order (RES-5).
func TestPoolReadingsOutOfRangeAndResetOrder(t *testing.T) {
	r := newRig(t)
	for _, used := range []int64{-1, kernel.PoolFull + 1} {
		_, err := r.k.Log().Append(1, kernel.TPoolRead, 2, map[string]any{"pool": "x", "windows": []kernel.WindowReading{{Window: "5h", Used: used, ResetAt: 1_000}}})
		must(t, err)
	}
	s, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if w := s.Pools["x"].Windows; len(w) != 0 {
		t.Fatalf("a reading out of range was folded: %+v", w)
	}

	r = newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	var ws []kernel.WindowReading
	for i := len(names) - 1; i >= 0; i-- {
		ws = append(ws, kernel.WindowReading{Window: names[i], Used: 950, ResetAt: 1_000})
	}
	must(t, r.k.ReadPool(2, "p", ws))
	if rf := r.k.AdmitPool(1_000, "p"); rf != nil {
		t.Fatal(rf)
	}
	var got []string
	for _, e := range r.k.Log().Entries() {
		if e.Type == kernel.TPoolReset {
			var b struct{ Window string }
			must(t, json.Unmarshal(e.Body, &b))
			got = append(got, b.Window)
		}
	}
	if strings.Join(got, "") != strings.Join(names, "") {
		t.Fatalf("resets logged in order %v", got)
	}
}

// Open trims a torn tail (a length cut short, or a frame cut short) and
// refuses a whole frame too short to be one, or an entry of a type it does
// not know; an anchor at seq 0 checks nothing (LOG-2).
func TestOpenTrimsATornTailAndRefusesAShortFrame(t *testing.T) {
	r := newRig(t)
	good := append([]byte(nil), r.store.B...)
	n := len(r.k.Log().Entries())
	// A cut length; frames cut short by 97, 4 and 3 bytes (the last shorter
	// than a nonce and tag); a whole frame that does not open, last.
	for i, tail := range [][]byte{{0, 1}, {0, 0, 0, 100, 1, 2, 3}, {0, 0, 0, 40}, {0, 0, 0, 20}, {0, 0, 0, 28}} {
		tail = append(tail, make([]byte, []int{0, 0, 36, 17, 28}[i])...)
		r.store.B = append(append([]byte(nil), good...), tail...)
		l, err := kernel.Open(cfg(r))
		if err != nil || len(l.Entries()) != n || len(r.store.B) != len(good) {
			t.Fatalf("tail %d: %v, %d entries, %d bytes", i, err, len(l.Entries()), len(r.store.B))
		}
	}
	for i, tail := range [][]byte{{0, 0, 0, 0}, {0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}} {
		r.store.B = append(append([]byte(nil), good...), tail...)
		if _, err := kernel.Open(cfg(r)); !errors.Is(err, kernel.ErrCorrupt) {
			t.Fatalf("short frame %d: %v", i, err)
		}
	}
	// A frame a later kernel could write: a sealed entry of a type this one
	// does not know.
	es := r.k.Log().Entries()
	last := es[len(es)-1]
	pt, err := json.Marshal(kernel.Entry{Seq: last.Seq + 1, Prev: last.Hash(), At: last.At, Type: "no.such.type", V: 1, Body: json.RawMessage(`{}`)})
	must(t, err)
	b, err := aes.NewCipher(logKey[:])
	must(t, err)
	a, err := cipher.NewGCM(b)
	must(t, err)
	nonce := make([]byte, a.NonceSize())
	ct := a.Seal(nonce, nonce, pt, binary.BigEndian.AppendUint64(nil, last.Seq+1))
	r.store.B = append(binary.BigEndian.AppendUint32(append([]byte(nil), good...), uint32(len(ct))), ct...)
	if _, err := kernel.Open(cfg(r)); !errors.Is(err, kernel.ErrUnknown) {
		t.Fatalf("an unknown entry type: %v", err)
	}
	// An entry sealed under its place's seq that names another is corrupt.
	pt, err = json.Marshal(kernel.Entry{Seq: last.Seq + 2, Prev: last.Hash(), At: last.At, Type: kernel.TStop, V: 1, Body: json.RawMessage(`{}`)})
	must(t, err)
	ct = a.Seal(nonce, nonce, pt, binary.BigEndian.AppendUint64(nil, last.Seq+1))
	r.store.B = append(binary.BigEndian.AppendUint32(append([]byte(nil), good...), uint32(len(ct))), ct...)
	if _, err := kernel.Open(cfg(r)); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("an entry naming another seq: %v", err)
	}
	if err := (&kernel.MemStore{B: []byte{1, 2}}).Truncate(3); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("a truncate past the end: %v", err)
	}
	if err := (&kernel.MemStore{B: []byte{1, 2}}).Truncate(2); err != nil {
		t.Fatalf("a truncate to the end: %v", err)
	}
	// A whole frame of nonce and tag alone seals no entry: corrupt, not torn.
	empty := a.Seal(nonce, nonce, nil, binary.BigEndian.AppendUint64(nil, last.Seq+1))
	r.store.B = append(binary.BigEndian.AppendUint32(append([]byte(nil), good...), uint32(len(empty))), empty...)
	if _, err := kernel.Open(cfg(r)); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("a frame sealing nothing: %v", err)
	}

	c := kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: r.head.pub, Sign: r.head.priv, Key: logKey, Rand: cfg(r).Rand}
	must(t, c.Anchor.Put(kernel.SignHead(r.head.priv, 0, kernel.Hash{})))
	if _, err := kernel.Open(c); err != nil {
		t.Fatalf("an empty log anchored at seq 0: %v", err)
	}
}
