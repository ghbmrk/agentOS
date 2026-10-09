package mail_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/verb"
)

// REQ: ADP-2, ADP-9, OP-2, OP-3, OP-4 (SR3-2-f1a, SR3-2-f1b, SR3-5-f1a, SR3-5-f1b, SR3-5-f1c)

// queue authorizes n organize effects on one newsletter through the real
// gate under STOP, so none is dispatched, and returns them.
func (r *gated) queue(n int) []journal.Intent {
	r.t.Helper()
	if _, err := r.eng.Stop(ctx); err != nil {
		r.t.Fatal(err)
	}
	id := r.news(r.n + 1000)
	var q []journal.Intent
	for i := 0; i < n; i++ {
		in := r.intent(mail.OpStar, rec(id))
		in.Machine, in.Label = "agent", "private"
		if _, err := r.g.Submit(in); err != nil {
			r.t.Fatal(err)
		}
		if st, _ := r.g.Authorize(ctx, in.ID); st.State != journal.Authorized {
			r.t.Fatalf("authorize %d: %s %q", i, st.State, st.Permission.Reason)
		}
		q = append(q, in)
	}
	return q
}

// release resumes the journal and dispatches q, each through the gate's
// dispatch recheck.
func (r *gated) release(q []journal.Intent) {
	r.t.Helper()
	if err := r.eng.Resume(); err != nil {
		r.t.Fatal(err)
	}
	for _, in := range q {
		if st, _ := r.g.Dispatch(ctx, in.ID); st.State != journal.Succeeded {
			r.t.Fatalf("dispatch %s: %s %q", in.ID, st.State, st.Permission.Reason)
		}
	}
}

// restart is a new adapter on the same configuration and journal.
func (r *gated) restart() *mail.Adapter {
	r.t.Helper()
	a, err := mail.New(r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

// TestStaleQueueCountsAfterRestart (SR3-2-f1a): 200 organize effects
// authorized at T0 and released 36 h later count for the day they were
// dispatched in, so an adapter built after a restart asks the 201st.
func TestStaleQueueCountsAfterRestart(t *testing.T) {
	r := newGated(t, nil)
	t0 := r.now
	q := r.queue(mail.DefaultDailyLimit)
	r.now = t0.Add(36 * time.Hour)
	r.release(q)
	r.now = t0.Add(36*time.Hour + 30*time.Minute)
	a := r.restart()
	e, err := a.Escalate(ctx, r.intent(mail.OpStar, rec(r.news(1))))
	if err != nil || !e.Ask || e.Held {
		t.Fatalf("the 201st after a restart: %+v %v", e, err)
	}
}

// TestStaleQueueSameAdapterAsks (SR3-2-f1 control): without the restart
// the same timeline asks the 201st too.
func TestStaleQueueSameAdapterAsks(t *testing.T) {
	r := newGated(t, nil)
	t0 := r.now
	q := r.queue(mail.DefaultDailyLimit)
	r.now = t0.Add(36 * time.Hour)
	r.release(q)
	r.now = t0.Add(36*time.Hour + 30*time.Minute)
	e, err := r.a.Escalate(ctx, r.intent(mail.OpStar, rec(r.news(1))))
	if err != nil || !e.Ask {
		t.Fatalf("the 201st: %+v %v", e, err)
	}
}

// TestBoundIsExactAfterRestart (SR3-2-f1b): 150 dispatched 25 h after
// they were authorized leave exactly 50 places for a restarted adapter;
// the 51st is the one ask and the rest never pass.
func TestBoundIsExactAfterRestart(t *testing.T) {
	r := newGated(t, nil)
	t0 := r.now
	q := r.queue(150)
	r.now = t0.Add(25 * time.Hour)
	r.release(q)
	r.now = t0.Add(25*time.Hour + 30*time.Minute)
	a := r.restart()
	id := r.news(1)
	for i := 1; i <= 60; i++ {
		e, err := a.Escalate(ctx, r.intent(mail.OpStar, rec(id)))
		switch {
		case err != nil:
			t.Fatal(err)
		case i <= 50 && (e.Ask || e.Held):
			t.Fatalf("effect %d inside the bound: %+v", i, e)
		case i == 51 && (!e.Ask || e.Reason != "past 200, YES allows 2000"):
			t.Fatalf("effect 51: %+v", e)
		case i > 51 && !e.Held && !e.Ask:
			t.Fatalf("effect %d passed past the bound: %+v", i, e)
		}
	}
}

// TestNilInUseAsksEach (SR3-2-f1 control): with no journal hook every
// organize effect is asked, never held or passed.
func TestNilInUseAsksEach(t *testing.T) {
	x := newH(t, func(c *mail.Config) { c.InUse = nil })
	id := x.news(1)
	for i := 0; i < 3; i++ {
		e, err := x.a.Escalate(ctx, x.intent(mail.OpStar, rec(id)))
		if err != nil || !e.Ask || e.Held || e.Reason != "past 2000 today" {
			t.Fatalf("nil hook, effect %d: %+v %v", i, e, err)
		}
	}
}

// swap replaces the message id names in the inbox with a security alert
// carrying the same Message-ID, delivered into folder.
func (x *h) swap(id, folder string) {
	x.srv.Remove("INBOX", id)
	x.deliver(folder, msg{id: id, from: "someone@x.example", to: me, subject: "New sign-in on your account", body: "Was this you?"})
}

// TestExecuteActsOnlyOnTheJudgedMessage (SR3-5-f1a): a same-ID alert
// that replaced the approved newsletter after the dispatch recheck is not
// hidden.
func TestExecuteActsOnlyOnTheJudgedMessage(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Ask || e.Verb != "" {
		t.Fatalf("recheck: %+v %v", e, err)
	}
	x.swap(id, "INBOX")
	out := x.a.Execute(ctx, in, 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	if folder, flags, _ := x.srv.Find(id); folder != "INBOX" || len(flags) != 0 {
		t.Fatalf("alert in %s with %v", folder, flags)
	}
}

// TestExecuteWithoutPinDoesNothing (SR3-5-f1a nopin): an adapter that
// never judged the intent does not run it.
func TestExecuteWithoutPinDoesNothing(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	out := x.a.Execute(ctx, x.intent(mail.OpArchive, rec(id)), 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	if folder, _, _ := x.srv.Find(id); folder != "INBOX" {
		t.Fatalf("moved to %s", folder)
	}
}

// TestJudgementsMustAgree (SR3-5-f1a recheck, control): an alert swapped
// in between the authorize judgement and the dispatch recheck is escalated
// there, but the two judgements disagree on the message, so Execute acts
// on neither.
func TestJudgementsMustAgree(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != "" {
		t.Fatalf("authorize: %+v %v", e, err)
	}
	x.swap(id, "INBOX")
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("recheck: %+v %v", e, err)
	}
	out := x.a.Execute(ctx, in, 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	if folder, _, _ := x.srv.Find(id); folder != "INBOX" {
		t.Fatalf("alert in %s", folder)
	}
}

// ordered calls the adapter unchanged, running a test's hooks before or
// after its nth Escalate and before Execute, to order concurrent calls.
type ordered struct {
	*mail.Adapter
	mu        sync.Mutex
	n         int
	pre, post map[int]func()
	exec      func()
}

func (o *ordered) Escalate(ctx context.Context, in journal.Intent) (grants.Escalation, error) {
	o.mu.Lock()
	o.n++
	pre, post := o.pre[o.n], o.post[o.n]
	o.mu.Unlock()
	if pre != nil {
		pre()
	}
	e, err := o.Adapter.Escalate(ctx, in)
	if post != nil {
		post()
	}
	return e, err
}

func (o *ordered) Execute(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	if o.exec != nil {
		o.exec()
	}
	return o.Adapter.Execute(ctx, in, attempt)
}

// TestRefusedRecheckCannotRepinAnAttemptInFlight (SR3-5-f1a race, L3 on
// #579): through the real gate and journal, dispatch D1 rechecks the
// newsletter and commits; D2's concurrent recheck, which began before
// that commit, judges an alert swapped in meanwhile and is refused. D1's
// attempt, already in flight, must not hide the alert.
func TestRefusedRecheckCannotRepinAnAttemptInFlight(t *testing.T) {
	w := &ordered{pre: map[int]func(){}, post: map[int]func(){}}
	r := newGatedVia(t, nil, func(a *mail.Adapter) adapterAPI { w.Adapter = a; return w })
	id := r.news(1)
	in := r.intent(mail.OpArchive, rec(id))
	in.Machine, in.Label = "agent", "private"
	if _, err := r.g.Submit(in); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.g.Authorize(ctx, in.ID); st.State != journal.Authorized {
		t.Fatalf("authorize: %s %q", st.State, st.Permission.Reason)
	}
	d1Judged, d1Go := make(chan struct{}), make(chan struct{})
	d2In, d2Go := make(chan struct{}), make(chan struct{})
	d1Exec, d1Run := make(chan struct{}), make(chan struct{})
	w.mu.Lock()
	w.post[w.n+1] = func() { close(d1Judged); <-d1Go }
	w.pre[w.n+2] = func() { close(d2In); <-d2Go }
	w.mu.Unlock()
	w.exec = func() { close(d1Exec); <-d1Run }

	d1 := make(chan journal.Status)
	go func() { st, _ := r.g.Dispatch(ctx, in.ID); d1 <- st }()
	<-d1Judged // D1's recheck judged the newsletter
	d2 := make(chan journal.Status)
	go func() { st, _ := r.g.Dispatch(ctx, in.ID); d2 <- st }()
	<-d2In // D2 is past the journal's dispatchable check, in its recheck
	close(d1Go)
	<-d1Exec // D1 committed and is in flight
	r.swap(id, "INBOX")
	close(d2Go)
	if st := <-d2; st.State == journal.Succeeded {
		t.Fatalf("D2: %s", st.State)
	}
	close(d1Run)
	if st := <-d1; st.State != journal.NotApplied {
		t.Fatalf("D1: %s %q", st.State, st.Permission.Reason)
	}
	if folder, flags, _ := r.srv.Find(id); folder != "INBOX" || len(flags) != 0 {
		t.Fatalf("alert in %s with %v", folder, flags)
	}
}

// TestPlanErrorPoisonsTheJudgements (SR3-5-f1a race, Security B1 on
// #579): D1 rechecks the newsletter and commits; the newsletter is then
// removed, so D2's concurrent recheck cannot plan; a same-ID alert
// arrives and D3's concurrent recheck judges it. Both are refused, and
// D2's failure must not erase D1's judgement and leave D3's as the only
// one: D1's attempt must not hide the alert.
func TestPlanErrorPoisonsTheJudgements(t *testing.T) {
	w := &ordered{pre: map[int]func(){}, post: map[int]func(){}}
	r := newGatedVia(t, nil, func(a *mail.Adapter) adapterAPI { w.Adapter = a; return w })
	id := r.news(1)
	in := r.intent(mail.OpArchive, rec(id))
	in.Machine, in.Label = "agent", "private"
	if _, err := r.g.Submit(in); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.g.Authorize(ctx, in.ID); st.State != journal.Authorized {
		t.Fatalf("authorize: %s %q", st.State, st.Permission.Reason)
	}
	d1Judged, d1Go := make(chan struct{}), make(chan struct{})
	d2In, d2Go := make(chan struct{}), make(chan struct{})
	d3In, d3Go := make(chan struct{}), make(chan struct{})
	d1Exec, d1Run := make(chan struct{}), make(chan struct{})
	w.mu.Lock()
	w.post[w.n+1] = func() { close(d1Judged); <-d1Go }
	w.pre[w.n+2] = func() { close(d2In); <-d2Go }
	w.pre[w.n+3] = func() { close(d3In); <-d3Go }
	w.mu.Unlock()
	w.exec = func() { close(d1Exec); <-d1Run }

	dispatch := func() chan journal.Status {
		c := make(chan journal.Status, 1)
		go func() { st, _ := r.g.Dispatch(ctx, in.ID); c <- st }()
		return c
	}
	d1 := dispatch()
	<-d1Judged
	d2 := dispatch()
	<-d2In
	d3 := dispatch()
	<-d3In // D2 and D3 are both past the journal's dispatchable check
	close(d1Go)
	<-d1Exec // D1 committed and is in flight
	r.srv.Remove("INBOX", id)
	close(d2Go)
	if st := <-d2; st.State == journal.Succeeded {
		t.Fatalf("D2: %s", st.State)
	}
	r.deliver("INBOX", msg{id: id, from: "someone@x.example", to: me, subject: "New sign-in on your account", body: "Was this you?"})
	close(d3Go)
	if st := <-d3; st.State == journal.Succeeded {
		t.Fatalf("D3: %s", st.State)
	}
	close(d1Run)
	if st := <-d1; st.State != journal.NotApplied {
		t.Fatalf("D1: %s %q", st.State, st.Permission.Reason)
	}
	if folder, flags, _ := r.srv.Find(id); folder != "INBOX" || len(flags) != 0 {
		t.Fatalf("alert in %s with %v", folder, flags)
	}
}

// TestJudgementsMustAgreeOnTheMessage (SR3-5-f1a, Security B2 on #579):
// two judgements that both escalated an alert, but of different messages
// with one Message-ID, do not carry the first one's approval to the
// second.
func TestJudgementsMustAgreeOnTheMessage(t *testing.T) {
	x := newH(t, nil)
	id := "<alert-1@x.example>"
	x.deliver("INBOX", msg{id: id, from: "someone@x.example", to: me, subject: "New sign-in on your account", body: "Was this you?"})
	in := x.intent(mail.OpArchive, rec(id))
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("first: %+v %v", e, err)
	}
	x.swap(id, "INBOX")
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("second: %+v %v", e, err)
	}
	out := x.a.Execute(ctx, in, 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	if folder, flags, _ := x.srv.Find(id); folder != "INBOX" || len(flags) != 0 {
		t.Fatalf("alert in %s with %v", folder, flags)
	}
}

// twin delivers a same-ID "New sign-in" alert to Receipts. Escalate's
// plan counts an alert copy of the record in any searched folder, so the
// newsletter's own Ref is judged an alert from then on.
func (x *h) twin(id string) {
	x.deliver("Receipts", msg{id: id, from: "someone@x.example", to: me, subject: "New sign-in on your account", body: "Was this you?"})
}

// untouched fails unless the newsletter id is still in INBOX unflagged.
func (x *h) untouched(id string) {
	x.t.Helper()
	for _, m := range x.srv.Messages("INBOX") {
		if m.ID == id && len(m.Flags) == 0 {
			return
		}
	}
	x.t.Fatalf("%s moved or flagged", id)
}

// TestJudgementsMustAgreeOnTheAlert (SR3-5-f1a, delta L3 B1 on #579): the
// same message judged first a non-alert and then, once a same-ID alert
// twin arrived, an alert, gives judgements that disagree, so Execute
// does nothing.
func TestJudgementsMustAgreeOnTheAlert(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, map[string]any{mail.ParamRecord: id, mail.ParamFolder: "INBOX"})
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != "" {
		t.Fatalf("first: %+v %v", e, err)
	}
	x.twin(id)
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("second: %+v %v", e, err)
	}
	out := x.a.Execute(ctx, in, 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	x.untouched(id)
}

// TestExecuteDoesNotHideAnAlertTheRecheckPassed (SR3-5-f1a check, lens M1
// on #579): the recheck judged the newsletter a non-alert; a same-ID alert
// twin arrived before Execute, whose plan now hides an alert on the same
// Ref, so it does nothing.
func TestExecuteDoesNotHideAnAlertTheRecheckPassed(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, map[string]any{mail.ParamRecord: id, mail.ParamFolder: "INBOX"})
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != "" {
		t.Fatalf("recheck: %+v %v", e, err)
	}
	x.twin(id)
	out := x.a.Execute(ctx, in, 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	x.untouched(id)
}

func (x *h) mustRun2(in journal.Intent, attempt int) {
	x.t.Helper()
	if out := x.a.Execute(ctx, in, attempt); out.Result != journal.ResultSucceeded {
		x.t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
}

// TestPinIsConsumed (SR3-5-f1a consume): a second Execute of the intent
// without a new recheck does nothing.
func TestPinIsConsumed(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpStar, rec(id))
	x.a.Escalate(ctx, in)
	x.mustRun2(in, 1)
	x.srv.SetFlags(id)
	if out := x.a.Execute(ctx, in, 2); out.Result != journal.ResultNotApplied {
		t.Fatalf("second execute: %s %q", out.Result, out.Evidence)
	}
	if _, flags, _ := x.srv.Find(id); len(flags) != 0 {
		t.Fatalf("flags %v", flags)
	}
}

// TestReconcileDoesNotLaunderAnAlert (SR3-5-f1b): after a restart, with
// a same-ID alert where the archive put the newsletter, reconciliation
// is unknown, not succeeded.
func TestReconcileDoesNotLaunderAnAlert(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	x.a.Escalate(ctx, in)
	x.swap(id, "Archive")
	a, err := mail.New(x.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out := a.Reconcile(ctx, in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("reconcile: %s %q", out.Result, out.Evidence)
	}
}

// lossy moves the message and then reports a failure, as a lost reply
// to the MOVE does.
type lossy struct{ mail.Store }

func (l *lossy) Move(ctx context.Context, r mail.Ref, to string) error {
	if err := l.Store.Move(ctx, r, to); err != nil {
		return err
	}
	return errors.New("connection lost")
}

// TestReconcileJudgesThePinnedAttempt (SR3-5-f1b): an approved alert
// archive whose MOVE reply was lost reconciles as succeeded on the
// adapter that ran it, which kept the attempt's pin; after a restart
// the pin is gone and the same state is unknown.
func TestReconcileJudgesThePinnedAttempt(t *testing.T) {
	x := newH(t, func(c *mail.Config) { c.Store = &lossy{c.Store} })
	x.deliver("INBOX", msg{id: "<al@x.example>", from: "someone@x.example", to: me, subject: "New sign-in", body: "x"})
	in := x.intent(mail.OpArchive, rec("<al@x.example>"))
	if e, _ := x.a.Escalate(ctx, in); e.Verb != verb.ChangeAccount {
		t.Fatalf("recheck: %+v", e)
	}
	if out := x.a.Execute(ctx, in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	restarted, err := mail.New(x.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out := restarted.Reconcile(ctx, in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("reconcile after restart: %s %q", out.Result, out.Evidence)
	}
	if out := x.a.Reconcile(ctx, in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile: %s %q", out.Result, out.Evidence)
	}
	// The pin served its attempt once.
	if out := x.a.Reconcile(ctx, in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("second reconcile: %s %q", out.Result, out.Evidence)
	}
}

// TestUndoRefusesFlagChangeWithoutValidity (SR3-5-f1c): flag-only
// evidence with no UID validity names no message, so a same-ID message
// now in the folder keeps its flags.
func TestUndoRefusesFlagChangeWithoutValidity(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	x.srv.SetFlags(id, mail.Flagged)
	r := x.a.Undo(ctx, []mail.Change{{Op: mail.OpStar, Record: id, From: "INBOX", Added: []string{mail.Flagged}}})
	if r.Skipped != 1 || r.Restored != 0 {
		t.Fatalf("undo: %+v", r)
	}
	if _, flags, _ := x.srv.Find(id); len(flags) != 1 || flags[0] != mail.Flagged {
		t.Fatalf("flags %v", flags)
	}
}

// TestExecuteRefusesASwappedAlertAfterOneJudgement (SR3-5-f1a, Security
// re-sign B1 on #579 round 3): the owner approved hiding alert A, and a
// same-ID alert B replaced it before Execute. With one judgement, only
// Execute's Ref check stops B being hidden under A's approval.
func TestExecuteRefusesASwappedAlertAfterOneJudgement(t *testing.T) {
	x := newH(t, nil)
	id := "<alert-1@x.example>"
	x.deliver("INBOX", msg{id: id, from: "someone@x.example", to: me, subject: "New sign-in on your account", body: "Was this you?"})
	in := x.intent(mail.OpArchive, rec(id))
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != verb.ChangeAccount {
		t.Fatalf("recheck: %+v %v", e, err)
	}
	x.swap(id, "INBOX")
	out := x.a.Execute(ctx, in, 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	if folder, flags, _ := x.srv.Find(id); folder != "INBOX" || len(flags) != 0 {
		t.Fatalf("alert in %s with %v", folder, flags)
	}
}

// TestExecuteRefusesASwappedNonAlert (SR3-5-f1a, delta L3 point 1 on #579
// round 3): a same-ID non-alert that replaced the judged newsletter after
// the recheck is a message nobody judged, so Execute leaves it alone.
func TestExecuteRefusesASwappedNonAlert(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Ask || e.Verb != "" {
		t.Fatalf("recheck: %+v %v", e, err)
	}
	x.srv.Remove("INBOX", id)
	x.deliver("INBOX", msg{id: id, from: "Bank <noreply@bank.example>", to: me, subject: "Your statement", body: "Your monthly statement is ready."})
	out := x.a.Execute(ctx, in, 1)
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	x.untouched(id)
}
