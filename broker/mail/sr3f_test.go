package mail_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

// TestRecheckRepinsTheSwappedMessage (SR3-5-f1a recheck, control): an
// alert swapped in before the dispatch recheck is judged there, escalated
// to change-account, and that judgement is the one Execute acts on.
func TestRecheckRepinsTheSwappedMessage(t *testing.T) {
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
	x.mustRun2(in, 1)
	if folder, _, _ := x.srv.Find(id); folder != "Archive" {
		t.Fatalf("alert in %s after an approved archive", folder)
	}
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
