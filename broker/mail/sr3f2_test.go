package mail_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/verb"
)

// REQ: ADP-2, OP-2, OP-3 (SR3-5-f2a, SR3-5-f2b)

// changed fails unless out is NotApplied for a changed message.
func changed(t *testing.T, out journal.Outcome) {
	t.Helper()
	if out.Result != journal.ResultNotApplied || !strings.Contains(out.Evidence, "changed since approval") {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
}

// TestDeleteActsOnlyOnTheJudgedMessage (SR3-5-f2a swap): a same-ID alert
// that replaced the judged newsletter after the recheck is neither
// trashed nor reported as spam.
func TestDeleteActsOnlyOnTheJudgedMessage(t *testing.T) {
	for _, op := range []string{mail.OpDelete, mail.OpReportSpam} {
		t.Run(op, func(t *testing.T) {
			x := newH(t, nil)
			id := x.news(1)
			in := x.intent(op, rec(id))
			if e, err := x.a.Escalate(ctx, in); err != nil || e.Ask || e.Verb != "" {
				t.Fatalf("recheck: %+v %v", e, err)
			}
			x.swap(id, "INBOX")
			changed(t, x.a.Execute(ctx, in, 1))
			if folder, _, _ := x.srv.Find(id); folder != "INBOX" {
				t.Fatalf("alert in %s", folder)
			}
		})
	}
}

// TestDeleteWithoutPinDoesNothing (SR3-5-f2a nopin): a delete the adapter
// never judged does not run.
func TestDeleteWithoutPinDoesNothing(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	changed(t, x.a.Execute(ctx, x.intent(mail.OpDelete, rec(id)), 1))
	if folder, _, _ := x.srv.Find(id); folder != "INBOX" {
		t.Fatalf("moved to %s", folder)
	}
}

// TestDeleteThatCannotPlanIsRefused (SR3-5-f2a plan error): Escalate of a
// delete whose message is missing fails, so the gate denies it.
func TestDeleteThatCannotPlanIsRefused(t *testing.T) {
	x := newH(t, nil)
	if _, err := x.a.Escalate(ctx, x.intent(mail.OpDelete, rec("<gone@x.example>"))); err == nil {
		t.Fatal("escalate: no error")
	}
}

// TestDeleteRunsOnTheJudgedMessage (SR3-5-f2a control): an unchanged
// judged delete runs.
func TestDeleteRunsOnTheJudgedMessage(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpDelete, rec(id))
	x.a.Escalate(ctx, in)
	x.mustRun2(in, 1)
	if folder, _, _ := x.srv.Find(id); folder != "Trash" {
		t.Fatalf("delete put it in %s", folder)
	}
}

// TestExpiryKeepsTheJudgementOfAnAttemptInFlight (SR3-5-f2b race,
// Security re-sign R1 on #579): through the real gate and journal, D1
// rechecks the newsletter and commits; a day later a same-ID alert is
// swapped in and D2's concurrent recheck judges it and is refused. D2's
// judgement must not expire D1's and stand alone: D1's attempt, still in
// flight, must not hide the alert.
func TestExpiryKeepsTheJudgementOfAnAttemptInFlight(t *testing.T) {
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
	<-d1Judged
	d2 := make(chan journal.Status)
	go func() { st, _ := r.g.Dispatch(ctx, in.ID); d2 <- st }()
	<-d2In
	close(d1Go)
	<-d1Exec // D1 committed and is in flight
	r.now = r.now.Add(25 * time.Hour)
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

// TestExpiryKeepsTheJudgedPinOfAnUnknownAttempt (SR3-5-f2b judged): the
// pin an unknown attempt ran under outlives a day while the journal still
// holds the attempt, so its Reconcile still judges the pinned message.
func TestExpiryKeepsTheJudgedPinOfAnUnknownAttempt(t *testing.T) {
	var held []journal.Use
	x := newH(t, func(c *mail.Config) {
		c.Store = &lossy{c.Store}
		c.InUse = func(action string, _ time.Time) []journal.Use {
			if action == mail.OpArchive {
				return held
			}
			return nil
		}
	})
	x.deliver("INBOX", msg{id: "<al@x.example>", from: "someone@x.example", to: me, subject: "New sign-in", body: "x"})
	in := x.intent(mail.OpArchive, rec("<al@x.example>"))
	held = []journal.Use{{Intent: in, Started: true}}
	if e, _ := x.a.Escalate(ctx, in); e.Verb != verb.ChangeAccount {
		t.Fatalf("recheck: %+v", e)
	}
	if out := x.a.Execute(ctx, in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	x.now = x.now.Add(25 * time.Hour)
	x.a.Escalate(ctx, x.intent(mail.OpStar, rec(x.news(2))))
	if out := x.a.Reconcile(ctx, in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("reconcile: %s %q", out.Result, out.Evidence)
	}
}

// TestNilInUseNeverExpires (SR3-5-f2b nil hook): without the journal hook
// nothing is known to be settled, so a day-old judgement still has to
// agree with the recheck.
func TestNilInUseNeverExpires(t *testing.T) {
	x := newH(t, func(c *mail.Config) { c.InUse = nil })
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	x.a.Escalate(ctx, in)
	x.now = x.now.Add(25 * time.Hour)
	x.swap(id, "INBOX")
	if e, _ := x.a.Escalate(ctx, in); e.Verb != verb.ChangeAccount {
		t.Fatalf("recheck: %+v", e)
	}
	changed(t, x.a.Execute(ctx, in, 1))
	if folder, flags, _ := x.srv.Find(id); folder != "INBOX" || len(flags) != 0 {
		t.Fatalf("alert in %s with %v", folder, flags)
	}
}

// TestSettledJudgementsExpire (SR3-5-f2b control): a day-old judgement of
// an intent the journal no longer holds is dropped, so the recheck of a
// newsletter redelivered since is the only one and Execute runs.
func TestSettledJudgementsExpire(t *testing.T) {
	x := newH(t, nil)
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	x.a.Escalate(ctx, in)
	x.now = x.now.Add(25 * time.Hour)
	x.srv.Remove("INBOX", id)
	x.news(1)
	x.a.Escalate(ctx, in)
	x.mustRun2(in, 1)
	if folder, _, _ := x.srv.Find(id); folder != "Archive" {
		t.Fatalf("archive put it in %s", folder)
	}
}
