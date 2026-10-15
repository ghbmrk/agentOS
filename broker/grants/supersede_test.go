package grants

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-2

// B6 at the gate: the send of invoice 1042 to sam is proved not done
// after a restart and its resend refused (the approval lived in memory),
// so RETRY offers it. Before the owner answers, the agent resubmits the
// same send, the owner approves that and it goes. The send is then no
// longer offered, and the owner's approval of the RETRY line already
// shown is refused and spent: invoice 1042 goes once.
func TestOP2NotDoneSendIsNotResentAfterAResubmissionWent(t *testing.T) {
	ctx := context.Background()
	r := killedSend(t, true)
	ns := r.eng.NotResent()
	if len(ns) != 1 || ns[0].Intent.ID != "agent/s1" {
		t.Fatalf("not resent %+v", ns)
	}
	l := r.g.RetryItem(ctx, ns[0], "an email")

	if st := r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042", "template": "invoice"}, "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("resubmit: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	req, _ := r.own.last(t)
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
	deadline := time.Now().Add(5 * time.Second)
	for r.state("agent/s2").State != journal.Succeeded {
		if time.Now().After(deadline) {
			t.Fatalf("s2: %+v", r.state("agent/s2"))
		}
		time.Sleep(time.Millisecond)
	}
	if ns := r.eng.NotResent(); len(ns) != 0 {
		t.Fatalf("still offered after the resubmission went: %+v", ns)
	}
	_, err := r.g.Resend(ctx, "agent/s1", ns[0].Attempt, l, false)
	var se *journal.SupersededError
	if !errors.As(err, &se) || se.By != "agent/s2" || !errors.Is(err, journal.ErrState) {
		t.Fatalf("resend: %v", err)
	}
	if r.exec.runs("agent/s1") != 0 || r.exec.runs("agent/s2") != 1 {
		t.Fatalf("invoice 1042 sent: s1 %d, s2 %d", r.exec.runs("agent/s1"), r.exec.runs("agent/s2"))
	}
	r.g.mu.Lock()
	_, left := r.g.decided["agent/s1"]
	r.g.mu.Unlock()
	if left {
		t.Fatal("the refused resend's approval was not spent")
	}
}

// waitFor waits until id reaches want.
func waitFor(t *testing.T, r *rig, id string, want journal.State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.state(id).State != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: %+v", id, r.state(id))
		}
		time.Sleep(time.Millisecond)
	}
}

// resubmit is the agent sending invoice 1042 to sam again as id; it
// waits for the owner's approval.
func resubmit(t *testing.T, r *rig, id string, params map[string]any, to string) string {
	t.Helper()
	if st := r.effect(id, "invoice.send", params, to); st.State != journal.Pending {
		t.Fatalf("resubmit %s: %s %q", id, st.State, st.Permission.Reason)
	}
	r.g.Flush()
	req, _ := r.own.last(t)
	return req
}

func invoice1042() map[string]any { return map[string]any{"record": "inv-1042", "template": "invoice"} }

// B7 at the gate, the mirror of B6: the agent's resubmission s2 waits for
// approval when the owner approves the RETRY line of s1. That resend is
// refused (s2 waits to send the same invoice) and its approval spent;
// the owner then approves s2, which goes. Invoice 1042 goes once.
func TestOP2NotDoneSendIsNotResentWhileAResubmissionWaits(t *testing.T) {
	ctx := context.Background()
	r := killedSend(t, true)
	ns := r.eng.NotResent()
	if len(ns) != 1 || ns[0].Intent.ID != "agent/s1" {
		t.Fatalf("not resent %+v", ns)
	}
	l := r.g.RetryItem(ctx, ns[0], "an email")
	req := resubmit(t, r, "agent/s2", invoice1042(), "sam@example.com")
	if ns := r.eng.NotResent(); len(ns) != 0 {
		t.Fatalf("offered while the resubmission waits: %+v", ns)
	}
	_, err := r.g.Resend(ctx, "agent/s1", ns[0].Attempt, l, false)
	var se *journal.SupersededError
	if !errors.As(err, &se) || se.By != "agent/s2" {
		t.Fatalf("resend: %v", err)
	}
	r.g.mu.Lock()
	_, left := r.g.decided["agent/s1"]
	r.g.mu.Unlock()
	if left {
		t.Fatal("the refused resend's approval was not spent")
	}
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
	waitFor(t, r, "agent/s2", journal.Succeeded)
	if r.exec.runs("agent/s1") != 0 || r.exec.runs("agent/s2") != 1 {
		t.Fatalf("invoice 1042 sent: s1 %d, s2 %d", r.exec.runs("agent/s1"), r.exec.runs("agent/s2"))
	}
}

// The other order: the owner's RETRY of s1 goes before the agent
// resubmits. A request made after s1 went is a new send (journal A19, B8):
// the owner is asked about it as any send and, approved, it goes. Only a
// request made before s1 went is refused.
func TestOP2SendRequestedAfterTheResendWentIsANewSend(t *testing.T) {
	ctx := context.Background()
	r := killedSend(t, true)
	ns := r.eng.NotResent()
	l := r.g.RetryItem(ctx, ns[0], "an email")
	if st, err := r.g.Resend(ctx, "agent/s1", ns[0].Attempt, l, false); err != nil || st.State != journal.Succeeded {
		t.Fatalf("resend: %+v %v", st, err)
	}
	req := resubmit(t, r, "agent/s2", invoice1042(), "sam@example.com")
	// Confirm repeats (D-116): the ask says the same send was already
	// sent, and when, at the tier its facts give.
	s1 := r.state("agent/s1")
	went := s1.Attempts[len(s1.Attempts)-1].Dispatched
	if _, items := r.own.last(t); len(items) != 1 || !items[0].Sent.Equal(went) || !items[0].Retried.IsZero() || items[0].Facts.Kind == owner.MoneyRetry {
		t.Fatalf("s2's ask %+v, want it marked as sent at %v", items, went)
	}
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
	waitFor(t, r, "agent/s2", journal.Succeeded)
	if r.exec.runs("agent/s1") != 1 || r.exec.runs("agent/s2") != 1 {
		t.Fatalf("invoice 1042 sent: s1 %d, s2 %d", r.exec.runs("agent/s1"), r.exec.runs("agent/s2"))
	}
	// Another invoice to the same recipient is not marked.
	resubmit(t, r, "agent/s3", map[string]any{"record": "inv-1043", "template": "invoice"}, "sam@example.com")
	if _, items := r.own.last(t); len(items) != 1 || !items[0].Retried.IsZero() || !items[0].Sent.IsZero() {
		t.Fatalf("s3's ask %+v is marked", items)
	}
}

// R7 at the gate: after the resubmission s2 went, the agent repeats
// request s1. Its dispatch is refused by the engine's same check, with
// no owner prompt, and s1 is denied.
func TestOP2RepeatedRequestForANotDoneSendIsRefusedAfterItsResubmissionWent(t *testing.T) {
	r := killedSend(t, true)
	req := resubmit(t, r, "agent/s2", invoice1042(), "sam@example.com")
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
	waitFor(t, r, "agent/s2", journal.Succeeded)
	st, err := r.g.Dispatch(context.Background(), "agent/s1")
	var se *journal.SupersededError
	if !errors.As(err, &se) || se.By != "agent/s2" || st.State != journal.Denied {
		t.Fatalf("repeat of s1: %+v %v", st, err)
	}
	if g := st.Permission.GuestReason; g == "" || strings.Contains(g, "agent/") {
		t.Fatalf("s1 guest text %q", g)
	}
	if r.exec.runs("agent/s1") != 0 || r.exec.runs("agent/s2") != 1 {
		t.Fatalf("invoice 1042 sent: s1 %d, s2 %d", r.exec.runs("agent/s1"), r.exec.runs("agent/s2"))
	}
}

// R7, pre-allowed: under a pre-allowance no owner is asked. s1 is killed
// mid-send, a check proves it not done and STOP refuses its resend; after
// RESUME the agent resubmits it as s2, which goes, then repeats request
// s1, which is refused.
func TestOP2PreAllowedRepeatOfANotDoneSendIsRefused(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: 3, PerDay: 5, HoldDays: 7}})
	r.ver.set("inv-1042", sam())
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	r.exec.mu.Lock()
	r.exec.block = map[string]chan struct{}{"agent/s1": hold}
	r.exec.entered = make(chan string, 4)
	entered := r.exec.entered
	r.exec.mu.Unlock()
	s1 := journal.Intent{ID: "agent/s1", Origin: "guest:agent", Account: "mail", Action: "invoice.send",
		Params: invoice1042(), Recipients: []string{"sam@example.com"}, Executor: "mail", Machine: "agent", Label: "private"}
	go func() {
		defer func() { _ = recover() }()
		_, _ = r.g.Submit(s1)
		_, _ = r.g.Authorize(ctx, "agent/s1")
		_, _ = r.g.Dispatch(ctx, "agent/s1")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for st, _ := r.g.Get("agent/s1"); len(st.Attempts) == 0; st, _ = r.g.Get("agent/s1") {
		if time.Now().After(deadline) {
			t.Fatalf("s1 never dispatched: %+v", st)
		}
		time.Sleep(time.Millisecond)
	}
	// s1 must be parked on hold before block is cleared (see killedSend).
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("s1 never reached Execute")
	}
	data, err := r.store.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	r.store = &journal.MemStore{}
	if err := r.store.Rewrite(data); err != nil {
		t.Fatal(err)
	}
	r.exec.mu.Lock()
	r.exec.block = nil
	r.exec.entered = nil
	r.exec.notDone = map[string]bool{"agent/s1": true}
	r.exec.mu.Unlock()
	r.open()
	if _, err := r.eng.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	r.eng.SettleUnknown(ctx, 0, 0)
	if st := r.state("agent/s1"); st.State != journal.NotApplied || len(r.eng.NotResent()) != 1 {
		t.Fatalf("s1 %+v", st)
	}
	if err := r.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	if st := r.effect("agent/s2", "invoice.send", invoice1042(), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("s2: %s %q", st.State, st.Permission.Reason)
	}
	_, err = r.g.Dispatch(ctx, "agent/s1")
	var se *journal.SupersededError
	if !errors.As(err, &se) || se.By != "agent/s2" {
		t.Fatalf("repeat of s1: %v", err)
	}
	if r.exec.runs("agent/s1") != 0 || r.exec.runs("agent/s2") != 1 {
		t.Fatalf("invoice 1042 sent: s1 %d, s2 %d", r.exec.runs("agent/s1"), r.exec.runs("agent/s2"))
	}
}

// R9: a resubmission that differs from the not-done send in a byte the
// engine's effect fingerprint covers (an extra param, a recipient's case)
// is not matched by it (journal A19), so both may go. The RETRY line then
// warns "may go twice", since the gate reads the same verified record
// and recipients; without such a send it does not.
func TestOP2RetryLineWarnsOfANearResubmission(t *testing.T) {
	for _, c := range []struct {
		name   string
		params map[string]any
		to     string
	}{
		{"extra param", map[string]any{"record": "inv-1042", "template": "invoice", "note": "resend"}, "sam@example.com"},
		{"recipient case", invoice1042(), "Sam@Example.com"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			r := killedSend(t, true)
			ns := r.eng.NotResent()
			if l := r.g.RetryItem(ctx, ns[0], "an email"); !l.Shown.Retried.IsZero() {
				t.Fatalf("warned with no other send: %+v", l.Shown)
			}
			req := resubmit(t, r, "agent/s2", c.params, c.to)
			r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
			waitFor(t, r, "agent/s2", journal.Succeeded)
			ns = r.eng.NotResent()
			if len(ns) != 1 {
				t.Fatalf("not resent %+v", ns)
			}
			l := r.g.RetryItem(ctx, ns[0], "an email")
			if !l.Shown.Retried.Equal(ns[0].Dispatched) || l.Shown.Facts.Kind != owner.MoneyRetry {
				t.Fatalf("near resubmission not warned: %+v", l.Shown)
			}
			// Erased (CAP-3), it names no record, and still counts.
			if er, _, err := r.eng.Erase([]string{"agent/s2"}); err != nil || len(er) != 1 {
				t.Fatalf("erase: %v %v", er, err)
			}
			if l := r.g.RetryItem(ctx, ns[0], "an email"); l.Shown.Retried.IsZero() {
				t.Fatalf("erased near resubmission not warned: %+v", l.Shown)
			}
		})
	}
}

// Without a verifier for the account, sentSince compares the record the
// intents name and their recipients with case folded.
func TestOP2NearResubmissionKeyWithoutAVerifier(t *testing.T) {
	r := newRig(t, nil)
	in := journal.Intent{ID: "x", Account: "no-verifier", Action: "invoice.send",
		Params: invoice1042(), Recipients: []string{" Sam@Example.COM"}}
	rec, to := r.g.sendKey(context.Background(), in)
	if rec != "inv-1042" || len(to) != 1 || to[0] != "sam@example.com" {
		t.Fatalf("key %q %q", rec, to)
	}
}

// R9b: a near resubmission that is still waiting for approval, not only
// one that went, makes the RETRY line warn "may go twice": the owner
// could otherwise approve both. The verifier reads the same record from
// a param spelled another way, which the comparison must follow.
func TestOP2RetryLineWarnsOfAWaitingNearResubmission(t *testing.T) {
	ctx := context.Background()
	r := killedSend(t, true)
	r.ver.set("INV-1042", sam())
	ns := r.eng.NotResent()
	if len(ns) != 1 {
		t.Fatalf("not resent %+v", ns)
	}
	if l := r.g.RetryItem(ctx, ns[0], "an email"); !l.Shown.Retried.IsZero() {
		t.Fatalf("warned with no other send: %+v", l.Shown)
	}
	resubmit(t, r, "agent/s2", map[string]any{"record": "INV-1042", "template": "invoice"}, "sam@example.com")
	if st := r.state("agent/s2"); st.State != journal.Pending {
		t.Fatalf("s2: %+v", st)
	}
	l := r.g.RetryItem(ctx, ns[0], "an email")
	if !l.Shown.Retried.Equal(ns[0].Dispatched) || l.Shown.Facts.Kind != owner.MoneyRetry {
		t.Fatalf("waiting near resubmission not warned: %+v", l.Shown)
	}
	// Another record is not a near resubmission.
	r2 := killedSend(t, true)
	r2.ver.set("inv-77", Verified{Record: "inv-77", Recipients: []string{"sam@example.com"}})
	resubmit(t, r2, "agent/s3", map[string]any{"record": "inv-77", "template": "invoice"}, "sam@example.com")
	ns = r2.eng.NotResent()
	if l := r2.g.RetryItem(ctx, ns[0], "an email"); !l.Shown.Retried.IsZero() {
		t.Fatalf("warned of another record: %+v", l.Shown)
	}
}

// B8 at the gate: an owner PAUSE cut off by a restart is proved not done
// by the check and sent again. Pauses and revokes only take authority
// away (ADP-9), so later ones, of any grant, are never refused as the
// same effect.
func TestOP2PauseAfterARestartedPauseStillWorks(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	var rules []string
	for i := 0; i < 4; i++ {
		rules = append(rules, r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", AmountCap: 15000, PerRecord: 5 + i, PerDay: 50}}))
	}
	if got := r.g.Narrow("PAUSE", rules[0]); !strings.HasPrefix(got, "Paused") {
		t.Fatal(got)
	}
	// The kill: the journal as it was after the pause's dispatched record.
	data, err := r.store.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	cut := -1
	for i, l := range lines {
		if bytes.Contains(l, []byte(`"dispatched"`)) && bytes.Contains(l, []byte("owner/pause/")) {
			cut = i
		}
	}
	if cut < 0 {
		t.Fatalf("no dispatched pause in %s", data)
	}
	r.store = &journal.MemStore{}
	if err := r.store.Rewrite(bytes.Join(lines[:cut+1], nil)); err != nil {
		t.Fatal(err)
	}
	r.open()
	r.eng.Reconcile(context.Background())
	for _, g := range rules[1:] {
		if got := r.g.Narrow("PAUSE", g); !strings.HasPrefix(got, "Paused") {
			t.Fatalf("PAUSE %s: %q", g, got)
		}
	}
	for _, g := range rules[1:3] {
		if got := r.g.Narrow("REVOKE", g); !strings.HasPrefix(got, "Revoked") {
			t.Fatalf("REVOKE %s: %q", g, got)
		}
	}
	if got := r.g.Narrow("PAUSE", rules[3]); !strings.HasPrefix(got, "Paused") {
		t.Fatalf("second PAUSE of %s: %q", rules[3], got)
	}
}
