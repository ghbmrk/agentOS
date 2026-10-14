package grants

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-2

// parkedSend leaves an approved invoice send to sam with an unknown
// outcome: the broker is killed while the send runs, and on restart no
// check settles it, so it is parked.
func parkedSend(t *testing.T) (*rig, journal.ParkedIntent) {
	t.Helper()
	r := killedSend(t, false)
	ps := r.eng.Parked()
	if len(ps) != 1 || ps[0].Intent.ID != "agent/s1" {
		t.Fatalf("parked %+v", ps)
	}
	return r, ps[0]
}

// killedSend kills the broker while an approved invoice send to sam runs
// and settles it after the restart. notDone: the check proves the send was
// not done; otherwise no check can tell.
func killedSend(t *testing.T, notDone bool) *rig {
	t.Helper()
	ctx := context.Background()
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	r.exec.mu.Lock()
	r.exec.block = map[string]chan struct{}{"agent/s1": hold}
	r.exec.entered = make(chan string, 4)
	entered := r.exec.entered
	r.exec.mu.Unlock()
	if st := r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042", "template": "invoice"}, "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("send: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	req, _ := r.own.last(t)
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s1", Approved: true, Why: "owner"})
	for st := r.state("agent/s1"); len(st.Attempts) == 0; st = r.state("agent/s1") {
		time.Sleep(time.Millisecond)
	}
	// The pre-kill attempt must be parked on hold before block is cleared,
	// or it reads a nil block, runs, and leaks into the restarted counts.
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the pre-kill attempt never reached Execute")
	}
	// The kill: the restarted broker reads the journal as it was.
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
	r.exec.notDone = map[string]bool{"agent/s1": notDone}
	r.exec.mu.Unlock()
	r.open()
	r.eng.SettleUnknown(ctx, 0, 0)
	return r
}

// P1b (OP-2): the broker restarts after an approved send was dispatched,
// and the check proves it did not go. The engine's own resend is refused,
// because the owner's approval lived in memory, so the send is listed as
// not resent instead of dropped. Its RETRY line is the ordinary verified
// ask at the tier its facts give, with no "may go twice", and the owner's
// approval sends it once; a parked-effect retry does not.
func TestOP2NotDoneSendIsOfferedAgainAfterARestart(t *testing.T) {
	ctx := context.Background()
	r := killedSend(t, true)
	if ps := r.eng.Parked(); len(ps) != 0 {
		t.Fatalf("parked %+v", ps)
	}
	ns := r.eng.NotResent()
	if len(ns) != 1 || ns[0].Intent.ID != "agent/s1" || !ns[0].NotDone || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("not resent %+v, ran %d", ns, r.exec.runs("agent/s1"))
	}
	l := r.g.RetryItem(ctx, ns[0], "an email")
	it := l.Shown
	if it.Object != "invoice 1042" || it.Recipient != "sam@example.com" || it.Amount != "$120.00" || !it.Retried.IsZero() {
		t.Fatalf("resend line %+v", it)
	}
	if it.Facts.Kind == owner.MoneyRetry || it.Facts != l.Base.Facts {
		t.Fatalf("resend tier: shown %+v, base %+v", it.Facts, l.Base.Facts)
	}
	if _, err := r.g.Retry(ctx, "agent/s1", ns[0].Attempt, l, false); !errors.Is(err, journal.ErrState) || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("parked retry of a not-done send: %v, ran %d", err, r.exec.runs("agent/s1"))
	}
	st, err := r.g.Resend(ctx, "agent/s1", ns[0].Attempt, l, false)
	if err != nil || st.State != journal.Succeeded || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("resend: %s %v, ran %d", st.State, err, r.exec.runs("agent/s1"))
	}
	if ns := r.eng.NotResent(); len(ns) != 0 {
		t.Fatalf("still listed %+v", ns)
	}
	r.g.mu.Lock()
	_, left := r.g.decided["agent/s1"]
	r.g.mu.Unlock()
	if left {
		t.Fatal("the resend's approval was not spent")
	}
	if _, err := r.g.Resend(ctx, "agent/s1", ns[0].Attempt, l, false); !errors.Is(err, journal.ErrState) || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("second resend: %v, ran %d", err, r.exec.runs("agent/s1"))
	}
}

// A retry is asked from the effect's verified line, never from fixed
// words: the recipient and amount the source holds, when it was first
// tried, and the tier its facts give, except that money is always high.
// The owner's approval then passes the dispatch recheck once.
func TestOP2RetryLineIsTheVerifiedLine(t *testing.T) {
	ctx := context.Background()
	r, p := parkedSend(t)
	l := r.g.RetryItem(ctx, p, "an email")
	it := l.Shown
	if it.Object != "invoice 1042" || it.Recipient != "sam@example.com" || it.Amount != "$120.00" || it.Facts.NoRecipient ||
		!it.Facts.HasAmount || it.Retried.IsZero() || !it.Retried.Equal(p.Dispatched) {
		t.Fatalf("retry line %+v", it)
	}
	if it.Facts.Kind != owner.MoneyRetry || r.own.Tier(it.Facts) != owner.High || l.Base.Facts.Kind == owner.MoneyRetry {
		t.Fatalf("money retry tier: shown %+v, base %+v", it.Facts, l.Base.Facts)
	}

	// A line the source no longer gives fails the recheck and runs nothing.
	bad := l
	bad.Base.Recipient = "eve@example.com"
	if _, err := r.g.Retry(ctx, "agent/s1", p.Attempt, bad, false); !errors.Is(err, journal.ErrRecheck) || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("changed line: %v, ran %d", err, r.exec.runs("agent/s1"))
	}
	if ps := r.eng.Parked(); len(ps) != 1 {
		t.Fatalf("parked %+v", ps)
	}

	st, err := r.g.Retry(ctx, "agent/s1", p.Attempt, l, false)
	if err != nil || st.State != journal.Succeeded || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("retry: %s %v, ran %d", st.State, err, r.exec.runs("agent/s1"))
	}
	r.g.mu.Lock()
	_, left := r.g.decided["agent/s1"]
	r.g.mu.Unlock()
	if left {
		t.Fatal("the retry's approval was not spent")
	}
	if _, err := r.g.Retry(ctx, "agent/s1", p.Attempt, l, false); !errors.Is(err, journal.ErrState) || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("second retry: %v, ran %d", err, r.exec.runs("agent/s1"))
	}
}

// A line that is approved only on the local page is not retried on an
// answer from anywhere else.
func TestOP2LocalRetryNeedsThePage(t *testing.T) {
	ctx := context.Background()
	r, p := parkedSend(t)
	l := r.g.RetryItem(ctx, p, "an email")
	l.Local = true
	if _, err := r.g.Retry(ctx, "agent/s1", p.Attempt, l, false); !errors.Is(err, ErrRetryNotConfirmed) || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("local line without the page: %v, ran %d", err, r.exec.runs("agent/s1"))
	}
}
