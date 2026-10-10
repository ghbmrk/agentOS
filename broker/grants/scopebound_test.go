package grants

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: ADP-9, OP-3, OP-2, OP-4

// boundRig is a rig with one invoice rule allowing one send a day and
// one per record a day (the F2 reproduction's rule).
func boundRig(t *testing.T) (*rig, func(id, rec string) journal.Status) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: 1, PerDay: 1}})
	send := func(id, rec string) journal.Status {
		r.t.Helper()
		x := sam()
		x.Record = rec
		r.ver.set(rec, x)
		return r.effect(id, "invoice.send", map[string]any{"template": "invoice", "record": rec}, "sam@example.com")
	}
	return r, send
}

// TestQueuedPreAllowedSendsObeyTheCurrentWindow (SR3-2, F2 regression):
// with one send a day and one per record a day, sends queued under STOP
// on separate days do not all run at RESUME. The first holds the day's
// place while it waits; the rest fall back to the owner's approval (ADP-9
// "no match, no silence"), and RESUME runs one without asking.
func TestQueuedPreAllowedSendsObeyTheCurrentWindow(t *testing.T) {
	r, send := boundRig(t)
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	asked := r.own.count()
	ids := []string{"agent/d1", "agent/d2", "agent/d3"}
	for i, id := range ids {
		st := send(id, "inv-1042")
		want := journal.Authorized
		if i > 0 {
			want = journal.Pending
		}
		if st.State != want {
			t.Fatalf("%s queued on day %d: %s %q, want %s", id, i+1, st.State, st.Permission.Reason, want)
		}
		r.advance(25 * time.Hour)
	}
	if err := r.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if st := r.state(id); st.State == journal.Authorized {
			r.g.Dispatch(context.Background(), id)
		}
	}
	ran := 0
	for _, id := range ids {
		ran += r.exec.runs(id)
	}
	if ran != 1 || r.exec.runs("agent/d1") != 1 {
		t.Fatalf("ran %d sends without approval at RESUME, want only agent/d1", ran)
	}
	r.g.Flush()
	if r.own.count() == asked {
		t.Fatal("the remainder was neither held nor asked")
	}
	// The started send holds the day: another for the same record asks.
	if st := send("agent/d4", "inv-1042"); st.State != journal.Pending {
		t.Fatalf("same day after RESUME: %s %q", st.State, st.Permission.Reason)
	}
}

// TestRecheckCountsStartedSends (SR3-2): the recheck before dispatch
// counts sends that started in the current window, not authorizations,
// so a retry of a send that did not apply cannot run past one that did.
func TestRecheckCountsStartedSends(t *testing.T) {
	r, send := boundRig(t)
	r.exec.fail = map[string]bool{"agent/a": true}
	if st := send("agent/a", "inv-a"); st.State != journal.NotApplied {
		t.Fatalf("a: %s %q", st.State, st.Permission.Reason)
	}
	// Not applied releases the place: b takes it and runs.
	if st := send("agent/b", "inv-b"); st.State != journal.Succeeded {
		t.Fatalf("b after a did not apply: %s %q", st.State, st.Permission.Reason)
	}
	r.exec.fail = nil
	st, err := r.g.Dispatch(context.Background(), "agent/a")
	if err == nil || st.State != journal.Denied || r.exec.runs("agent/a") != 1 {
		t.Fatalf("retry past the bound: %s %v, ran %d", st.State, err, r.exec.runs("agent/a"))
	}
	// Window boundary: once b's start is a day old, a new send fits.
	r.advance(24*time.Hour + time.Second)
	if st := send("agent/c", "inv-c"); st.State != journal.Succeeded {
		t.Fatalf("next day: %s %q", st.State, st.Permission.Reason)
	}
}

// TestRacingRetriesStartOneEffect (SR3-2): two retries racing for the
// last place in the window start at most one external effect. The engine
// commits a dispatch only if nothing was journaled since its recheck, so
// the loser rechecks against the winner's start.
func TestRacingRetriesStartOneEffect(t *testing.T) {
	for round := 0; round < 20; round++ {
		r, send := boundRig(t)
		a, b := fmt.Sprintf("agent/a%d", round), fmt.Sprintf("agent/b%d", round)
		r.exec.fail = map[string]bool{a: true, b: true}
		for _, id := range []string{a, b} {
			if st := send(id, "inv-"+id); st.State != journal.NotApplied {
				t.Fatalf("%s: %s %q", id, st.State, st.Permission.Reason)
			}
		}
		r.exec.mu.Lock()
		r.exec.fail = nil
		r.exec.mu.Unlock()
		var wg sync.WaitGroup
		for _, id := range []string{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.g.Dispatch(context.Background(), id)
			}()
		}
		wg.Wait()
		if n := r.exec.runs(a) + r.exec.runs(b); n != 3 {
			t.Fatalf("round %d: %d attempts, want the two failures and one retry", round, n)
		}
	}
}

// TestStartedSendSurvivesRestart (SR3-2, OP-4): a send journaled as
// dispatched before a crash, its executor not yet returned, still holds
// its place after the restart replays it as outcome_unknown, and after
// evidence resolves it as sent it is charged to the window it started in,
// not the one it was authorized in.
func TestStartedSendSurvivesRestart(t *testing.T) {
	r, send := boundRig(t)
	block := make(chan struct{})
	r.exec.block = map[string]chan struct{}{"agent/a": block}
	x := sam()
	x.Record = "inv-a"
	r.ver.set("inv-a", x)
	if _, err := r.g.Submit(journal.Intent{ID: "agent/a", Origin: "guest:agent", Account: "mail", Action: "invoice.send",
		Params: map[string]any{"template": "invoice", "record": "inv-a"}, Recipients: []string{"sam@example.com"},
		Executor: "mail", Machine: "agent", Label: "private"}); err != nil {
		t.Fatal(err)
	}
	if st, err := r.g.Authorize(context.Background(), "agent/a"); err != nil || st.State != journal.Authorized {
		t.Fatalf("authorize a: %s %v", st.State, err)
	}
	// Authorized a day before it starts, as if queued.
	r.advance(25 * time.Hour)
	before, _ := r.store.ReadAll()
	marks := bytes.Count(before, []byte(`"dispatched"`))
	old := r.g
	done := make(chan struct{})
	go func() {
		defer close(done)
		old.Dispatch(context.Background(), "agent/a")
	}()
	var snap []byte
	for i := 0; ; i++ {
		snap, _ = r.store.ReadAll()
		if bytes.Count(snap, []byte(`"dispatched"`)) > marks {
			break
		}
		if i > 1000 {
			t.Fatal("agent/a never dispatched")
		}
		time.Sleep(time.Millisecond)
	}
	// Restart on the journal as it stood mid-execution.
	r.store = &journal.MemStore{}
	if err := r.store.Rewrite(snap); err != nil {
		t.Fatal(err)
	}
	r.open()
	close(block)
	<-done
	old.Wait()

	r.advance(time.Hour)
	if st := r.state("agent/a"); st.State != journal.OutcomeUnknown {
		t.Fatalf("after restart: %s", st.State)
	}
	if _, err := r.eng.Resolve("agent/a", 1, journal.Outcome{Result: journal.ResultSucceeded, Evidence: "in Sent"}, "owner"); err != nil {
		t.Fatal(err)
	}
	if st := send("agent/b", "inv-b"); st.State != journal.Pending || r.exec.runs("agent/b") != 0 {
		t.Fatalf("b in the same window: %s %q", st.State, st.Permission.Reason)
	}
}

// TestQueuedDeliveriesObeyTheDailyCap (SR3-2, F2 on the evidence path):
// deliveries queued under STOP across days hold their places, so at
// RESUME no more than DeliveryCap run in one window.
func TestQueuedDeliveriesObeyTheDailyCap(t *testing.T) {
	r, _ := evidenceRig(t, nil)
	r.setEvidence(OriginOwner, ownAddr, true)
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for day := 0; day < 2; day++ {
		for i := 0; i < DeliveryCap; i++ {
			id := fmt.Sprintf("ev/%d/%d", day, i)
			ids = append(ids, id)
			r.deliver(id, OriginEvidence, body("x"), ownAddr)
		}
		r.advance(25 * time.Hour)
	}
	if err := r.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, id := range ids {
		if st := r.state(id); st.State == journal.Authorized {
			r.g.Dispatch(context.Background(), id)
		}
		ran += r.exec.runs(id)
	}
	if ran > DeliveryCap {
		t.Fatalf("%d deliveries ran in one window, cap %d", ran, DeliveryCap)
	}
}
