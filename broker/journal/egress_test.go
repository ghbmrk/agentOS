package journal

// REQ: ADP-10

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestADP10EgressDenialsAreJournaledAndReplayed: a denied egress request is
// a journal record of its own, durable and replayed like any other, with
// guest-chosen text redacted and clipped.
func TestADP10EgressDenialsAreJournaledAndReplayed(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	n := EgressNote{Machine: "m1", Adapter: "openai", Operation: "chat.completions", Method: "POST", Status: 403, Reason: `body key "` + canary + `" not allowed`}
	if err := e.RecordEgress(n); err != nil {
		t.Fatal(err)
	}
	if err := e.RecordEgress(EgressNote{Machine: "m1", Method: "GET\r\nX: " + strings.Repeat("a", 200), Status: 403, Reason: "no such adapter"}); err != nil {
		t.Fatal(err)
	}
	reopened := mustOpen(t, st, newPolicy(), newService())
	var got []EgressNote
	for _, r := range reopened.Trail() {
		if r.Type == RecEgress {
			got = append(got, *r.Egress)
		}
	}
	if len(got) != 2 {
		t.Fatalf("replayed %d egress records, want 2", len(got))
	}
	if strings.Contains(got[0].Reason, canary) {
		t.Fatalf("reason not redacted: %q", got[0].Reason)
	}
	if got[0].Machine != "m1" || got[0].Adapter != "openai" || got[0].Status != 403 {
		t.Fatalf("identifiers changed: %+v", got[0])
	}
	if m := got[1].Method; m != "?" {
		t.Fatalf("a guest-chosen method that is not a token is kept as %q", m)
	}
}

func TestADP10EgressNoteNeedsMachineAndReason(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	for _, n := range []EgressNote{{Reason: "x"}, {Machine: "m1"}} {
		if err := e.RecordEgress(n); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: err = %v, want ErrInvalid", n, err)
		}
	}
}

// TestADP10EgressRecordsDoNotDisturbIntents: audit records are journaled
// during STOP and between intent steps without changing intent state.
func TestADP10EgressRecordsDoNotDisturbIntents(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	must(e.Submit(intent("a", "acct")))
	if _, err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.RecordEgress(EgressNote{Machine: "m1", Reason: "spend limit"}); err != nil {
		t.Fatalf("egress record refused during STOP: %v", err)
	}
	if err := e.Resume(); err != nil {
		t.Fatal(err)
	}
	if s := must(e.Get("a")); s.State != Pending {
		t.Fatalf("intent state %s", s.State)
	}
}

// TestADP10GateNeverAdmitsUntracked: once every key in the coalescing
// table is live, a new reason class is folded into the machine's overflow
// entry, so a guest minting reasons gets at most one record per window.
func TestADP10GateNeverAdmitsUntracked(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := &EgressGate{Now: func() time.Time { return now }}
	for i := 0; i < maxEgressKeys; i++ {
		if !g.Admit(&EgressNote{Machine: "m1", Reason: fmt.Sprint("reason ", i)}) {
			t.Fatalf("reason %d not admitted while the table had room", i)
		}
	}
	admitted := 0
	for i := 0; i < 500; i++ {
		if g.Admit(&EgressNote{Machine: "m1", Reason: fmt.Sprint("overflow ", i)}) {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("admitted %d notes past a full table in one window, want 1", admitted)
	}
	if !g.Admit(&EgressNote{Machine: "m2", Reason: "another machine"}) {
		t.Fatal("another machine's first overflow note was not admitted")
	}
	now = now.Add(61 * time.Second)
	n := &EgressNote{Machine: "m1", Reason: "overflow again"}
	// The window ended: expired keys are pruned, so this one is tracked
	// on its own again.
	if !g.Admit(n) {
		t.Fatalf("after the window: %+v not admitted", n)
	}
}
