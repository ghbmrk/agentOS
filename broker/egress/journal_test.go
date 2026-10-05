package egress

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: ADP-10

type recorder struct {
	notes []journal.EgressNote
	fail  bool
}

func (r *recorder) RecordEgress(n journal.EgressNote) error {
	if r.fail {
		return errors.New("disk")
	}
	r.notes = append(r.notes, n)
	return nil
}

// TestADP10EgressDenialsGoToTheJournal: the proxy's auditor journals every
// denial and nothing else (E6).
func TestADP10EgressDenialsGoToTheJournal(t *testing.T) {
	rec := &recorder{}
	j := &JournalAuditor{Journal: rec}
	j.Egress(Event{Machine: "m1", Allowed: true, Status: 200})
	j.Egress(Event{Machine: "m1", Adapter: "openai", Method: "GET", Status: 403, Reason: "no declared operation matches", Path: "/openai/v1/files"})
	if len(rec.notes) != 1 || rec.notes[0].Reason != "no declared operation matches" || rec.notes[0].Status != 403 {
		t.Fatalf("%+v", rec.notes)
	}
	var logged bytes.Buffer
	(&JournalAuditor{Journal: &recorder{fail: true}, Logf: func(f string, a ...any) { fmt.Fprintf(&logged, f, a...) }}).Egress(Event{Machine: "m1"})
	if logged.Len() == 0 {
		t.Fatal("a failed journal write went unreported")
	}
}

// TestADP10DenialFloodsAreCoalesced: a guest looping on a denied request
// adds one journal record per machine and reason per minute, and the next
// record carries how many were folded into it.
func TestADP10DenialFloodsAreCoalesced(t *testing.T) {
	rec := &recorder{}
	now := time.Unix(1_800_000_000, 0)
	j := &JournalAuditor{Journal: rec, Now: func() time.Time { return now }}
	for i := 0; i < 1000; i++ {
		j.Egress(Event{Machine: "m1", Status: 403, Reason: "no such adapter"})
	}
	j.Egress(Event{Machine: "m2", Status: 403, Reason: "no such adapter"})
	j.Egress(Event{Machine: "m1", Status: 403, Reason: "body too large"})
	// A guest-chosen key name in the reason does not open a new entry.
	for i := 0; i < 100; i++ {
		j.Egress(Event{Machine: "m1", Status: 403, Reason: fmt.Sprintf("body key %q needs a public machine", fmt.Sprint("k", i))})
	}
	if len(rec.notes) != 4 {
		t.Fatalf("journaled %d notes, want 4", len(rec.notes))
	}
	now = now.Add(61 * time.Second)
	j.Egress(Event{Machine: "m1", Status: 403, Reason: "no such adapter"})
	if n := rec.notes[len(rec.notes)-1]; len(rec.notes) != 5 || n.Suppressed != 999 {
		t.Fatalf("after the window: %+v", rec.notes)
	}
}
