package egress

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

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
	j := JournalAuditor{Journal: rec}
	j.Egress(Event{Machine: "m1", Allowed: true, Status: 200})
	j.Egress(Event{Machine: "m1", Adapter: "openai", Method: "GET", Status: 403, Reason: "no declared operation matches", Path: "/openai/v1/files"})
	if len(rec.notes) != 1 || rec.notes[0].Reason != "no declared operation matches" || rec.notes[0].Status != 403 {
		t.Fatalf("%+v", rec.notes)
	}
	var logged bytes.Buffer
	JournalAuditor{Journal: &recorder{fail: true}, Logf: func(f string, a ...any) { fmt.Fprintf(&logged, f, a...) }}.Egress(Event{Machine: "m1"})
	if logged.Len() == 0 {
		t.Fatal("a failed journal write went unreported")
	}
}
