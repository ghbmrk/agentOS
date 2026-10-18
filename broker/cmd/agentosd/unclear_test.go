package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: DRA-3, OP-2, CH-12

// unclearNoteOver is an unclear note over a fixed list, read in UTC.
func unclearNoteOver(waiting *[]journal.ParkedIntent) *unclearNote {
	n := &unclearNote{loc: time.UTC}
	n.set(func() []journal.ParkedIntent { return *waiting })
	return n
}

// checkNote fails on a note STATUS would cut or change, that is not
// GSM-7, or that names a recipient or an internal ID.
func checkNote(t *testing.T, l string) {
	t.Helper()
	if len(l) > unclearNoteMax || strings.Contains(l, "canary") || strings.Contains(l, "m1/r1") {
		t.Fatalf("note %q", l)
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" .,;:()-", r)) {
			t.Fatalf("STATUS drops %q from %q", r, l)
		}
	}
	if _, gsm := modem.Segments(l); !gsm {
		t.Fatalf("not GSM-7: %q", l)
	}
}

// STATUS names a parked effect in the owner's words and when it was first
// tried, says it was not retried and that RETRY may send it twice, counts
// several, and keeps listing them for as long as they wait.
func TestStatusListsUnclearEffects(t *testing.T) {
	var parked []journal.ParkedIntent
	if l := (&unclearNote{loc: time.UTC}).line(); l != "" {
		t.Fatalf("before Run: %q", l)
	}
	n := unclearNoteOver(&parked)
	if l := n.line(); l != "" {
		t.Fatalf("nothing parked: %q", l)
	}
	parked = []journal.ParkedIntent{
		{Intent: journal.Intent{ID: "m1/r1", Executor: "mail", Recipients: []string{"canary@example.invalid"}}, Attempt: 1, Seq: 7,
			Dispatched: time.Date(2026, 10, 13, 14, 2, 0, 0, time.UTC)},
	}
	for range 2 {
		l := n.line()
		checkNote(t, l)
		// With when it was first tried, the line passes STATUS's cut, so
		// the time is dropped rather than the RETRY warning.
		if l != "An email may not have gone; not retried. Text RETRY to try again; it may go twice." {
			t.Fatalf("one parked: %q", l)
		}
	}
	parked = append(parked, journal.ParkedIntent{Intent: journal.Intent{ID: "p1", Executor: "payments-stub"}, Attempt: 2, Seq: 9})
	l := n.line()
	checkNote(t, l)
	if !strings.HasPrefix(l, "2 actions may not have gone") || !strings.Contains(l, "RETRY") || !strings.Contains(l, "may go twice") {
		t.Fatalf("two parked: %q", l)
	}
	for range 200 {
		parked = append(parked, parked[1])
	}
	checkNote(t, n.line())
	parked = nil
	if l := n.line(); l != "" {
		t.Fatalf("all settled: %q", l)
	}
}

// An effect a check proved was not done, whose resend was refused, did not
// go and cannot go twice, so the note does not say it may; a refused owner
// retry leaves it waiting, and the note still names it (OP-2c).
func TestRefusedRetryStaysInStatus(t *testing.T) {
	waiting := []journal.ParkedIntent{
		{Intent: journal.Intent{ID: "m1/r1", Executor: "mail", Recipients: []string{"canary@example.invalid"}}, Attempt: 1, Seq: 7,
			Dispatched: time.Date(2026, 10, 13, 14, 2, 0, 0, time.UTC), NotDone: true},
	}
	n := unclearNoteOver(&waiting)
	const want = "An email first tried 14:02 Oct 13 did not go; not resent. Text RETRY to send it."
	for range 2 { // before and after a refused retry: RetryWaiting still lists it
		if l := n.line(); l != want {
			t.Fatalf("line %q", l)
		}
	}
	waiting = append(waiting, waiting[0])
	l := n.line()
	checkNote(t, l)
	if l != "2 actions did not go; not resent. Text RETRY to send them." {
		t.Fatalf("two not done: %q", l)
	}
}
