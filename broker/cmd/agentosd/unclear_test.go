package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: OP-2, CH-12

// The digest names each parked effect in the owner's words and when it was
// first tried, says it was not retried and that RETRY may send it twice,
// and names the list again only once something new is parked or a refused
// retry relists it, across a restart.
func TestOP2DigestNamesUnclearEffectsOnce(t *testing.T) {
	ctx := context.Background()
	var parked []journal.ParkedIntent
	store := &change.MemStore{}
	src, err := newUnclearSource(func() []journal.ParkedIntent { return parked }, store)
	if err != nil {
		t.Fatal(err)
	}
	src.loc = time.UTC
	if snap, err := src.Peek(ctx); snap != nil || err != nil {
		t.Fatalf("nothing parked: %+v %v", snap, err)
	}
	parked = []journal.ParkedIntent{
		{Intent: journal.Intent{ID: "m1/r1", Executor: "mail", Recipients: []string{"canary@example.invalid"}}, Attempt: 1, Seq: 7,
			Dispatched: time.Date(2026, 10, 13, 14, 2, 0, 0, time.UTC)},
		{Intent: journal.Intent{ID: "p1", Executor: "payments-stub"}, Attempt: 2, Seq: 9},
	}
	snap, err := src.Peek(ctx)
	if err != nil || snap == nil || snap.Generation != 9<<relistBits || len(snap.Lines) != 2 {
		t.Fatalf("snapshot %+v %v", snap, err)
	}
	want := []string{"An email first tried 14:02 Oct 13 may not have gone", "An action may not have gone"}
	for i, l := range snap.Lines {
		if !strings.HasPrefix(l, want[i]) || strings.Contains(l, "restart") || !strings.Contains(l, "not retried") || !strings.Contains(l, "RETRY") ||
			!strings.Contains(l, "may go twice") || strings.Contains(l, "canary") || strings.Contains(l, "m1/r1") {
			t.Fatalf("line %q", l)
		}
		if _, gsm := modem.Segments(l); !gsm {
			t.Fatalf("not GSM-7: %q", l)
		}
	}
	if err := src.Ack(ctx, *snap); err != nil {
		t.Fatal(err)
	}
	reopen := func() *unclearSource {
		t.Helper()
		s, err := newUnclearSource(func() []journal.ParkedIntent { return parked }, store)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	again := reopen()
	if snap, err := again.Peek(ctx); snap != nil || err != nil {
		t.Fatalf("acked list offered again: %+v %v", snap, err)
	}

	// A refused retry lists the effects again, once, across a restart.
	again.Relist()
	again = reopen()
	relisted, err := again.Peek(ctx)
	if err != nil || relisted == nil || relisted.Generation != 9<<relistBits+1 || len(relisted.Lines) != 2 {
		t.Fatalf("relist: %+v %v", relisted, err)
	}
	if err := again.Ack(ctx, *relisted); err != nil {
		t.Fatal(err)
	}
	if snap, err := reopen().Peek(ctx); snap != nil || err != nil {
		t.Fatalf("relisted list offered again: %+v %v", snap, err)
	}

	parked = append(parked, journal.ParkedIntent{Intent: journal.Intent{ID: "m1/r2", Executor: "mail"}, Attempt: 1, Seq: 12})
	if snap, err := again.Peek(ctx); err != nil || snap == nil || snap.Generation != 12<<relistBits || len(snap.Lines) != 3 {
		t.Fatalf("new park: %+v %v", snap, err)
	}
}

// An effect a check proved was not done, whose resend was refused, is
// named too (R4, P1b): it did not go, RETRY sends it, and it cannot go
// twice, so the line does not say it may.
func TestOP2DigestNamesRefusedResends(t *testing.T) {
	ctx := context.Background()
	waiting := []journal.ParkedIntent{
		{Intent: journal.Intent{ID: "m1/r1", Executor: "mail", Recipients: []string{"canary@example.invalid"}}, Attempt: 1, Seq: 7,
			Dispatched: time.Date(2026, 10, 13, 14, 2, 0, 0, time.UTC), NotDone: true},
	}
	src, err := newUnclearSource(func() []journal.ParkedIntent { return waiting }, &change.MemStore{})
	if err != nil {
		t.Fatal(err)
	}
	src.loc = time.UTC
	snap, err := src.Peek(ctx)
	if err != nil || snap == nil || snap.Generation != 7<<relistBits || len(snap.Lines) != 1 {
		t.Fatalf("snapshot %+v %v", snap, err)
	}
	if l := snap.Lines[0]; l != "An email first tried 14:02 Oct 13 did not go; not resent. Text RETRY to send it." {
		t.Fatalf("line %q", l)
	}
}
