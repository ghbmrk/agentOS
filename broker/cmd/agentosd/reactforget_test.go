package main

import (
	"context"
	"strings"
	"testing"
	"time"

	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CAP-3
// A deletion through the forget fan-out also clears the owner channel's
// recent replies (#2360): a reaction held before it is dropped, so a
// second one is held in its place rather than colliding with it. What a
// reaction carries after a deletion is pinned in broker/owner.
func TestADeletionForgetsTheOwnerChannelsRecentReplies(t *testing.T) {
	r := pacedOwner(t, ownerch.Pacing{}, time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	ev := newEvRig(t).ev
	ev.wireOwner(func() *ownerch.Channel { return r.ch })
	if err := r.ch.Converse("The Acme contract renews on the third of March at forty dollars a seat."); err != nil {
		t.Fatal(err)
	}
	r.sent()
	say := func(s string) string { return strings.Join(r.ch.Handle(context.Background(), ownerNum, s), " | ") }
	quote := "Liked “The Acme contract renews…”"
	if got := say(quote); !strings.Contains(got, "reaction is held") {
		t.Fatalf("locked reaction: %q", got)
	}
	if _, err := ev.kept.forget(); err != nil {
		t.Fatal(err)
	}
	if got := say(quote); strings.Contains(got, "both were dropped") || !strings.Contains(got, "reaction is held") {
		t.Fatalf("a reaction after the deletion: %q, want it held alone (the earlier one dropped)", got)
	}
}

// A reply in flight across a deletion lands in the owner channel's recent
// texts after the deletion cleared them; settle clears them again, so a
// reaction held on it is dropped too (#2360). A reply routed with no
// deletion in between leaves them alone.
func TestAReplyInFlightAcrossADeletionIsForgottenOnSettle(t *testing.T) {
	r := pacedOwner(t, ownerch.Pacing{}, time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	ev := newEvRig(t).ev
	ev.wireOwner(func() *ownerch.Channel { return r.ch })
	say := func(s string) string { return strings.Join(r.ch.Handle(context.Background(), ownerNum, s), " | ") }
	quote := "Liked “The Acme contract renews…”"

	ev.kept.fmu.Lock()
	gen := ev.kept.gen
	ev.kept.fmu.Unlock()
	if _, err := ev.kept.forget(); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.Converse("The Acme contract renews on the third of March at forty dollars a seat."); err != nil {
		t.Fatal(err)
	}
	r.sent()
	if got := say(quote); !strings.Contains(got, "reaction is held") {
		t.Fatalf("locked reaction: %q", got)
	}
	ev.kept.settle(gen + 1)
	if got := say(quote); !strings.Contains(got, "both were dropped") {
		t.Fatalf("settle with no deletion in between: %q, want the held reaction kept", got)
	}
	if err := r.ch.Converse("The Acme contract renews on the third of March at forty dollars a seat."); err != nil {
		t.Fatal(err)
	}
	r.sent()
	if got := say(quote); !strings.Contains(got, "reaction is held") {
		t.Fatalf("locked reaction: %q", got)
	}
	ev.kept.settle(gen)
	if got := say(quote); strings.Contains(got, "both were dropped") || !strings.Contains(got, "reaction is held") {
		t.Fatalf("a reaction after settle: %q, want it held alone (the earlier one dropped)", got)
	}
}
