package main

import (
	"context"
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
	quote := "Liked “The Acme contract renews…”"
	// A locked reaction waits for the page (CH-14, D-311); a deletion
	// drops a held one, since it may quote a forgotten text.
	held := heldOn(t, r.ch, ownerNum)
	if n := held(quote); n != 1 {
		t.Fatalf("locked reaction: %d held", n)
	}
	if _, err := ev.kept.forget(); err != nil {
		t.Fatal(err)
	}
	if n := held(quote); n != 1 {
		t.Fatalf("a reaction after the deletion: %d held, want it alone (the earlier one dropped)", n)
	}
}

// heldOn returns a sender that texts s from the owner and returns how many
// messages then wait for the page.
func heldOn(t *testing.T, ch *ownerch.Channel, from string) func(string) int {
	return func(s string) int {
		ch.Handle(context.Background(), from, s)
		msgs, _, _ := ch.LocalHeld()
		return len(msgs)
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
	held := heldOn(t, r.ch, ownerNum)
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
	if n := held(quote); n != 1 {
		t.Fatalf("locked reaction: %d held", n)
	}
	ev.kept.settle(gen + 1)
	if n := held(quote); n != 2 {
		t.Fatalf("settle with no deletion in between: %d held, want the held reaction kept", n)
	}
	if err := r.ch.Converse("The Acme contract renews on the third of March at forty dollars a seat."); err != nil {
		t.Fatal(err)
	}
	r.sent()
	ev.kept.settle(gen)
	if n := held(quote); n != 1 {
		t.Fatalf("a reaction after settle: %d held, want it alone (the earlier ones dropped)", n)
	}
}
