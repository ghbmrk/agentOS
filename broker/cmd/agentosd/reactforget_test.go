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
	ev := newEvRig(t, "").ev
	ev.wireOwner(func() *ownerch.Channel { return r.ch })
	if err := r.ch.Converse("The Acme contract renews on the third of March at forty dollars a seat."); err != nil {
		t.Fatal(err)
	}
	r.sent()
	say := func(s string) string { return strings.Join(r.ch.Handle(context.Background(), ownerNum, s), " | ") }
	quote := "Liked “Agent: The Acme contract renews…”"
	if got := say(quote); !strings.Contains(got, "reaction is held") {
		t.Fatalf("locked reaction: %q", got)
	}
	if _, err := (forgetFan{kept: ev.kept}).ForgetTasks("agent/1"); err != nil {
		t.Fatal(err)
	}
	if got := say(quote); strings.Contains(got, "both were dropped") || !strings.Contains(got, "reaction is held") {
		t.Fatalf("a reaction after the deletion: %q, want it held alone (the earlier one dropped)", got)
	}
}
