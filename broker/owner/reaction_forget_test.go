package owner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// REQ: CAP-3, CH-11

// forgottenReply is an agent reply a deletion covers; the reaction quotes
// part of it (12 or more characters), as phones do.
const (
	forgottenReply = "The Acme contract renews on the third of March at forty dollars a seat."
	forgottenWords = "Acme contract renews"
)

func noForgottenText(t *testing.T, got []string) {
	t.Helper()
	for _, g := range got {
		if strings.Contains(g, forgottenWords) || strings.Contains(g, "forty dollars") {
			t.Fatalf("agent got the forgotten reply: %q", g)
		}
	}
}

// After a deletion, a partial quote of a forgotten reply matches nothing,
// so the event does not carry the reply back to the agent (#2360).
func TestAReactionAfterAForgetDoesNotQuoteTheForgottenReply(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.say("Liked “Agent: The Acme contract renews…”")
	if g := r.agent.got(); len(g) != 1 || !strings.Contains(g[0], forgottenWords) {
		t.Fatalf("before the deletion the reaction matched %q, want the reply", g)
	}
	r.ch.ForgetRecent()
	before := len(r.agent.got())
	r.say("Liked “Agent: The Acme contract renews…”")
	r.say("Emphasized “Acme contract renews on the third”")
	r.say("Loved “Agent: " + forgottenReply + "”")
	got := r.agent.got()[before:]
	if len(got) != 3 {
		t.Fatalf("agent got %q, want three events", got)
	}
	for _, g := range got {
		if !strings.Contains(g, "none of the recent texts") {
			t.Fatalf("reaction after a deletion: %q", g)
		}
	}
	noForgottenText(t, got)
	// Texts after the deletion still match.
	r.ch.Converse("Lunch is booked for one in the afternoon.")
	r.inbox()
	r.say("Liked “Agent: Lunch is booked for one…”")
	if g := r.agent.got(); !strings.Contains(g[len(g)-1], "Lunch is booked") {
		t.Fatalf("a text after the deletion did not match: %q", g[len(g)-1])
	}
}

// A reaction held while locked, worded before the deletion, is dropped by
// it: RUN after the unlock delivers nothing (#2360).
func TestAHeldReactionIsDroppedByAForget(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	if got := r.say("Liked “Agent: The Acme contract renews…”"); !strings.Contains(got, "reaction is held") {
		t.Fatalf("locked reaction: %q", got)
	}
	r.ch.ForgetRecent()
	r.say(r.totp())
	if got := r.say("RUN"); !strings.Contains(got, "Nothing is held.") {
		t.Fatalf("RUN after a deletion: %q", got)
	}
	if g := r.agent.got(); len(g) != 0 {
		t.Fatalf("agent got %q after a deletion", g)
	}
}

// An event worded before a deletion and not yet delivered when it ran is
// never delivered (#2360).
func TestAReactionWordedBeforeAForgetIsNotDelivered(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	rt, ok := r.ch.route(ownerNum, "Liked “Agent: The Acme contract renews…”")
	if !ok || !strings.Contains(rt.react, forgottenWords) {
		t.Fatalf("route: %v %q", ok, rt.react)
	}
	r.ch.ForgetRecent()
	r.ch.finish(context.Background(), ownerNum, rt)
	if g := r.agent.got(); len(g) != 0 {
		t.Fatalf("agent got %q after a deletion", g)
	}
}

// A deletion that runs while an event is being delivered returns only once
// that delivery is over, so none quoting a forgotten text reaches the agent
// after the deletion completes (#2360).
func TestAForgetWaitsForAReactionBeingDelivered(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	started := make(chan struct{})
	release := make(chan struct{})
	r.ch.ctrl.Agent = gatedAgent{started: started, release: release}
	go r.ch.Handle(context.Background(), ownerNum, "Liked “Agent: The Acme contract renews…”")
	<-started
	done := make(chan struct{})
	go func() { r.ch.ForgetRecent(); close(done) }()
	select {
	case <-done:
		t.Fatal("the deletion completed while a reaction quoting the forgotten reply was being delivered")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
}

type gatedAgent struct{ started, release chan struct{} }

func (g gatedAgent) Deliver(ctx context.Context, _ string, _ bool) error {
	close(g.started)
	select {
	case <-g.release:
	case <-ctx.Done():
	}
	return nil
}
