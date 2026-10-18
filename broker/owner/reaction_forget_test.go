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

// A deletion keeps a live request in the window (security finding on
// #2369): a reaction quoting it whole, code and all, in an unlisted form or
// a listed form whose quote holds quote marks, is still read as a reaction,
// so neither the request nor its code reaches the agent as chat.
func TestAForgetKeepsALiveRequestGuarded(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	r.ch.ForgetRecent()
	before := len(r.agent.got())
	if got := r.say("Pinned “" + req + "”"); !strings.Contains(got, readAsReaction) {
		t.Fatalf("unlisted form on a live request after a deletion replied %q, want it read as a reaction", got)
	}
	r.say("Liked “" + req + " \"x\"”")
	got := r.agent.got()[before:]
	if len(got) != 2 {
		t.Fatalf("agent got %q, want two reaction events", got)
	}
	for _, g := range got {
		if strings.Contains(g, code) || strings.Contains(g, "Reply YES") || !strings.HasPrefix(g, "Owner reaction:") {
			t.Fatalf("agent got %q, want an event that shows neither the request nor its code", g)
		}
	}
}

// After a deletion, a listed form quoting a forgotten reply that holds
// quote marks is read as a reaction that matched none for the window's 24
// hours, so the reply does not reach the agent word for word as chat
// (security finding on #2369). Past that, such a text is chat again.
func TestAQuotedForgottenReplyIsNotChatAfterAForget(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	reply := `The client wrote "pay by Friday" about the Acme contract renews notice.`
	if err := r.ch.Converse(reply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch.ForgetRecent()
	before := len(r.agent.got())
	r.say("Liked “Agent: " + reply + "”")
	got := r.agent.got()[before:]
	if len(got) != 1 || !strings.Contains(got[0], "none of the recent texts") {
		t.Fatalf("agent got %q, want one reaction that matched none", got)
	}
	noForgottenText(t, got)
	r.advance(recentMaxAge + time.Minute)
	before = len(r.agent.got())
	r.say(`Liked "a" and "b" both`)
	if got := r.agent.got()[before:]; len(got) != 1 || strings.HasPrefix(got[0], "Owner reaction:") {
		t.Fatalf("a day after the deletion: %q, want chat", got)
	}
}

// #2202 after a deletion: a forget keeps the request and coded box texts,
// so an unlisted form quoting one is still read as a reaction, the owner
// hears so, and the agent gets no code.
func TestUnlistedReactionStaysGuardedAfterAForget(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	r.ch.ForgetRecent()
	if got := r.say("Cancel “" + req + "”"); !strings.Contains(got, readAsReaction) || strings.Contains(got, code) {
		t.Fatalf("unlisted form on a request after a forget replied %q, want %q", got, readAsReaction)
	}
	if got := r.say("Cancel “Your sign-in code is 482913.”"); got != readAsReaction {
		t.Fatalf("unlisted form on a coded text after a forget replied %q, want only %q", got, readAsReaction)
	}
	for _, m := range r.agent.got() {
		if strings.Contains(m, "482913") || strings.Contains(m, code) {
			t.Fatalf("agent got a code: %q", m)
		}
	}
}
