package owner

// REQ: CH-11, CH-14
// A held reaction whose quote nests quote marks (read only through the
// recent texts) is still dropped by a forget: the hold marks it (#5185 L3).

import (
	"strings"
	"testing"
	"time"
)

func TestANestedHeldReactionIsDroppedByAForget(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	got := r.say("Liked “Loved “" + forgottenReply + "””")
	t.Logf("locked reply: %q", got)
	r.ch.ForgetRecent()
	msgs, _, _ := r.ch.LocalHeld()
	t.Logf("held after forget: %+v", msgs)
	r.unlock()
	n := r.runHeld()
	g := r.agent.got()
	t.Logf("ran %d, agent got %q", n, g)
	for _, s := range g {
		if strings.Contains(s, forgottenWords) {
			t.Fatalf("forgotten text reached the agent after a forget: %q", s)
		}
	}
	if len(msgs) != 0 {
		t.Fatalf("forgotten text still held on disk after forget")
	}
}

// Potency fix-list on #5185: a forget keeps the owner's own quoted
// messages that quote nothing it deletes, and counts what it removes.
func TestAForgetKeepsHeldMessagesThatQuoteNothingForgotten(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.say(`Remind me to call "Mum" tomorrow at 9`)
	r.say("Book a table at “Nopi” for two")
	r.say("check my mail")
	r.say("Liked “" + forgottenReply + "”")
	r.ch.ForgetRecent()
	msgs, dropped, _ := r.ch.LocalHeld()
	if len(msgs) != 3 || dropped != 1 {
		t.Fatalf("held %+v, dropped %d", msgs, dropped)
	}
	if note := r.ch.heldNote(); !strings.Contains(note, "1 removed with a deletion") {
		t.Fatalf("STATUS note: %q", note)
	}
}

// Delta fix-lists on #5185 (Potency, L3, Security): a forget sees every
// layer of a held nest, a cut one and one quoting a short text too, and
// what it keeps never reaches the agent with the forgotten words later.
func TestAForgetDropsCutAndShortNestedHeldReactions(t *testing.T) {
	cut := "The Acme contract renews on the third of…"
	for _, tc := range []struct{ reply, held string }{
		{forgottenReply, "Pinned “Liked “" + cut},
		{forgottenReply, "Liked “Loved “" + cut + "”"},
		{"Ok, booked.", "Liked “Loved “Ok, booked.””"},
		{"Call Dr Lee", "Liked “Call Dr Lee”"},
	} {
		r := newRig(t, nil)
		if err := r.ch.Converse(tc.reply); err != nil {
			t.Fatal(err)
		}
		r.inbox()
		r.say(tc.held)
		r.ch.ForgetRecent()
		if msgs, dropped, _ := r.ch.LocalHeld(); len(msgs) != 0 || dropped != 1 {
			t.Fatalf("%q: held %+v, dropped %d", tc.held, msgs, dropped)
		}
		r.advance(25 * time.Hour)
		r.unlock()
		r.runHeld()
		for _, s := range r.agent.got() {
			if strings.Contains(s, "Acme") || strings.Contains(s, "booked") || strings.Contains(s, "Dr Lee") {
				t.Fatalf("%q: forgotten words reached the agent: %q", tc.held, s)
			}
		}
	}
}
