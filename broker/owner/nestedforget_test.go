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

// One table for every shape the #5185 review rounds probed (Potency, L3
// and Security, rounds 1-4): the forget decides with the delivery path's
// own matcher (matchForgettable), so a held text that quotes a forgotten
// text, at any layer, cut or whole, short or long, is dropped and its
// words never reach the agent, even run from the page past the 24 h
// window; and a held message that only contains a short agent text, or
// quotes nothing forgotten, stays.
func TestAForgetDropsExactlyTheHeldTextsQuotingAForgottenText(t *testing.T) {
	cut := "The Acme contract renews on the third of…"
	for _, tc := range []struct {
		reply, held, word string
		drop              bool
	}{
		// Dropped: each quotes the forgotten reply at some layer.
		{forgottenReply, "Liked “" + forgottenReply + "”", "Acme", true},
		{forgottenReply, "Liked “Loved “" + forgottenReply + "””", "Acme", true},
		{forgottenReply, "Pinned “Liked “" + cut, "Acme", true},
		{forgottenReply, "Liked “Loved “" + cut + "”", "Acme", true},
		{"Ok, booked.", "Liked “Ok, booked.”", "booked", true},
		{"Ok, booked.", "Liked “Loved “Ok, booked.””", "booked", true},
		{"Call Dr Lee", "Liked “Call Dr Lee”", "Dr Lee", true},
		{"Call Dr Lee", "Liked “Loved “Call Dr Lee””", "Dr Lee", true},
		{"See you at 6", "Liked “Loved “See you at 6””", "See you", true},
		{`Call "Mum"`, `Liked “Call "Mum"”`, "Mum", true},
		{`Call "Mum"`, `Liked “Call “Mum””`, "Mum", true},
		{`Call "Mum"`, `Liked “Loved “Call "Mum"””`, "Mum", true},
		{`Say "hi"`, `Liked “Say "hi"”`, "hi", true},
		{`Say "hi"`, `Liked “Loved “Say "hi"””`, "hi", true},
		{`Call "Dr Lee" now`, `Liked “Call "Dr Lee" now”`, "Dr Lee", true},
		// Kept: a short agent text inside a longer quote marks nothing
		// (#5185 L3 round 4).
		{"OK", "Text Sam “booking for six people tonight”", "", false},
		{"No", "Tell Sam “not tonight, maybe next week”", "", false},
		{"Yes", "Liked “yesterday was a lovely dinner”", "", false},
		{forgottenReply, `Remind me to call "Mum" tomorrow at 9`, "", false},
		{forgottenReply, "Book a table at “Nopi” for two", "", false},
	} {
		r := newRig(t, nil)
		if err := r.ch.Converse(tc.reply); err != nil {
			t.Fatal(err)
		}
		r.inbox()
		r.say(tc.held)
		r.ch.ForgetRecent()
		msgs, dropped, _ := r.ch.LocalHeld()
		if tc.drop && (len(msgs) != 0 || dropped != 1) || !tc.drop && (len(msgs) != 1 || dropped != 0) {
			t.Errorf("%q after %q: held %+v, dropped %d, want dropped %v", tc.held, tc.reply, msgs, dropped, tc.drop)
			continue
		}
		if !tc.drop {
			continue
		}
		r.advance(25 * time.Hour)
		r.unlock()
		r.runHeld()
		for _, s := range r.agent.got() {
			if strings.Contains(s, tc.word) {
				t.Errorf("%q: forgotten words reached the agent: %q", tc.held, s)
			}
		}
	}
}
