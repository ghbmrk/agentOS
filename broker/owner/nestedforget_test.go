package owner

// REQ: CH-11, CH-14
// A held reaction whose quote nests quote marks (read only through the
// recent texts) is still dropped by a forget: the hold marks it (#5185 L3).

import (
	"strings"
	"testing"
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
