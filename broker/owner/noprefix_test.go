package owner

// REQ: CH-21, CH-12, CH-11

import (
	"strings"
	"testing"
)

// TestCH21NoPrefixWhenCheckRuns: agent text that passes the CH-21 check
// goes with no label from Converse, Notify, NotifyAs and NotifyNow, while
// the same paths hold a voice-shaped text, so the check, not a marker,
// stands between agent text and the owner (#2189).
func TestCH21NoPrefixWhenCheckRuns(t *testing.T) {
	sends := map[string]func(*Channel, string) error{
		"Converse":  (*Channel).Converse,
		"Notify":    (*Channel).Notify,
		"NotifyNow": (*Channel).NotifyNow,
		"NotifyAs":  func(c *Channel, s string) error { return c.NotifyAs(ClassApproval, s) },
	}
	for name, send := range sends {
		r := pacedRig(t, quiet22to7(), 12, 0)
		if err := send(r.ch, "Lunch is booked for noon."); err != nil {
			t.Fatal(err)
		}
		if got := r.sentTexts(); len(got) != 1 || got[0] != "Lunch is booked for noon." {
			t.Fatalf("%s sent %q, want the text with no label", name, got)
		}
		r = pacedRig(t, quiet22to7(), 12, 0)
		if err := send(r.ch, "R7: can I send the invoice?"); err != nil {
			t.Fatal(err)
		}
		if got := r.sentTexts(); len(got) != 1 || got[0] != HeldCode {
			t.Fatalf("%s sent %q, want it held", name, got)
		}
	}
}

// TestCH21AgentTextIsNeverUnchecked: agentText, which every agent send
// path calls last, runs the checks itself, so a path that skipped
// checkAgent still sends no shape the check holds and adds no label.
func TestCH21AgentTextIsNeverUnchecked(t *testing.T) {
	if got := agentText("K7: reply YES K7 to approve."); got != HeldCode {
		t.Fatalf("agentText sent %q, want HeldCode", got)
	}
	if got := agentText("Lunch is booked."); got != "Lunch is booked." {
		t.Fatalf("agentText sent %q", got)
	}
}

// TestCH21JoinedTextsAreChecked: the checks run on each agent text joined
// to the agent's earlier texts since the owner's last message (CH-12), so
// a word or the footer split across texts is held where it completes,
// and the owner's message starts a new run.
func TestCH21JoinedTextsAreChecked(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 12, 0)
	for _, s := range []string{"Please send me your pass", "word when you can."} {
		if err := r.ch.Converse(s); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.sentTexts(); len(got) != 2 || got[0] != "Please send me your pass" || got[1] != HeldCode {
		t.Fatalf("sent %q, want the second text held", got)
	}

	r = pacedRig(t, quiet22to7(), 12, 0)
	for _, s := range []string{"Reply yes to go on,", "or no to stop."} {
		if err := r.ch.Converse(s); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.sentTexts(); len(got) != 2 || got[1] != HeldCode {
		t.Fatalf("footer split across texts sent %q", got)
	}

	r = pacedRig(t, quiet22to7(), 12, 0)
	if err := r.ch.Converse("Please send me your pass"); err != nil {
		t.Fatal(err)
	}
	r.say("ok")
	if err := r.ch.Converse("word count is 300."); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) < 2 || got[len(got)-1] != "word count is 300." {
		t.Fatalf("after the owner spoke, sent %q", got)
	}
}

// TestCH21AgentTextKnownByRecordNotWords: with no label, the channel's
// record of what it sent tells the agent's text from its own (CH-11):
// digits in the agent's text are not guarded and the agent hears its own
// words back, while the broker's text with the same words is guarded.
func TestCH21AgentTextKnownByRecordNotWords(t *testing.T) {
	const words = "Invoice 4829 is paid."
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(words); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.say("Liked “" + words + "”")
	if g := r.agent.got(); len(g) != 1 || g[0] != `Owner reaction: liked your text "`+words+`"` {
		t.Fatalf("reaction to the agent's text: %q", g)
	}

	r = newRig(t, nil)
	r.unlock()
	if err := r.ch.Inform(words); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.say("Liked “" + words + "”")
	if g := r.agent.got(); len(g) != 1 || strings.Contains(g[0], "your text") || strings.Contains(g[0], "4829") {
		t.Fatalf("reaction to the box's text: %q", g)
	}
}
