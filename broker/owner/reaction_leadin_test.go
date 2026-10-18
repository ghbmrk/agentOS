package owner

import (
	"strings"
	"testing"
)

// REQ: CH-11

// #2277: an unlisted form read as a reaction drops the owner's lead-in, so
// the owner is told, in a fixed line that never echoes the quoted text, that
// the message did not reach the agent. A listed form gets no such line.
func TestUnlistedReactionTellsTheOwner(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	got := r.say("Cancel “" + req + "”")
	if !strings.Contains(got, readAsReaction) {
		t.Fatalf("unlisted form on a request replied %q, want %q", got, readAsReaction)
	}
	if strings.Contains(got, code) {
		t.Fatalf("reply echoed the code: %q", got)
	}
	if got := r.say("Liked “" + req + "”"); strings.Contains(got, readAsReaction) {
		t.Fatalf("listed form replied %q, want no lead-in note", got)
	}

	// A coded box text that expects no reply, so no pointer is sent: the
	// owner still hears that the agent was not told.
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	got = r.say("Cancel “Your sign-in code is 482913.”")
	if got != readAsReaction {
		t.Fatalf("unlisted form on a coded text replied %q, want only %q", got, readAsReaction)
	}
	for _, m := range r.agent.got() {
		if strings.Contains(m, "482913") || strings.Contains(m, code) {
			t.Fatalf("agent got a code: %q", m)
		}
	}
}

// While locked the reaction is held as any is; the owner is told it was read
// as a reaction too.
func TestLockedUnlistedReactionTellsTheOwner(t *testing.T) {
	r := newRig(t, nil)
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	got := r.say("Cancel “Your sign-in code is 482913.”")
	if !strings.Contains(got, "held for") || !strings.Contains(got, readAsReaction) || strings.Contains(got, "482913") {
		t.Fatalf("locked unlisted form replied %q, want held plus %q", got, readAsReaction)
	}
}
