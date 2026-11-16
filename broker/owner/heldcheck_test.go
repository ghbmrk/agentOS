package owner

// REQ: CH-14, CH-19, CH-21

import (
	"errors"
	"testing"
)

// heldFooter is owner-number text carrying CH-21's reply-options footer.
const heldFooter = "Bank transfer ready. Reply yes to send it, or no to stop."

// heldLookalike is owner-number text shaped like a texted code (CH-19)
// that carries no word of CH-21's vocabulary, so only the CH-19 check
// can catch it.
const heldLookalike = "Your login 482913 for the bank"

// heldByID returns the held message with ID id, failing t
// when it is not held.
func heldByID(t *testing.T, msgs []WaitingMsg, id string) WaitingMsg {
	t.Helper()
	for _, m := range msgs {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("message %s not held: %+v", id, msgs)
	return WaitingMsg{}
}

// A held message that fails CH-21 comes back pointer-only, its text left
// out; an ordinary one beside it keeps its text (CH-14).
func TestLocalHeldShowsACH21FooterAsAPointer(t *testing.T) {
	if !AgentVoice(heldFooter) {
		t.Fatalf("fixture %q is not CH-21-shaped", heldFooter)
	}
	r := newRig(t, nil)
	r.say("book a table")
	r.say(heldFooter)
	msgs, _, _ := r.ch.LocalHeld()
	if len(msgs) != 2 {
		t.Fatalf("held %+v", msgs)
	}
	if m := msgs[0]; m.Pointer || m.Text != "book a table" {
		t.Fatalf("ordinary message: %+v", m)
	}
	if m := msgs[1]; !m.Pointer || m.Text != "" || m.ID == "" {
		t.Fatalf("footer message: %+v", m)
	}
	// The stored text is untouched: only what the page gets is a pointer.
	if got := r.ch.codes.st.Waiting[1].Text; got != heldFooter {
		t.Fatalf("stored %q", got)
	}
}

// A held texted-code lookalike that only CH-19 catches is pointer-only
// too.
func TestLocalHeldShowsACH19FailureAsAPointer(t *testing.T) {
	if !AgentSecret(heldLookalike) || AgentVoice(heldLookalike) {
		t.Fatalf("fixture %q: secret %v, voice %v; want CH-19 only", heldLookalike, AgentSecret(heldLookalike), AgentVoice(heldLookalike))
	}
	r := newRig(t, nil)
	r.say(heldLookalike)
	msgs, _, _ := r.ch.LocalHeld()
	if len(msgs) != 1 || !msgs[0].Pointer || msgs[0].Text != "" {
		t.Fatalf("held %+v", msgs)
	}
}

// A run naming a pointer-only message is refused and runs nothing, not
// even the ordinary message marked beside it; the same list without it
// runs, and discards the pointer as one of those shown.
func TestLocalRunHeldRefusesAPointerOnlyID(t *testing.T) {
	for name, text := range map[string]string{"CH-21": heldFooter, "CH-19": heldLookalike} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			r.say("book a table")
			r.say(text)
			msgs, _, _ := r.ch.LocalHeld()
			ok, bad := heldByID(t, msgs, "1"), heldByID(t, msgs, "2")
			shown := []string{ok.ID, bad.ID}
			r.unlock()
			n, err := r.ch.LocalRunHeld(shown, []string{ok.ID, bad.ID})
			r.ch.WaitSends()
			if !errors.Is(err, ErrHeldChanged) || n != 0 {
				t.Fatalf("run naming a pointer: %d, %v", n, err)
			}
			if got := r.agent.got(); len(got) != 0 {
				t.Fatalf("a refused run ran %q", got)
			}
			if left, _, _ := r.ch.LocalHeld(); len(left) != 2 {
				t.Fatalf("a refused run changed the hold: %+v", left)
			}
			n, err = r.ch.LocalRunHeld(shown, []string{ok.ID})
			r.ch.WaitSends()
			if err != nil || n != 1 {
				t.Fatalf("run without the pointer: %d, %v", n, err)
			}
			if got := r.agent.got(); len(got) != 1 || got[0] != "book a table" {
				t.Fatalf("agent got %q", got)
			}
			if left, _, _ := r.ch.LocalHeld(); len(left) != 0 {
				t.Fatalf("pointer not discarded: %+v", left)
			}
		})
	}
}
