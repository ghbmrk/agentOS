package owner

import (
	"strings"
	"testing"
)

// REQ: CH-11, CH-15, CAP-3

const stopHintText = "To pause everything, reply STOP."

// hintFirst fails unless got carries the STOP hint ahead of readAsReaction.
func hintFirst(t *testing.T, what, got string) {
	t.Helper()
	h, rd := strings.Index(got, stopHintText), strings.Index(got, readAsReaction)
	if h < 0 || rd < 0 || h > rd {
		t.Fatalf("%s replied %q, want the STOP hint ahead of %q", what, got, readAsReaction)
	}
}

// A near-miss lead-in gets the hint, ahead of the read-as-reaction line.
func TestNearMissLedReactionGetsTheStopHintFirst(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	got := r.say("STOP NOW “Your sign-in code is 482913.”")
	hintFirst(t, "near-miss-led reaction", got)
	if strings.Contains(got, "482913") {
		t.Fatalf("reply echoed the code: %q", got)
	}
}

// A lead-in that is not STOP leaves the hour's window unspent.
func TestOtherLeadInLeavesTheStopHintWindowUnspent(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	if got := r.say("Cancel “Your sign-in code is 482913.”"); strings.Contains(got, stopHintText) {
		t.Fatalf("Cancel-led reaction replied %q, want no hint", got)
	}
	if got := r.say("stop the newsletter"); !strings.Contains(got, stopHintText) {
		t.Fatalf("near-miss chat after a Cancel-led reaction replied %q, want the hint", got)
	}
}

// A cut form (no closing quote) with a STOP lead-in gets the hint.
func TestStopLedCutFormGetsTheStopHint(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	got := r.say("STOP “Your sign-in code is 4829")
	hintFirst(t, "STOP-led cut form", got)
	if strings.Contains(got, "4829") {
		t.Fatalf("reply echoed the code: %q", got)
	}
	for _, m := range r.agent.got() {
		if strings.Contains(m, "4829") {
			t.Fatalf("agent got the code: %q", m)
		}
	}
}

// After a deletion, a STOP-led unlisted form quoting a forgotten agent reply
// is a reaction and gets the hint; the agent never sees the reply.
func TestStopLedFormOnAForgottenReplyGetsTheStopHint(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch.ForgetRecent()
	before := len(r.agent.got())
	got := r.say("STOP “Agent: " + forgottenReply + "”")
	hintFirst(t, "STOP-led form on a forgotten reply", got)
	if strings.Contains(got, forgottenWords) {
		t.Fatalf("reply echoed the forgotten reply: %q", got)
	}
	noForgottenText(t, r.agent.got()[before:])
}

// After a deletion, a listed form read as a reaction has no lead-in: no hint,
// and the window stays unspent.
func TestListedFormAfterADeletionLeavesTheStopHintWindowUnspent(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch.ForgetRecent()
	got := r.say("Liked “Loved “Agent: " + forgottenReply + "””")
	if got != readAsReaction {
		t.Fatalf("listed form after a deletion replied %q, want %q", got, readAsReaction)
	}
	if got := r.say("stop the newsletter"); !strings.Contains(got, stopHintText) {
		t.Fatalf("near-miss chat after the listed form replied %q, want the hint", got)
	}
}
