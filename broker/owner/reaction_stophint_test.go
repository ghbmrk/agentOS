package owner

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
)

// REQ: CH-11, CH-15

// #2264: a STOP-led text quoting a coded box text is read as a reaction, so
// it never reaches the control handler. It still gets the STOP near-miss
// hint, on the same hourly quiet window, and the agent never sees the code.
func TestStopLedReactionKeepsTheStopHint(t *testing.T) {
	const hint = "To pause everything, reply STOP."
	r := newRig(t, nil)
	r.unlock()
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	got := r.say("STOP “Your sign-in code is 482913.”")
	if !strings.Contains(got, hint) || !strings.Contains(got, readAsReaction) {
		t.Fatalf("STOP-led reaction replied %q, want the STOP hint and %q", got, readAsReaction)
	}
	if strings.Contains(got, "482913") {
		t.Fatalf("reply echoed the code: %q", got)
	}
	for _, m := range r.agent.got() {
		if strings.Contains(m, "482913") {
			t.Fatalf("agent got the code: %q", m)
		}
	}
	// The hint shares control's quiet window: none again within the hour,
	// from a reaction or from plain chat.
	if got := r.say("please stop “Your sign-in code is 482913.”"); strings.Contains(got, hint) {
		t.Fatalf("second STOP-led reaction within the hour replied %q, want no hint", got)
	}
	if got := r.say("stop the newsletter"); strings.Contains(got, hint) {
		t.Fatalf("near-miss chat within the hour replied %q, want no hint", got)
	}
	r.advance(control.HintQuiet + time.Minute)
	if got := r.say("Cancel “Your sign-in code is 482913.”"); strings.Contains(got, hint) {
		t.Fatalf("reaction without a STOP lead-in replied %q, want no hint", got)
	}
	// Only the lead-in counts: a quote ending in STOP is not a near-miss.
	r.ch.recent.add(sentText{text: "Code 482913. To pause, reply STOP", at: r.now})
	if got := r.say("Cancel “Code 482913. To pause, reply STOP”"); strings.Contains(got, hint) {
		t.Fatalf("quote ending in STOP replied %q, want no hint", got)
	}
}

// While locked the reaction is held, and the hint still comes, as it does
// for locked near-miss chat.
func TestLockedStopLedReactionKeepsTheStopHint(t *testing.T) {
	r := newRig(t, nil)
	r.ch.recent.add(sentText{text: "Your sign-in code is 482913.", at: r.now})
	got := r.say("STOP “Your sign-in code is 482913.”")
	if !strings.Contains(got, "held for") || !strings.Contains(got, "To pause everything, reply STOP.") || strings.Contains(got, "482913") {
		t.Fatalf("locked STOP-led reaction replied %q, want held plus the STOP hint", got)
	}
}
