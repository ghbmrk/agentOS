package owner

import (
	"strings"
	"testing"
)

// REQ: ID-1
//
// TR2: the owner's phone number is a signal, never enough alone. From the
// owner's own number, with no code, nothing is approved, the session is
// not unlocked, a held message does not run, and a STOP is not lifted.
func TestTheOwnersNumberAloneNeverApprovesOrUnlocks(t *testing.T) {
	r := newRig(t, nil)
	low, _ := r.ch.Request([]Item{lowItem("low")}, 0)
	r.inbox()
	high, _ := r.ch.Request([]Item{highItem("high")}, 0)
	r.inbox()
	for _, msg := range []string{"YES", "yes " + low, "YES " + high, "YES " + low + " 1", "YES " + high + " please", "approve " + high} {
		r.say(msg)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("approved with no code: %+v", ds)
	}

	if got := r.say("book a table for two"); !strings.HasPrefix(got, "Locked.") {
		t.Fatalf("chat with no code: %q", got)
	}
	r.say("RUN")
	r.say("STATUS")
	if r.ch.SessionUnlocked(r.clock()) || len(r.agent.got()) != 0 {
		t.Fatal("unlocked, or the held message ran, with no code")
	}

	r.say("STOP")
	r.say("RESUME")
	r.say("RESUME now")
	if !r.eng.Stopped() {
		t.Fatal("STOP lifted with no code")
	}
}
