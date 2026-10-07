package owner

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/boxname"
)

// REQ: CH-21
func TestCH21NotifyWithholdsAskForCode(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.Notify("Please send me the code from your authenticator."); err != nil {
		t.Fatal(err)
	}
	if got := r.inbox(); got != boxname.Withheld {
		t.Fatalf("got %q", got)
	}
}

// REQ: CH-21
func TestCH21NotifyWithholdsReplyGrammar(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.Notify("YES 1 482193"); err != nil {
		t.Fatal(err)
	}
	if got := r.inbox(); got != boxname.Withheld {
		t.Fatalf("got %q", got)
	}
}

// REQ: CH-21
func TestCH21NotifyPassesOrdinary(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.Notify("Booked a table for 7."); err != nil {
		t.Fatal(err)
	}
	got := r.inbox()
	if !strings.HasPrefix(got, AgentPrefix) || strings.Contains(got, boxname.Withheld) {
		t.Fatalf("got %q", got)
	}
}
