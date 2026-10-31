package wire

// REQ: NET-2, NET-4

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A name the channel carries refuses the hostile-text corpus as
// broker/enforcer/policy's tokens do (#3901), so the channel and the policy
// never disagree on a device's name.
func TestNameCheckRefusesHostileText(t *testing.T) {
	hostiletext.Run(t, Name)
}

// The channel refuses the name "unknown", in any case, as the policy
// reserves it (#4185), so a frame naming it ends the connection; a name
// that only starts with it is carried. Revert mutant: Name without the
// check.
func TestUnknownIsReserved(t *testing.T) {
	for s, want := range map[string]bool{
		"unknown": false, "Unknown": false, "UNKNOWN": false,
		"unknown-plug": true, "unknowns": true, "unknow": true,
		strings.Repeat("a", MaxName): true, strings.Repeat("a", MaxName+1): false,
	} {
		if Name(s) != want {
			t.Errorf("Name(%.20q, %d bytes) = %v, want %v", s, len(s), !want, want)
		}
	}
	if _, err := Encode(ToEnforcer, Command{ID: 1, Device: "unknown", Verb: VerbOn}); err == nil {
		t.Error("a command naming unknown encoded")
	}
}
