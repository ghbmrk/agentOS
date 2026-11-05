package driver

// REQ: CLK-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// A case's session prints no planner key, in sixteen verbs (%w and %p
// included), bare and in holders with unexported pointer and interface
// fields (CLK-1, DECOY-b-8, #4837). The key sits in a secret.Secret; the
// same key in a plain field shows, so the check can see one. The key is
// synthetic, but a print that showed it would show a real one the same way.
func TestTheSessionPrintsNoPlannerKey(t *testing.T) {
	s := runCase(t, &model{reply: say("spam")})
	_, planner := pair(4)
	if !planner.Equal(s.planner.Get()) {
		t.Fatal("the session holds another planner key")
	}
	secrettest.NoKey(t, [][]byte{planner.Seed()}, secrettest.Holders(s)...)
}
