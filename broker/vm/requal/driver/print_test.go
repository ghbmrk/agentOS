package driver

// REQ: CLK-1

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A case's session prints no planner key, in sixteen verbs (%w and %p
// included), bare and in holders with unexported pointer and interface
// fields (CLK-1, DECOY-b-8, #4837). The key sits in a handoff.Secret; the
// same key in a plain field shows, so the check can see one. The key is
// synthetic, but a print that showed it would show a real one the same way.
func TestTheSessionPrintsNoPlannerKey(t *testing.T) {
	s := runCase(t, &model{reply: say("spam")})
	_, planner := pair(4)
	if !planner.Equal(s.planner.Get()) {
		t.Fatal("the session holds another planner key")
	}
	type holder struct {
		s *session
		v any
	}
	h := holder{s, s}
	secrets := [][]byte{planner.Seed()}
	if keyShown(secrets, s, h, &h) {
		t.Error("a session prints its planner key")
	}
	type plain struct{ k ed25519.PrivateKey }
	if !keyShown(secrets, &holder{v: &plain{planner}}) {
		t.Error("no print showed the key in a plain field: the check cannot see it")
	}
}

// keyShown formats each of vs in sixteen verbs and reports whether any
// output holds a secret: raw, as hex, as decimal bytes, JSON-escaped or in
// the verb's own form of the bytes (handoff's TestKernelKeysPrintNoKey).
func keyShown(secrets [][]byte, vs ...any) bool {
	shown := false
	for _, v := range vs {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b", "%w", "%p"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				j, _ := json.Marshal(string(s))
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(string(j), `"`), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					shown = shown || len(f) >= 10 && strings.Contains(out, strings.ToLower(f))
				}
			}
		}
	}
	return shown
}
