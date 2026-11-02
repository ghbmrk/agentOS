package kernel_test

// REQ: KRN-12

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// TestStatePrintsNoDecoy formats the kernel and its state in every verb a
// log line or error might use and finds no decoy value and no honey key's
// ID, which would tell an intruder which key not to use (DECOY-a-7, #4505).
func TestStatePrintsNoDecoy(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	var secrets []any
	for _, e := range tb.Entries() {
		if e.Value != "" { // a destination entry has no value
			secrets = append(secrets, e.Value)
		}
		var hk key.Key
		if e.Kind == decoy.KHoneyKey && json.Unmarshal([]byte(e.Value), &hk) == nil {
			for _, id := range []key.ID{hk.Tip()} {
				secrets = append(secrets, [32]byte(id), id)
			}
		}
	}
	if len(secrets) < 3 {
		t.Fatalf("the table has no honey key: %d values", len(secrets))
	}
	// fmt calls no method through an unexported field, and it prints a
	// nested pointer whole under %s and %q, so the state is also formatted
	// inside the kinds of holder a caller might wrap it in.
	type holder struct {
		k *kernel.Kernel
		s kernel.State
	}
	for _, v := range []any{r.k, *r.k, r.k.State(), *r.k.State(), holder{r.k, *r.k.State()}, &holder{r.k, *r.k.State()}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q"} {
			out := fmt.Sprintf(verb, v)
			for _, s := range secrets {
				forms := []string{strings.Trim(fmt.Sprintf(verb, s), "[]{}\""), fmt.Sprint(s)}
				if b, ok := s.([32]byte); ok {
					forms = append(forms, hex.EncodeToString(b[:]))
				} else {
					forms = append(forms, hex.EncodeToString([]byte(fmt.Sprint(s))))
				}
				for _, f := range forms {
					if len(f) >= 10 && strings.Contains(strings.ToLower(out), strings.ToLower(f)) {
						t.Errorf("%s of %T shows a decoy (%.20s...)", verb, v, f)
					}
				}
			}
		}
	}
}
