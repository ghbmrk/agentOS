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

// TestStatePrintsNoDecoy formats the kernel, its log and its state in every
// verb a log line or error might use and finds no decoy value, no honey
// key's ID, which would tell an intruder which key not to use, and not the
// box's signing key: raw, in the verb's own form, as hex or as decimal bytes,
// whether bare or JSON-escaped as the log's entry body holds them (DECOY-a-7,
// CLK-1, #4505).
func TestStatePrintsNoDecoy(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	secrets := [][]byte{r.head.priv}
	for _, e := range tb.Entries() {
		if e.Value == "" { // a destination entry has no value
			continue
		}
		j, _ := json.Marshal(e.Value)
		secrets = append(secrets, []byte(e.Value), j[1:len(j)-1])
		var hk key.Key
		if e.Kind == decoy.KHoneyKey && json.Unmarshal([]byte(e.Value), &hk) == nil {
			id := hk.Tip()
			secrets = append(secrets, id[:])
		}
	}
	if len(secrets) < 4 {
		t.Fatalf("the table has no honey key: %d secrets", len(secrets))
	}
	// fmt calls no method through an unexported field, and it prints a
	// nested pointer whole under a verb a pointer has no form for, so the
	// state is also formatted inside a holder a caller might wrap it in.
	type holder struct {
		k *kernel.Kernel
		s kernel.State
	}
	for _, v := range []any{r.k, *r.k, r.k.Log(), *r.k.Log(), r.k.State(), *r.k.State(), holder{r.k, *r.k.State()}, &holder{r.k, *r.k.State()}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"),
					strings.Trim(fmt.Sprintf(verb, s), "[]"), strings.Trim(fmt.Sprintf(verb, string(s)), "[]\"")} {
					if len(f) >= 10 && strings.Contains(out, strings.ToLower(f)) {
						t.Errorf("%s of %T shows a secret (%.20s...)", verb, v, f)
					}
				}
			}
		}
	}
}
