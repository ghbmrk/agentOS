package apply

// REQ: CLK-1

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The applier prints no key: its Config and the Applier that holds it show
// none of the image-pinned update key's holder, in sixteen verbs (%w and %p
// included), bare and in holders with unexported pointer, value and
// interface fields (CLK-1, DECOY-b-8, #4837). Holder sits in a
// handoff.Secret; the same key in a plain field shows, so the check can see
// one. Catches an error or debug line in the update clerk's process that
// formats its Config and puts the holder key in a log.
func TestTheApplierPrintsNoKey(t *testing.T) {
	r := newRig(t)
	r.release(2, false)
	cfg := r.a.cfg
	// The rig's kernel and state point back at the rig, which keeps the
	// key in a plain field for its own use; a bad verb would print it
	// through them, so the probe drops them.
	cfg.Kernel, cfg.State = nil, nil
	a := &Applier{cfg: cfg}
	type holder struct {
		a  *Applier
		c  Config
		cp *Config
		v  any
	}
	h := holder{a, cfg, &cfg, cfg}
	secrets := [][]byte{r.holder.Seed()}
	if keyShown(secrets, cfg, &cfg, a, h, &h) {
		t.Error("the applier's Config prints its holder key")
	}
	type plain struct{ k ed25519.PrivateKey }
	if !keyShown(secrets, &holder{v: &plain{r.holder}}) {
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
