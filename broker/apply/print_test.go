package apply

// REQ: CLK-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// The applier prints no key: its Config and the Applier that holds it show
// none of the image-pinned update key's holder, in sixteen verbs (%w and %p
// included), bare and in holders with unexported pointer, value and
// interface fields (CLK-1, DECOY-b-8, #4837). Holder sits in a
// secret.Secret; the same key in a plain field shows, so the check can see
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
	secrettest.NoKey(t, [][]byte{r.holder.Seed()}, append(secrettest.Holders(cfg), secrettest.Holders(a)...)...)
}
