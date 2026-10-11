package change

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// REQ: UPD-8, CHG-3
//
// SR3-6: ProposeRelease rechecks attestation authority when it proposes.
// A security release checked before the box's attestor policy narrowed
// takes the owner's path, not the security standing policy.

func TestSR36NarrowedPolicyProposesThroughOwner(t *testing.T) {
	s := newEnv(t, func(c *Config) { c.SecurityAutoStage = true })
	v, st := updatetest.Box(t, 21, true, map[string][]byte{"host-image/release": []byte("host")})
	if !v.Security() {
		t.Fatal("the fixture's fix is not attested")
	}
	if err := st.NoteAttestors(nil, nil); err != nil {
		t.Fatal(err)
	}
	r := s.release(v)
	if r.Basis == BasisSecurity || !s.owner.wasAsked(adoptID(r.ID)) {
		t.Fatalf("a retired authority auto-adopted: %+v", r)
	}
}
