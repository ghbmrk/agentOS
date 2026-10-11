package update

// REQ: SR3-6-f4a
// SR3-6f-4 (Security 4a point 1 on #595): an ordinary release's passes
// are bound to the attestor policy too, so a removed attestor's pass no
// longer counts toward MinPasses and Stage refuses the release.

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestSR36f4OrdinaryPassesArePolicyBound(t *testing.T) {
	f := newFixture(t)
	a := newKey(t)
	allow := []ed25519.PublicKey{a.Public().(ed25519.PublicKey)}
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: allow})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	atts := [][]byte{pass(t, a, res.Release)}
	if n := res.Release.IndependentPasses(atts, nil); n != 1 {
		t.Fatalf("IndependentPasses under {a} = %d, want 1", n)
	}
	v := res.Release.WithAttestations(atts, nil)
	f.must(f.store.NoteAttestors(nil, nil))
	if n := res.Release.IndependentPasses(atts, nil); n != 0 {
		t.Fatalf("IndependentPasses after removing a = %d, want 0", n)
	}
	if err := f.store.Stage(v); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage after removing a = %v, want ErrPolicyMoved", err)
	}
	if _, ok, _ := f.store.Staged(); ok {
		t.Fatal("the release was staged on a removed attestor's pass")
	}
}

// Control: a release admitted with no attestor listed never rested on a
// pass, so a later policy change does not refuse it.
func TestSR36f4UnattestedOrdinaryStillStages(t *testing.T) {
	f := newFixture(t)
	a := newKey(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release.WithAttestations([][]byte{pass(t, a, res.Release)}, nil)
	f.must(f.store.NoteAttestors([]ed25519.PublicKey{a.Public().(ed25519.PublicKey)}, nil))
	f.must(f.store.Stage(v))
}
