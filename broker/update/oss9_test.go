package update

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// REQ: OSS-9

// Attestations are evidence, never authority (OSS-9): any number of
// passing reports from keys the box does not list counts for nothing, so
// fake installations cannot stage a security fix by volume. Neither do
// the box's own report or a listed key that holds a signing role.
func TestOSS9UnlistedReportsAreNeverAuthority(t *testing.T) {
	f, _ := securityFix(t)
	listed := newKey(t)
	res, err := f.check(Options{Attestors: f.attestors(listed)})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release
	var atts [][]byte
	for i := 0; i < 1000; i++ {
		atts = append(atts, pass(t, newKey(t), v))
	}
	if n := v.IndependentPasses(atts, nil); n != 0 {
		t.Fatalf("1000 unlisted reports counted as %d", n)
	}
	if n := v.MaintainerPasses(atts, nil); n != 0 {
		t.Fatalf("unlisted reports counted as maintainer evidence: %d", n)
	}
	if v.WithAttestations(atts, nil).Security() || !errors.Is(v.SecurityAutoStage(atts, nil), ErrNeedsAttestation) {
		t.Fatal("unlisted reports staged a security fix")
	}
	// The box's own report never counts, even with its key listed.
	own := newKey(t)
	res, err = f.check(Options{Attestors: f.attestors(own)})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	if n := res.Release.IndependentPasses([][]byte{pass(t, own, res.Release)}, own.Public().(ed25519.PublicKey)); n != 0 {
		t.Fatalf("the box's own report counted: %d", n)
	}
	// A listed key that holds a signing role never counts.
	res, err = f.check(Options{Attestors: []ed25519.PublicKey{f.root[0].Public().(ed25519.PublicKey)}})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	if n := res.Release.IndependentPasses([][]byte{pass(t, f.root[0], res.Release)}, nil); n != 0 {
		t.Fatalf("a signing key counted as an attestor: %d", n)
	}
	// One listed independent report is what it takes.
	if n := v.IndependentPasses(append(atts, pass(t, listed, v)), nil); n != 1 {
		t.Fatalf("the listed report counted %d", n)
	}
}
