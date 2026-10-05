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

// Evidence for the owner's text (OSS-9 A2): listed independent attestors,
// and maintainer-operated keys the signed list or the image names. A key
// that only labels itself maintainer-operated, or any other unlisted key,
// is not counted at all (Q-A).
func TestOSS9EvidenceCountsOnlyListedKeys(t *testing.T) {
	f := newFixture(t)
	ci, box, stranger, listed := newKey(t), newKey(t), newKey(t), newKey(t)
	f.must(f.repo.SetMaintainerAttestors([]ed25519.PublicKey{ci.Public().(ed25519.PublicKey)}))
	f.release(2, nil)
	f.publish(0, 1)
	pinned := []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	res, err := f.check(Options{Attestors: f.attestors(listed), InterimAttestors: pinned})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release
	claim, err := Attest(stranger, v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Operator: OperatorMaintainer})
	f.must(err)
	atts := [][]byte{pass(t, ci, v), pass(t, box, v), claim, pass(t, newKey(t), v), pass(t, listed, v)}
	if e := v.Evidence(atts, nil); e != (Evidence{Independent: 1, Maintainer: 2}) {
		t.Fatalf("evidence %+v", e)
	}
	if e := (&Verified{}).Evidence(atts, nil); e != (Evidence{}) {
		t.Fatalf("an unchecked release has evidence: %+v", e)
	}
}
