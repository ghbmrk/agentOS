package update

// REQ: UPD-8, UPD-5, OSS-9, CH-12
// SR3-6-f6: Bound reports whether a release's admission still holds under
// the box's attestor policy, and Stage binds a raw Check result whose
// check listed an attestor as if it had rested on a pass.

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
)

// T2b: Bound fails closed on nil, on a moved policy and on an unreadable
// store, and holds for a release that never rested on a pass.
func TestBoundFailsClosed(t *testing.T) {
	var nilV *Verified
	if nilV.Bound() {
		t.Fatal("nil is bound")
	}
	if (&Verified{}).Bound() {
		t.Fatal("a zero Verified is bound")
	}
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
	held := res.Release.WithAttestations(atts, nil)
	unattested := res.Release.WithAttestations(nil, nil)
	if !held.Bound() || !unattested.Bound() || !res.Release.Bound() {
		t.Fatal("not bound under the policy it was checked under")
	}
	f.must(f.store.NoteAttestors(nil, nil))
	if held.Bound() {
		t.Fatal("bound after the attestor whose pass it rested on was removed")
	}
	if res.Release.Bound() {
		t.Fatal("the raw Check result, never judged, is bound after the policy moved")
	}
	if !unattested.Bound() {
		t.Fatal("a release judged with no pass is retired by a policy change it never rested on")
	}
	// Unreadable: the store's policy file cannot be read.
	g := newFixture(t)
	g.release(2, nil)
	g.publish(0, 1)
	res, err = g.check(Options{Attestors: allow})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	h := res.Release.WithAttestations([][]byte{pass(t, a, res.Release)}, nil)
	q := g.store.p(allowListFile)
	g.must(os.RemoveAll(q))
	g.must(os.Mkdir(q, 0o700))
	if h.Bound() || res.Release.Bound() {
		t.Fatal("bound on an unreadable store")
	}
}

// T3: after a narrowing, the copy Loop 3 held is refused, and so is the
// raw Check result the same pass admitted: Stage binds an unjudged result
// whose check listed an attestor, so the W5b path cannot stage around the
// binding by passing the raw result.
func TestStageOfRawCheckResultRefusedAfterNarrowing(t *testing.T) {
	f := newFixture(t)
	a := newKey(t)
	allow := []ed25519.PublicKey{a.Public().(ed25519.PublicKey)}
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: allow})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	held := res.Release.WithAttestations([][]byte{pass(t, a, res.Release)}, nil)
	f.must(f.store.NoteAttestors(nil, nil))
	if err := f.store.Stage(held); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage(held) after narrowing = %v, want ErrPolicyMoved", err)
	}
	if err := f.store.Stage(res.Release); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage(raw Check result) after narrowing = %v, want ErrPolicyMoved", err)
	}
	if _, ok, _ := f.store.Staged(); ok {
		t.Fatal("a release was staged after the narrowing")
	}
	// Control: a raw result checked with no attestor listed never rested
	// on a pass, so a policy change does not refuse it (the owner's path,
	// apply's TestSR36OwnerPathUnaffectedByPolicyChange).
	h := newFixture(t)
	h.release(2, nil)
	h.publish(0, 1)
	res, err = h.check(Options{Attestors: []ed25519.PublicKey{}})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	if !res.Release.Bound() {
		t.Fatal("a raw result checked with no attestor is not bound")
	}
	h.must(h.store.NoteAttestors(allow, nil))
	if !res.Release.Bound() {
		t.Fatal("a policy change retired a raw result that never rested on a pass")
	}
	h.must(h.store.Stage(res.Release))
	// Control: the raw result stages while the policy it was checked
	// under holds.
	g := newFixture(t)
	g.release(2, nil)
	g.publish(0, 1)
	res, err = g.check(Options{Attestors: allow})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	g.must(g.store.Stage(res.Release))
}
