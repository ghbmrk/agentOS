package update

// REQ: UPD-8, SR3-6f-1c
// SR3-6: a Verified's attestation authority is bound to the attestor
// policy it was checked under; a later narrowing retires it.

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// interimFix checks a security fix under the interim rule (the image's test
// box alone on the allow-list) and returns it attested by that box.
func interimFix(t *testing.T) (f *fixture, box ed25519.PrivateKey, pinned []ed25519.PublicKey, v *Verified) {
	t.Helper()
	f = newFixture(t)
	box = newKey(t)
	pinned = []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: pinned, InterimAttestors: pinned})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v = res.Release.WithAttestations([][]byte{pass(t, box, res.Release)}, nil)
	if !v.Security() || !v.InterimAttestation() {
		t.Fatal("the interim check did not authorize the fix")
	}
	return f, box, pinned, v
}

// Acceptance 1: listing the first outside attestor retires the interim
// authority of a release checked before it; Stage refuses it.
func TestSR36NarrowingRetiresInterimVerified(t *testing.T) {
	f, box, pinned, old := interimFix(t)
	outside := newKey(t)
	allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
	f.must(f.store.NoteAttestors(allow, pinned))

	if old.Security() || old.InterimAttestation() {
		t.Fatal("the old release still reports the retired interim authority")
	}
	if err := old.SecurityAutoStage([][]byte{pass(t, box, old)}, nil); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("SecurityAutoStage on the old release: %v", err)
	}
	if again := old.WithAttestations([][]byte{pass(t, box, old)}, nil); again.Security() {
		t.Fatal("re-attesting the old release restored its authority")
	}
	if err := f.store.Stage(old); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage(old) = %v, want ErrPolicyMoved", err)
	}
	if _, ok, _ := f.store.Staged(); ok {
		t.Fatal("the old release was staged")
	}
	// Reverified under the current policy, the box's pass no longer counts.
	res, err := f.check(Options{Attestors: allow, InterimAttestors: pinned})
	if err != nil {
		t.Fatal(err)
	}
	if res.Release.WithAttestations([][]byte{pass(t, box, res.Release)}, nil).Security() {
		t.Fatal("the reverified release counted the test box")
	}
}

// Acceptance 2: removing the outside attestor again, and reopening the
// store, never restores the old interim authority.
func TestSR36RemovalAndReopenDoNotRestoreInterim(t *testing.T) {
	f, box, pinned, old := interimFix(t)
	outside := newKey(t)
	allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
	f.must(f.store.NoteAttestors(allow, pinned))
	reopened := &Store{Dir: f.store.Dir}
	f.must(reopened.NoteAttestors(pinned, pinned))
	if old.Security() || old.InterimAttestation() {
		t.Fatal("removing the outside attestor restored the old authority")
	}
	if err := reopened.Stage(old); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage(old) after reopen = %v, want ErrPolicyMoved", err)
	}
	f.store = reopened
	res, err := f.check(Options{Attestors: pinned, InterimAttestors: pinned})
	if err != nil {
		t.Fatal(err)
	}
	if v := res.Release.WithAttestations([][]byte{pass(t, box, res.Release)}, nil); v.Security() || v.InterimAttestation() {
		t.Fatal("a fresh check after removal revived the interim rule")
	}
}

// Acceptance 3: an ordinary allow-list narrowing (an outside attestor
// removed) retires the authority it gave.
func TestSR36AllowListNarrowingRetiresAuthority(t *testing.T) {
	f := newFixture(t)
	a, b := newKey(t), newKey(t)
	both := []ed25519.PublicKey{a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey)}
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: both})
	if err != nil {
		t.Fatal(err)
	}
	old := res.Release.WithAttestations([][]byte{pass(t, b, res.Release)}, nil)
	if !old.Security() {
		t.Fatal("an allow-listed attestor did not authorize the fix")
	}
	f.must(f.store.NoteAttestors(both[:1], nil))
	if old.Security() {
		t.Fatal("the removed attestor's pass still authorizes the fix")
	}
	if err := f.store.Stage(old); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage(old) = %v, want ErrPolicyMoved", err)
	}
	// The same list again is the same policy: nothing to recheck.
	f.must(f.store.NoteAttestors(both, nil))
	if !old.Security() {
		t.Fatal("an unchanged policy retired the authority")
	}
	f.must(f.store.Stage(old))
}

// Acceptance 3: the policy is rechecked at the commit point, under the
// store lock. No Stage that starts after NoteAttestors returned succeeds.
func TestSR36NarrowingConcurrentWithStage(t *testing.T) {
	for i := 0; i < 20; i++ {
		f, _, pinned, old := interimFix(t)
		outside := newKey(t)
		allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
		var noted atomic.Bool
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 10; k++ {
					after := noted.Load()
					err := f.store.Stage(old)
					if after && err == nil {
						errs <- errors.New("Stage succeeded after the narrowing was noted")
						return
					}
					if err != nil && !errors.Is(err, ErrPolicyMoved) {
						errs <- err
						return
					}
				}
			}()
		}
		if err := f.store.NoteAttestors(allow, pinned); err != nil {
			t.Fatal(err)
		}
		noted.Store(true)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	}
}

// Acceptance 4: a release checked under the current policy still stages,
// and a release without attestation authority is unaffected by a policy
// change (the owner's path); the TUF checks still apply.
func TestSR36CurrentReleasesStillProceed(t *testing.T) {
	f := newFixture(t)
	a := newKey(t)
	allow := []ed25519.PublicKey{a.Public().(ed25519.PublicKey)}
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: allow})
	if err != nil {
		t.Fatal(err)
	}
	attested := res.Release.WithAttestations([][]byte{pass(t, a, res.Release)}, nil)
	if !attested.Security() {
		t.Fatal("a current attested fix lost its authority")
	}
	f.must(f.store.Stage(attested))
	f.must(f.store.DropStaged())

	// The owner's path: no attestation authority, so a policy change does
	// not touch it.
	owner := res.Release
	f.must(f.store.NoteAttestors(nil, nil))
	f.must(f.store.Stage(owner))
	f.must(f.store.DropStaged())

	// A TUF move still refuses it (unchanged by this package).
	f.release(3, nil)
	f.publish(0, 1)
	if _, err := f.check(Options{}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Stage(owner); !errors.Is(err, ErrTrustMoved) {
		t.Fatalf("Stage after a targets move = %v, want ErrTrustMoved", err)
	}
}

// SR3-6f-1c (Security 4a point 2 on #430): an attestor policy the store
// cannot read fails closed. With attestor_policy replaced by a directory, a
// release checked before reports no authority and Stage refuses it.
func TestUnreadablePolicyFailsClosed(t *testing.T) {
	f, _, _, old := interimFix(t)
	path := filepath.Join(f.store.Dir, allowListFile)
	f.must(os.Remove(path))
	f.must(os.Mkdir(path, 0o700))

	if old.Security() || old.InterimAttestation() {
		t.Fatal("an unreadable attestor policy left the old release its authority")
	}
	if err := f.store.Stage(old); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage with an unreadable policy = %v, want ErrPolicyMoved", err)
	}
	if _, ok, _ := f.store.Staged(); ok {
		t.Fatal("the old release was staged")
	}
}
