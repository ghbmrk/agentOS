package update

// REQ: SR3-6f-2a, UPD-8
// SR3-6f-2a: the sticky outside-attestor record is anchored outside the
// store (a TPM NV counter in the vault process, behind Store.Anchor), so
// deleting the record or the whole store never revives the interim rule.

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeAnchor is a monotonic counter. It records, for each call, whether
// the store's outside record existed at that moment.
type fakeAnchor struct {
	mu       sync.Mutex
	n        uint64
	readErr  error
	raiseErr error
	dir      string
	calls    []string
}

func (a *fakeAnchor) Read() (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.readErr != nil {
		return 0, a.readErr
	}
	return a.n, nil
}

func (a *fakeAnchor) Raise() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	call := "raise:no-file"
	if _, err := os.Stat(filepath.Join(a.dir, outsideFile)); err == nil {
		call = "raise:file"
	}
	a.calls = append(a.calls, call)
	if a.raiseErr != nil {
		return a.raiseErr
	}
	if a.n == 0 {
		a.n = 1
	}
	return nil
}

// anchoredInterimFix is interimFix on a store with an anchor.
func anchoredInterimFix(t *testing.T) (*fixture, ed25519.PrivateKey, []ed25519.PublicKey, *Verified, *fakeAnchor) {
	t.Helper()
	f := newFixture(t)
	a := &fakeAnchor{dir: f.store.Dir}
	f.store.Anchor = a
	box := newKey(t)
	pinned := []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{Attestors: pinned, InterimAttestors: pinned})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release.WithAttestations([][]byte{pass(t, box, res.Release)}, nil)
	if !v.Security() || !v.InterimAttestation() {
		t.Fatal("the interim check did not authorize the fix")
	}
	return f, box, pinned, v, a
}

func listOutside(t *testing.T, f *fixture, pinned []ed25519.PublicKey) {
	t.Helper()
	outside := newKey(t)
	allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
	f.must(f.store.NoteAttestors(allow, pinned))
}

// interimCounts reports whether a fresh check with only the interim keys
// grants security authority.
func interimCounts(t *testing.T, f *fixture, box ed25519.PrivateKey, pinned []ed25519.PublicKey) bool {
	t.Helper()
	res, err := f.check(Options{Attestors: pinned, InterimAttestors: pinned})
	if err != nil {
		return false
	}
	v := res.Release.WithAttestations([][]byte{pass(t, box, res.Release)}, nil)
	return v.Security() || v.InterimAttestation()
}

// SR3-6f-2a: the record file deleted, the anchor still says an outside
// attestor was listed.
func TestDeletedOutsideRecordStaysRetiredWithAnchor(t *testing.T) {
	f, box, pinned, old, a := anchoredInterimFix(t)
	listOutside(t, f, pinned)
	if a.n < 1 {
		t.Fatal("listing an outside attestor did not raise the anchor")
	}
	f.must(f.store.NoteAttestors(pinned, pinned))
	f.must(os.Remove(filepath.Join(f.store.Dir, outsideFile)))

	if old.InterimAttestation() || old.Security() {
		t.Fatal("deleting outside_attestor_listed gave the old release its interim authority back")
	}
	if interimCounts(t, f, box, pinned) {
		t.Fatal("deleting outside_attestor_listed revived the interim rule")
	}
}

// SR3-6f-2a: the whole store directory wiped and re-initialised, the
// anchor (at 1) still ends the interim rule.
func TestWipedStoreDirWithAnchorFailsClosed(t *testing.T) {
	f, box, pinned, _, a := anchoredInterimFix(t)
	listOutside(t, f, pinned)
	root, err := os.ReadFile(filepath.Join(f.store.Dir, "root.json"))
	f.must(err)
	f.must(os.RemoveAll(f.store.Dir))
	s, err := InitStore(f.store.Dir, root, 1)
	f.must(err)
	s.Anchor = a
	f.store = s
	if interimCounts(t, f, box, pinned) {
		t.Fatal("a wiped store revived the interim rule despite the anchor")
	}
}

// SR3-6f-2a: an anchor that cannot be read fails closed: no attestation
// authority, and Stage refuses.
func TestAnchorReadErrorFailsClosed(t *testing.T) {
	f, box, pinned, old, a := anchoredInterimFix(t)
	a.readErr = errors.New("synthetic: vault process unreachable")
	if old.Security() || old.InterimAttestation() {
		t.Fatal("an unreadable anchor left the release its authority")
	}
	if err := f.store.Stage(old); !errors.Is(err, ErrPolicyMoved) {
		t.Fatalf("Stage with an unreadable anchor = %v, want ErrPolicyMoved", err)
	}
	if _, ok, _ := f.store.Staged(); ok {
		t.Fatal("the release was staged")
	}
	if interimCounts(t, f, box, pinned) {
		t.Fatal("a fresh check with an unreadable anchor granted interim authority")
	}
}

// SR3-6f-2a: Raise comes before the record is written, and a failed
// Raise still writes the record and returns the error.
func TestRaiseBeforeFile(t *testing.T) {
	f, _, pinned, _, a := anchoredInterimFix(t)
	a.raiseErr = errors.New("synthetic: raise refused")
	outside := newKey(t)
	allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
	if err := f.store.NoteAttestors(allow, pinned); err == nil {
		t.Fatal("a failed Raise was not returned")
	}
	if _, err := os.Stat(filepath.Join(f.store.Dir, outsideFile)); err != nil {
		t.Fatalf("a failed Raise left no outside record: %v", err)
	}
	if len(a.calls) == 0 || a.calls[0] != "raise:no-file" {
		t.Fatalf("Raise calls %q: want the first before the record is written", a.calls)
	}
}

// SR3-6f-2a: following a fork raises the anchor before the record too.
func TestFollowRootRaisesAnchor(t *testing.T) {
	f := newFixture(t)
	a := &fakeAnchor{dir: f.store.Dir}
	f.store.Anchor = a
	fork := newFixture(t)
	f.must(f.follow(fork.rootFile(1), Options{}))
	if a.n < 1 || len(a.calls) == 0 || a.calls[0] != "raise:no-file" {
		t.Fatalf("FollowRoot: anchor %d, calls %q", a.n, a.calls)
	}
}

// SR3-6f-2a: an anchor that answers ErrNoAnchor (a PC with no TPM) leaves
// the store as it is today, and Anchored says so.
func TestNoAnchorBehavesAsToday(t *testing.T) {
	f := newFixture(t)
	f.store.Anchor = noAnchor{}
	box := newKey(t)
	pinned := []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	if !interimCounts(t, f, box, pinned) {
		t.Fatal("a store whose anchor answers ErrNoAnchor lost the interim rule")
	}
	if ok, err := f.store.Anchored(); ok || err != nil {
		t.Fatalf("Anchored() = %v, %v; want false, nil", ok, err)
	}
	listOutside(t, f, pinned)
	if interimCounts(t, f, box, pinned) {
		t.Fatal("the outside record no longer ends the interim rule")
	}
	f.store.Anchor = nil
	if ok, err := f.store.Anchored(); ok || err != nil {
		t.Fatalf("Anchored() without an anchor = %v, %v", ok, err)
	}
	f.store.Anchor = &fakeAnchor{dir: f.store.Dir}
	if ok, err := f.store.Anchored(); !ok || err != nil {
		t.Fatalf("Anchored() with an anchor = %v, %v", ok, err)
	}
}

type noAnchor struct{}

func (noAnchor) Read() (uint64, error) { return 0, ErrNoAnchor }
func (noAnchor) Raise() error          { return ErrNoAnchor }
