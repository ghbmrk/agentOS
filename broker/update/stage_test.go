package update

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// REQ: UPD-1, UPD-1a, UPD-8
//
// A release handed to the A/B activator is recorded as staged before the
// restart, so the box can commit it after the new slot passes its health
// check, from a later process that no longer holds the *Verified.

func TestStagedReleaseCommitsAfterRestart(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	f.must(err)
	f.must(f.store.Stage(res.Release))

	// A later process: only the store directory survives the restart.
	s := &Store{Dir: f.store.Dir}
	st, ok, err := s.Staged()
	if err != nil || !ok || st.Version != 2 || st.UsrRootHash != f.rootHash || st.ManifestPath != ReleasePath(2) {
		t.Fatalf("staged %+v %v %v", st, ok, err)
	}
	if err := s.CommitStaged(3); err == nil {
		t.Fatal("committed a version that was not staged")
	}
	f.must(s.CommitStaged(2))
	in, err := s.Installed()
	if err != nil || in.Version != 2 || in.ManifestPath != ReleasePath(2) || in.UnconfirmedFreshness {
		t.Fatalf("installed %+v %v", in, err)
	}
	if _, ok, _ := s.Staged(); ok {
		t.Fatal("still staged after commit")
	}
	if err := s.CommitStaged(2); err == nil {
		t.Fatal("committed twice")
	}
}

func TestStageRefusesUnverifiedAndOlderReleases(t *testing.T) {
	f := newFixture(t)
	if err := f.store.Stage(&Verified{}); !errors.Is(err, ErrNotChecked) {
		t.Fatalf("unsealed: %v", err)
	}
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	f.must(err)
	f.must(f.store.Stage(res.Release))
	f.must(f.store.CommitStaged(2))
	if err := f.store.Stage(res.Release); !errors.Is(err, ErrRollback) {
		t.Fatalf("staging the installed release again: %v", err)
	}
}

// A fallback drops the staged record and leaves everything else in the
// store as it was: the installed release, and the root metadata with its
// key rotations and revocations, which live outside the image (UPD-1).
func TestDropStagedKeepsInstalledAndRoot(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	f.must(err)
	before, err := f.store.Installed()
	f.must(err)
	root, err := os.ReadFile(f.store.p("root.json"))
	f.must(err)
	f.must(f.store.Stage(res.Release))
	f.must(f.store.DropStaged())
	if _, ok, _ := f.store.Staged(); ok {
		t.Fatal("still staged")
	}
	if in, _ := f.store.Installed(); in != before {
		t.Fatalf("installed changed: %+v", in)
	}
	if r, _ := os.ReadFile(f.store.p("root.json")); !bytes.Equal(r, root) {
		t.Fatal("root metadata changed")
	}
	if err := f.store.CommitStaged(2); err == nil {
		t.Fatal("committed a dropped release")
	}
}
