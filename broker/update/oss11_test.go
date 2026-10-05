package update

import (
	"os"
	"path/filepath"
	"testing"
)

// REQ: OSS-11
//
// TR2: the public repository is a publication channel, not a runtime
// dependency. A box checks and installs updates from a local directory
// copy as it would from the repository itself, and with that copy gone a
// check fails and nothing about the installed release changes.
func TestUpdatesWorkFromALocalDirectory(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	local := filepath.Join(t.TempDir(), "copy")
	dir := toDrive(t, copyRepo(t, f.repo.Dir), local)

	res, err := f.checkOn(f.store, dir, Options{})
	if err != nil || res.Release == nil || !res.Release.Fresh() {
		t.Fatalf("online check from a local directory: %v %v", res.Release, err)
	}
	f.must(res.Release.Fetch(dir, "host-image/2/usr.img", filepath.Join(t.TempDir(), "usr.img")))
	f.must(f.store.Commit(res.Release))
	before, err := f.store.Installed()
	if err != nil || before.Version != 2 || before.UnconfirmedFreshness {
		t.Fatalf("installed %+v %v", before, err)
	}

	f.must(os.RemoveAll(local))
	if _, err := f.checkOn(f.store, dir, Options{}); err == nil {
		t.Fatal("a check passed with nothing to read")
	}
	if after, err := f.store.Installed(); err != nil || after != before {
		t.Fatalf("the installed release changed: %+v -> %+v (%v)", before, after, err)
	}
}
