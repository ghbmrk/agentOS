package update

import (
	"os"
	"testing"
)

// REQ: UPD-1, UPD-1a, OP-4
//
// SR3-4: committing a staged release after the restart is idempotent for
// that exact release (version, /usr root hash and manifest digest), so a
// crash or an error after the commit never leaves the box unable to settle.

func stagedFixture(t *testing.T) (*fixture, Ref) {
	t.Helper()
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	f.must(err)
	f.must(f.store.Stage(res.Release))
	r := res.Release.Ref()
	if r.Version != 2 || r.UsrRootHash != f.rootHash || r.ManifestSHA256 == "" {
		t.Fatalf("ref %+v", r)
	}
	return f, r
}

func TestCommitReleaseIsIdempotentForTheExactRelease(t *testing.T) {
	f, r := stagedFixture(t)
	s := &Store{Dir: f.store.Dir} // a later process
	f.must(s.CommitRelease(r))
	in, err := s.Installed()
	if err != nil || in.Version != 2 || in.UsrRootHash != r.UsrRootHash || in.ManifestSHA256 != r.ManifestSHA256 {
		t.Fatalf("installed %+v %v", in, err)
	}
	if _, ok, _ := s.Staged(); ok {
		t.Fatal("still staged after commit")
	}
	// A retry after the commit (its caller saw an error, or crashed) is a
	// success, and changes nothing.
	f.must(s.CommitRelease(r))
	if again, _ := s.Installed(); again != in {
		t.Fatalf("installed changed on replay: %+v", again)
	}
}

// The installed record was written but staged.json was not removed yet.
func TestCommitReleaseFinishesAnInterruptedCommit(t *testing.T) {
	f, r := stagedFixture(t)
	staged, err := os.ReadFile(f.store.p("staged.json"))
	f.must(err)
	f.must(f.store.CommitRelease(r))
	f.must(os.WriteFile(f.store.p("staged.json"), staged, 0o600))
	f.must(f.store.CommitRelease(r))
	if _, ok, _ := f.store.Staged(); ok {
		t.Fatal("staged record left behind")
	}
	if in, _ := f.store.Installed(); in.Version != 2 {
		t.Fatalf("installed %+v", in)
	}
}

// Another release with the same version is never taken for the committed
// one, before or after the commit.
func TestCommitReleaseRejectsADifferentReleaseWithTheSameVersion(t *testing.T) {
	f, r := stagedFixture(t)
	for _, other := range []Ref{
		{Version: r.Version, UsrRootHash: flip(r.UsrRootHash), ManifestSHA256: r.ManifestSHA256},
		{Version: r.Version, UsrRootHash: r.UsrRootHash, ManifestSHA256: flip(r.ManifestSHA256)},
		{Version: 3, UsrRootHash: r.UsrRootHash, ManifestSHA256: r.ManifestSHA256},
	} {
		if err := f.store.CommitRelease(other); err == nil {
			t.Fatalf("committed %+v while %+v is staged", other, r)
		}
	}
	f.must(f.store.CommitRelease(r))
	for _, other := range []Ref{
		{Version: r.Version, UsrRootHash: flip(r.UsrRootHash), ManifestSHA256: r.ManifestSHA256},
		{Version: r.Version, UsrRootHash: r.UsrRootHash, ManifestSHA256: flip(r.ManifestSHA256)},
	} {
		if err := f.store.CommitRelease(other); err == nil {
			t.Fatalf("replay of a different release %+v succeeded", other)
		}
	}
	if err := f.store.CommitRelease(Ref{}); err == nil {
		t.Fatal("committed an empty ref")
	}
}

func TestCommitReleaseRefusesWhatWasNeverStaged(t *testing.T) {
	f, r := stagedFixture(t)
	before, err := f.store.Installed()
	f.must(err)
	f.must(f.store.DropStaged())
	if err := f.store.CommitRelease(r); err == nil {
		t.Fatal("committed a dropped release")
	}
	if in, _ := f.store.Installed(); in != before {
		t.Fatalf("installed %+v", in)
	}
	if r := (&Verified{}).Ref(); r != (Ref{}) {
		t.Fatalf("unsealed release has a ref: %+v", r)
	}
}

// flip changes the first hex digit of h.
func flip(h string) string {
	if h[0] == '0' {
		return "1" + h[1:]
	}
	return "0" + h[1:]
}
