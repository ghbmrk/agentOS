package update

// REQ: OSS-10, UPD-8, OSS-9

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// rotateRoot publishes f's next root with the root role's keys replaced
// by fresh ones (threshold 2), signed by the old threshold and the new.
func (f *fixture) rotateRoot() []byte {
	f.t.Helper()
	keys, pubs := genKeys(f.t, f.t.TempDir(), "root-next", 3)
	var old []ed25519.PublicKey
	for _, k := range f.root {
		old = append(old, k.Public().(ed25519.PublicKey))
	}
	f.must(f.repo.Rotate("root", pubs, old, 2))
	for _, k := range []ed25519.PrivateKey{f.root[0], f.root[1], keys[0], keys[1]} {
		f.must(f.repo.Sign("root", k))
	}
	f.must(f.repo.Publish(f.snap, f.ts))
	f.root = keys
	m, err := f.repo.root()
	f.must(err)
	return f.rootFile(m.Signed.Version)
}

// OSS-10w-r: after the project rotates its root keys, its current root is
// the project's when a chain of rotations from the anchor reaches it.
func TestOSS10wrChainWalkAdmitsARotatedProjectRoot(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	v2 := f.rotateRoot()
	v3 := f.rotateRoot()
	o := f.opts(Options{})
	if err := ProjectRoot(v1, v1, nil, o); err != nil {
		t.Fatalf("the anchor itself: %v", err)
	}
	// The next root is its own one-link chain.
	if err := ProjectRoot(v1, v2, nil, o); err != nil {
		t.Fatalf("v1 -> v2 alone: %v", err)
	}
	if err := ProjectRoot(v1, v3, nil, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("two rotations on with no chain: %v", err)
	}
	if err := ProjectRoot(v1, v2, [][]byte{v2}, o); err != nil {
		t.Fatalf("v1 -> v2: %v", err)
	}
	// Links in any order; the target may be among them or not.
	if err := ProjectRoot(v1, v3, [][]byte{v3, v2}, o); err != nil {
		t.Fatalf("v1 -> v2 -> v3: %v", err)
	}
	if err := ProjectRoot(v1, v3, [][]byte{v2}, o); err != nil {
		t.Fatalf("v1 -> v2 -> v3, target apart: %v", err)
	}
	// The chain must end at the target: a newer link than the target is
	// not a chain to it.
	if err := ProjectRoot(v1, v2, [][]byte{v2, v3}, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("a chain past the target: %v", err)
	}
}

// A root re-signed with the anchor's own root keys (no rotation) needs no
// chain, but never below the anchor's version.
func TestOSS10wrSameKeysNeedNoChain(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	f.must(f.repo.Rotate("root", nil, nil, 0)) // a new version, same keys
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.must(f.repo.Publish(f.snap, f.ts))
	v2 := f.rootFile(2)
	o := f.opts(Options{})
	if err := ProjectRoot(v1, v2, nil, o); err != nil {
		t.Fatalf("same keys, newer: %v", err)
	}
	if err := ProjectRoot(v2, v1, nil, o); !errors.Is(err, ErrNotProject) || !errors.Is(err, ErrRollback) {
		t.Fatalf("same keys, older than the anchor: %v", err)
	}
}

// Threat: the anchor's keys at a lowered threshold, signed by fewer of
// them than the anchor's threshold (L3 on #476). Same keys is no shortcut
// past TUF's old-threshold rule; a real lowering is admitted by its chain.
func TestOSS10wrSameKeysNeedTheAnchorsThreshold(t *testing.T) {
	f := newFixture(t)
	f.must(f.repo.Rotate("root", nil, nil, 3))
	for _, k := range f.root {
		f.must(f.repo.Sign("root", k))
	}
	f.must(f.repo.Publish(f.snap, f.ts))
	v2 := f.rootFile(2) // 3 root keys, threshold 3
	o := f.opts(Options{})
	forged := resign(t, v2, func(m *metadata.Metadata[metadata.RootType]) {
		m.Signed.Version = 3
		m.Signed.Roles[metadata.ROOT].Threshold = 2
	}, f.root[0], f.root[1])
	if err := ProjectRoot(v2, forged, nil, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("same keys, two of the anchor's three: %v", err)
	}
	// The project lowers its threshold with all three, then signs with two.
	f.must(f.repo.Rotate("root", nil, nil, 2))
	for _, k := range f.root {
		f.must(f.repo.Sign("root", k))
	}
	f.must(f.repo.Publish(f.snap, f.ts))
	v3 := f.rootFile(3)
	f.must(f.repo.Rotate("root", nil, nil, 0))
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.must(f.repo.Publish(f.snap, f.ts))
	v4 := f.rootFile(4)
	if err := ProjectRoot(v2, v4, nil, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("v4 by two keys, no chain from threshold 3: %v", err)
	}
	if err := ProjectRoot(v2, v4, [][]byte{v3}, o); err != nil {
		t.Fatalf("v2 -> v3 (lowered by all three) -> v4: %v", err)
	}
	if err := ProjectRoot(v2, v3, nil, o); err != nil {
		t.Fatalf("v3, signed by the anchor's threshold: %v", err)
	}
}

// Threat: a forged link, signed by its own new keys but not by a
// threshold of the previous root's; or by other material filed under the
// previous root's key IDs.
func TestOSS10wrForgedLinkIsRefused(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	old := f.root
	v2 := f.rotateRoot()
	o := f.opts(Options{})
	onlyNew := resign(t, v2, func(*metadata.Metadata[metadata.RootType]) {}, f.root[0], f.root[1])
	if err := ProjectRoot(v1, onlyNew, nil, o); !errors.Is(err, ErrNotProject) || !errors.Is(err, ErrSignatures) {
		t.Fatalf("a link without the old threshold: %v", err)
	}
	// One old key is below the old threshold of 2.
	oneOld := resign(t, v2, func(*metadata.Metadata[metadata.RootType]) {}, f.root[0], f.root[1], old[0])
	if err := ProjectRoot(v1, oneOld, nil, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("a link with one old key: %v", err)
	}
	// Other material under the old IDs: signatures are checked against
	// the anchor's key material, never the link's claim.
	m, err := metadata.Root().FromBytes(v2)
	f.must(err)
	a, err := metadata.Root().FromBytes(v1)
	f.must(err)
	var ks []ed25519.PrivateKey
	for _, id := range a.Signed.Roles[metadata.ROOT].KeyIDs {
		k, _ := genKeys(t, t.TempDir(), "imp", 1)
		key, err := metadata.KeyFromPublicKey(k[0].Public())
		f.must(err)
		m.Signed.Keys[id] = key
		m.Signed.Roles[metadata.ROOT].KeyIDs = append(m.Signed.Roles[metadata.ROOT].KeyIDs, id)
		ks = append(ks, k[0])
	}
	m.ClearSignatures()
	for i, k := range append(ks, f.root[0], f.root[1]) {
		s, err := Signer(k)
		f.must(err)
		sig, err := m.Sign(s)
		f.must(err)
		if i < len(ks) {
			sig.KeyID = a.Signed.Roles[metadata.ROOT].KeyIDs[i]
			m.Signatures[len(m.Signatures)-1] = *sig
		}
	}
	imp, err := m.ToBytes(true)
	f.must(err)
	if err := ProjectRoot(v1, imp, nil, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("other material under the anchor's key IDs: %v", err)
	}
}

// Threat: a chain rooted elsewhere, such as a fork rotating its own keys.
func TestOSS10wrChainRootedElsewhereIsRefused(t *testing.T) {
	f := newFixture(t)
	fork := newFixture(t)
	f1 := fork.rootFile(1)
	f2 := fork.rotateRoot()
	o := f.opts(Options{})
	if err := ProjectRoot(f.rootFile(1), f2, [][]byte{f1, f2}, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("a fork's own rotation: %v", err)
	}
	if err := ProjectRoot(f.rootFile(1), f1, nil, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("a fork's root: %v", err)
	}
}

// Threat: rollback. From an anchor at v3, an older project root is
// refused, however chained; root files at or below the anchor are history
// the box passed and are skipped, so the owner may bring them all. A gap is
// refused.
func TestOSS10wrRollbackAndGapsAreRefused(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	v2 := f.rotateRoot()
	v3 := f.rotateRoot()
	v4 := f.rotateRoot()
	o := f.opts(Options{})
	if err := ProjectRoot(v3, v2, [][]byte{v1, v2}, o); !errors.Is(err, ErrNotProject) || !errors.Is(err, ErrRollback) {
		t.Fatalf("v2 from an anchor at v3: %v", err)
	}
	if err := ProjectRoot(v3, v4, [][]byte{v1, v2, v3, v4}, o); err != nil {
		t.Fatalf("every project root file, from an anchor at v3: %v", err)
	}
	// A branch at or below the anchor is skipped, never walked.
	f2 := newFixture(t)
	f2.rootFile(1)
	b2 := f2.rotateRoot()
	if err := ProjectRoot(v3, v4, [][]byte{b2}, o); err != nil {
		t.Fatalf("a foreign v2 beside the chain: %v", err)
	}
	if err := ProjectRoot(v3, v4, nil, o); err != nil {
		t.Fatalf("v3 -> v4: %v", err)
	}
	if err := ProjectRoot(v1, v3, [][]byte{v3}, o); !errors.Is(err, ErrNotProject) {
		t.Fatalf("a gap (v1 -> v3): %v", err)
	}
}

// Threat: a weak intermediate root vouching for the next with one key.
func TestOSS10wrWeakLinkIsRefused(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	f.must(f.repo.Rotate("root", nil, nil, 1))
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.must(f.repo.Publish(f.snap, f.ts))
	weak := f.rootFile(2)
	v3 := f.rotateRoot() // new keys, so only a walk through v2 reaches it
	if err := ProjectRoot(v1, v3, [][]byte{weak}, f.opts(Options{})); !errors.Is(err, ErrNotProject) || !errors.Is(err, ErrWeakThreshold) {
		t.Fatalf("a weak link: %v", err)
	}
}

// Bound: no more links than a check would walk.
func TestOSS10wrChainIsBounded(t *testing.T) {
	f := newFixture(t)
	links := make([][]byte, MaxRootRotations+1)
	for i := range links {
		links[i] = []byte("x")
	}
	if err := ProjectRoot(f.rootFile(1), f.rootFile(1), links, f.opts(Options{})); !errors.Is(err, ErrNotProject) {
		t.Fatalf("too many links: %v", err)
	}
}

// The anchor: on the project chain it is the root the box trusts, after
// any rotation Check verified (security F1 on #476); leaving the chain
// records the root being left; leaving one fork for another does not
// overwrite it.
func TestOSS10wrLeavingTheProjectRecordsItsRoot(t *testing.T) {
	f := newFixture(t)
	if b, err := f.store.ProjectRoot(); err != nil || string(b) != string(f.rootFile(1)) {
		t.Fatalf("before any follow: %v", err)
	}
	v2 := f.rotateRoot()
	f.release(2, nil)
	f.publish(0, 1)
	if _, err := f.check(Options{}); err != nil {
		t.Fatal(err)
	}
	if b, err := f.store.ProjectRoot(); err != nil || string(b) != string(v2) {
		t.Fatalf("after Check rotated to v2: %v", err)
	}
	fork := forkOf(t)
	f.must(f.follow(fork.rootFile(1), Options{}))
	if b, err := f.store.ProjectRoot(); err != nil || string(b) != string(v2) {
		t.Fatalf("after leaving the project at v2: %v", err)
	}
	other := forkOf(t)
	f.must(f.follow(other.rootFile(1), Options{}))
	if b, _ := f.store.ProjectRoot(); string(b) != string(v2) {
		t.Fatal("leaving a fork overwrote the project's root")
	}
}

// A switch back through a rotation chain puts every walked root's keys in
// seen_keys, not only the anchor's and the target's: a rotated-out
// intermediate root key, even allow-listed, never counts as an
// independent attestor (U13, security C2 and C8; L3 on #667).
func TestOSS10wrSwitchBackSeesEveryWalkedRootsKeys(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	fork := forkOf(t)
	f.must(f.follow(fork.rootFile(1), Options{}))
	v2 := f.rotateRoot()
	v3 := f.rotateRoot()
	o := f.opts(Options{})
	sum, err := DescribeRoot(v3, o)
	f.must(err)
	f.must(f.store.FollowProject(v3, [][]byte{v2}, v1, sum.Digest, o))
	seen, err := f.store.seenKeys()
	f.must(err)
	for _, b := range [][]byte{v1, v2, v3} {
		s := mustV(DescribeRoot(b, o))
		for role, fps := range s.Keys {
			for _, fp := range fps {
				if !seen[fp] {
					t.Fatalf("a %s key of root %s is not in seen_keys after the switch back", role, s.RootSHA256[:8])
				}
			}
		}
	}
}

// A stray root file among the brought links (a fork's own root at a version
// the chain needs) is skipped, never a reason to stop: the project's root
// is still the project's, so a named follow of it is refused and a switch
// back through it is admitted (security 4a on #667).
func TestOSS10wrStrayLinkNeitherHidesNorBlocksTheChain(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	v2 := f.rotateRoot()
	v3 := f.rotateRoot()
	stray := forkOf(t).rotateRoot() // the fork's own v2
	o := f.opts(Options{})
	f.must(ProjectRoot(v1, v3, [][]byte{stray, v2}, o))
	f.must(ProjectRoot(v1, v2, [][]byte{stray}, o))
	for _, c := range []struct {
		root  []byte
		links [][]byte
	}{{v2, [][]byte{stray}}, {v3, [][]byte{stray, v2}}, {v3, [][]byte{v2, stray}}} {
		sum := mustV(DescribeRoot(c.root, o))
		if err := f.store.FollowFork(c.root, c.links, v1, sum.Digest, "AgentOS", o); !errors.Is(err, ErrIsProject) {
			t.Fatalf("named follow of project v%d with a stray link: %v, want ErrIsProject", sum.Version, err)
		}
	}
	if !bytes.Equal(storeFile(t, f, "root.json"), v1) {
		t.Fatal("a refused named follow changed the trusted root")
	}
}

// A project record the box cannot read as a root fails a named follow
// closed instead of switching the project check off (L3 on #667).
func TestOSS10wrUnreadableAnchorFailsANamedFollowClosed(t *testing.T) {
	f := newFixture(t)
	v1 := f.rootFile(1)
	fork := forkOf(t)
	f.must(f.follow(fork.rootFile(1), Options{}))
	f.must(os.WriteFile(f.store.p(projectFile), []byte("{}"), 0o600))
	other := forkOf(t).rootFile(1)
	o := f.opts(Options{})
	sum := mustV(DescribeRoot(other, o))
	if err := f.store.FollowFork(other, nil, v1, sum.Digest, "Other", o); err == nil {
		t.Fatal("a named follow went ahead with an unreadable project record")
	}
}
