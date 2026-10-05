package update

// REQ: OSS-9, OSS-10, UPD-8

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// rootFile is the repository's published root of version n.
func (f *fixture) rootFile(n int64) []byte {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.repo.Dir, "metadata", fmt.Sprintf("%d.root.json", n)))
	f.must(err)
	return b
}

func (f *fixture) opts(o Options) Options {
	if o.Now == nil {
		o.Now = func() time.Time { return f.now }
	}
	return o
}

// follow switches f's box to root, as the tier-4 page does: describe what
// the owner is shown, then follow exactly that.
func (f *fixture) follow(root []byte, o Options) error {
	name := "Acme"
	if bytes.Equal(root, f.rootFile(1)) {
		name = "" // switching back to the project
	}
	sum, err := DescribeRoot(root, f.opts(o))
	if err != nil {
		return err
	}
	return f.store.FollowRoot(root, sum.Digest, name, f.opts(o))
}

// checkAt checks the repository of other with f's box.
func (f *fixture) checkAt(other *fixture, o Options) (Result, error) {
	o = f.opts(o)
	if o.Attestors == nil {
		o.Attestors = f.attestors()
	}
	return f.store.Check(DirSource(other.repo.Dir), o)
}

// forkOf is a fork of f's project: its own keys and repository, with
// releases above f's installed one.
func forkOf(t *testing.T, versions ...int64) *fixture {
	k := newFixture(t)
	for _, v := range versions {
		k.release(v, nil)
	}
	if len(versions) > 0 {
		k.publish(0, 1)
	}
	return k
}

func storeFile(t *testing.T, f *fixture, name string) []byte {
	b, err := os.ReadFile(f.store.p(name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

// B1, B4: following a fork changes which chain the box checks, and only
// FollowRoot changes it.
func TestOSS9FollowForkRoot(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	fork := forkOf(t, 2, 3)
	if res, err := f.check(Options{}); err != nil || res.Release == nil || res.Release.Version() != "2" {
		t.Fatal("project release before following:", res.Release, err)
	}
	if _, err := f.checkAt(fork, Options{}); err == nil {
		t.Fatal("the fork's repository passed before the box followed it")
	}
	f.must(f.follow(fork.rootFile(1), Options{}))
	for _, n := range []string{"timestamp.json", "snapshot.json", followFile} {
		if storeFile(t, f, n) != nil {
			t.Fatalf("%s from the old chain kept", n)
		}
	}
	res, err := f.checkAt(fork, Options{})
	if err != nil || res.Release == nil || res.Release.Version() != "3" {
		t.Fatal("fork release after following:", res.Release, err)
	}
	shown := mustV(DescribeRoot(fork.rootFile(1), f.opts(Options{})))
	if src := mustV(f.store.Following()); src.Name != "Acme" || !src.Since.Equal(t0) ||
		src.RootSHA256 != shown.RootSHA256 || src.Fingerprint != shown.Keys[metadata.ROOT][0] {
		t.Fatalf("source %+v", src)
	}
	if _, err := f.check(Options{}); !errors.Is(err, ErrSignatures) {
		t.Fatalf("the project's repository still passed after the switch: %v", err)
	}
	// Switching back is the same act, with the project's root.
	f.must(f.follow(f.rootFile(1), Options{}))
	if res, err := f.check(Options{}); err != nil || res.Release == nil || res.Release.Version() != "2" {
		t.Fatal("project release after switching back:", res.Release, err)
	}
	if src := mustV(f.store.Following()); src != (Followed{}) || storeFile(t, f, sourceFile) != nil {
		t.Fatalf("still following %+v after switching back", src)
	}
}

// resign replaces root's signatures with the given keys' after mod.
func resign(t *testing.T, root []byte, mod func(*metadata.Metadata[metadata.RootType]), keys ...ed25519.PrivateKey) []byte {
	m, err := metadata.Root().FromBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	mod(m)
	m.ClearSignatures()
	for _, k := range keys {
		s, err := Signer(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Sign(s); err != nil {
			t.Fatal(err)
		}
	}
	b, err := m.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Security C3: a root to follow passes its own root-role threshold, the
// box's floor (never below 2), has no zero threshold and is unexpired.
// Anything refused leaves the store as it was.
func TestOSS9FollowRootRefusesWeakRoots(t *testing.T) {
	fork := forkOf(t, 2)
	good := fork.rootFile(1)
	k := fork.root
	threshold := func(role string, n int) func(*metadata.Metadata[metadata.RootType]) {
		return func(m *metadata.Metadata[metadata.RootType]) { m.Signed.Roles[role].Threshold = n }
	}
	same := func(*metadata.Metadata[metadata.RootType]) {}
	for _, c := range []struct {
		name string
		root []byte
		o    Options
		want error
	}{
		{"one root signature", resign(t, good, same, k[0]), Options{}, ErrSignatures},
		{"signed by the wrong keys", resign(t, good, same, fork.tgt[0], fork.tgt[1]), Options{}, ErrSignatures},
		{"root threshold 1", resign(t, good, threshold(metadata.ROOT, 1), k[0]), Options{}, ErrWeakThreshold},
		{"root threshold 1, floor asked 1", resign(t, good, threshold(metadata.ROOT, 1), k[0]), Options{MinThreshold: 1}, ErrWeakThreshold},
		{"targets threshold 1", resign(t, good, threshold(metadata.TARGETS, 1), k[0], k[1]), Options{}, ErrWeakThreshold},
		{"floor raised to 3", good, Options{MinThreshold: 3}, ErrWeakThreshold},
		{"snapshot threshold 0", resign(t, good, threshold(metadata.SNAPSHOT, 0), k[0], k[1]), Options{}, ErrSignatures},
		{"timestamp threshold 0", resign(t, good, threshold(metadata.TIMESTAMP, 0), k[0], k[1]), Options{}, ErrSignatures},
		{"expired", good, Options{Now: func() time.Time { return time.Now().Add(RootExpiry + time.Hour) }}, ErrExpired},
		{"not a root", []byte(`{"signed":{}}`), Options{}, ErrBadRepository},
		// L3 on #180: go-tuf dereferences a null entry while parsing, and
		// an oversized root is refused before it is parsed at all.
		{"a null role", edit(t, good, `"roles": {`, `"roles": {"x": null, `), Options{}, ErrBadRepository},
		{"a null key", edit(t, good, `"keys": {`, `"keys": {"x": null, `), Options{}, ErrBadRepository},
		{"over 4 MiB", append(append([]byte{}, good...), bytes.Repeat([]byte(" "), maxMetadata)...), Options{}, ErrBadRepository},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			before := storeFile(t, f, "root.json")
			if _, err := DescribeRoot(c.root, f.opts(c.o)); !errors.Is(err, c.want) {
				t.Fatalf("describe: %v, want %v", err, c.want)
			}
			if err := f.store.FollowRoot(c.root, Digest(c.root), "Acme", f.opts(c.o)); !errors.Is(err, c.want) {
				t.Fatalf("follow: %v, want %v", err, c.want)
			}
			if !bytes.Equal(before, storeFile(t, f, "root.json")) || storeFile(t, f, outsideFile) != nil {
				t.Fatal("a refused root changed the store")
			}
		})
	}
}

// Security C6: the switch follows only the root whose description the
// owner approved, and the description covers what the page shows.
func TestOSS9FollowRootNeedsTheApprovedDigest(t *testing.T) {
	f := newFixture(t)
	fork, other := forkOf(t, 2), forkOf(t, 2)
	shown, err := DescribeRoot(fork.rootFile(1), f.opts(Options{}))
	f.must(err)
	if len(shown.Keys[metadata.ROOT]) != 3 || shown.Thresholds[metadata.ROOT] != 2 || shown.Thresholds[metadata.TARGETS] != 2 ||
		!shown.Expires.After(time.Now().Add(RootExpiry-time.Hour)) || shown.Version != 1 {
		t.Fatalf("description: %+v", shown)
	}
	before := storeFile(t, f, "root.json")
	for name, d := range map[string]string{
		"another root's":  mustV(DescribeRoot(other.rootFile(1), f.opts(Options{}))).Digest,
		"the bytes alone": Digest(fork.rootFile(1)),
		"none":            "",
	} {
		if err := f.store.FollowRoot(fork.rootFile(1), d, "Acme", f.opts(Options{})); !errors.Is(err, ErrFollowNotApproved) {
			t.Fatalf("%s digest: %v", name, err)
		}
	}
	if !bytes.Equal(before, storeFile(t, f, "root.json")) {
		t.Fatal("an unapproved follow changed the root")
	}
	f.must(f.store.FollowRoot(fork.rootFile(1), shown.Digest, "Acme", f.opts(Options{})))
	// Same bytes, different shown expiry: a different digest.
	later := shown
	later.Expires = later.Expires.Add(time.Hour)
	if later.digest() == shown.Digest {
		t.Fatal("the digest does not cover the shown expiry")
	}
}

// Security C5, UPD-8: following a fork keeps the installed version, so no
// release older than it is accepted from the fork.
func TestOSS9FollowKeepsAntiRollback(t *testing.T) {
	f := newFixture(t)
	f.release(5, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	f.must(err)
	f.must(f.store.Commit(res.Release))
	fork := forkOf(t, 2, 3)
	f.must(f.follow(fork.rootFile(1), Options{}))
	res, err = f.checkAt(fork, Options{})
	if err != nil || res.Release != nil {
		t.Fatal("an older fork release was offered:", res.Release, err)
	}
	if in, _ := f.store.Installed(); in.Version != 5 {
		t.Fatalf("installed version moved: %d", in.Version)
	}
	fork.release(6, nil)
	fork.publish(0, 1)
	if res, err := f.checkAt(fork, Options{}); err != nil || res.Release == nil || res.Release.Version() != "6" {
		t.Fatal("a newer fork release:", res.Release, err)
	}
}

// Security R2 on #180: a root of the chain the box follows now that is no
// newer is a rollback, refused before anything is written; a root of
// another chain with a lower version, such as the project's own, is a
// switch.
func TestOSS9FollowRefusesAnOlderRootOfTheSameChain(t *testing.T) {
	f := newFixture(t)
	fork := forkOf(t, 2)
	v2 := resign(t, fork.rootFile(1), func(m *metadata.Metadata[metadata.RootType]) { m.Signed.Version = 2 }, fork.root[0], fork.root[1])
	sibling := resign(t, fork.rootFile(1), func(m *metadata.Metadata[metadata.RootType]) {
		m.Signed.Version = 2
		m.Signed.Expires = m.Signed.Expires.Add(-time.Hour)
	}, fork.root[0], fork.root[1])
	f.must(f.follow(v2, Options{}))
	before := storeFile(t, f, "root.json")
	for _, r := range [][]byte{fork.rootFile(1), sibling} {
		if err := f.follow(r, Options{}); !errors.Is(err, ErrRollback) {
			t.Fatalf("a root of the same chain, no newer: %v", err)
		}
	}
	if !bytes.Equal(before, storeFile(t, f, "root.json")) {
		t.Fatal("a refused rollback changed the store")
	}
	// The trusted root itself re-trusts nothing: following it again only
	// renames the source.
	f.must(f.follow(v2, Options{}))
	if !bytes.Equal(before, storeFile(t, f, "root.json")) {
		t.Fatal("following the trusted root again changed it")
	}
	f.must(f.follow(f.rootFile(1), Options{}))
}

// Security C2 and C8: every key the fork's root lists, in any role, joins
// seen_keys before the switch and never leaves it, so a fork maintainer's
// key never counts as an attestor, even allow-listed and even after
// switching back; nor does a former root's key, or a self-labelled
// maintainer key, on the fork.
func TestOSS9SigningKeysNeverAttestAcrossForks(t *testing.T) {
	f := newFixture(t)
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	fork := forkOf(t)
	fork.release(2, func(r *Manifest) { r.Security = true })
	fork.publish(0, 1)
	forkKey := fork.ts    // a fork maintainer's online key
	former := f.root[0]   // the project's root key
	labelled := newKey(t) // labels itself maintainer-operated
	listed := newKey(t)   // an ordinary outside attestor
	allow := f.attestors(forkKey, former, labelled, listed)
	o := Options{Attestors: allow}
	res, err := f.check(o)
	f.must(err)
	if n := res.Release.IndependentPasses([][]byte{pass(t, forkKey, res.Release)}, nil); n != 1 {
		t.Fatalf("before the switch the fork's key is just a listed attestor: %d", n)
	}
	f.must(f.follow(fork.rootFile(1), o))
	seen, err := f.store.seenKeys()
	f.must(err)
	for _, sum := range []RootSummary{mustV(DescribeRoot(fork.rootFile(1), f.opts(o))), mustV(DescribeRoot(f.rootFile(1), f.opts(o)))} {
		for role, fps := range sum.Keys {
			for _, fp := range fps {
				if !seen[fp] {
					t.Fatalf("a %s key of root %s is not in seen_keys after the switch", role, sum.RootSHA256[:8])
				}
			}
		}
	}
	res, err = f.checkAt(fork, o)
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release
	claim, err := Attest(labelled, v, Statement{Result: ResultPass, Channel: ChannelFast, Hardware: floorPC, Operator: OperatorMaintainer})
	f.must(err)
	for name, b := range map[string][]byte{
		"fork maintainer": pass(t, forkKey, v), "former root": pass(t, former, v), "self-labelled": claim,
	} {
		if n := v.IndependentPasses([][]byte{b}, nil); n != 0 || v.WithAttestations([][]byte{b}, nil).Security() {
			t.Fatalf("%s key counted on the fork: %d", name, n)
		}
	}
	if n := v.IndependentPasses([][]byte{pass(t, listed, v)}, nil); n != 1 {
		t.Fatalf("a listed outside attestor stops counting on a fork (Q-B keeps it): %d", n)
	}
	f.must(f.follow(f.rootFile(1), o))
	res, err = f.check(o)
	f.must(err)
	if n := res.Release.IndependentPasses([][]byte{pass(t, forkKey, res.Release)}, nil); n != 0 {
		t.Fatalf("switching back forgot the fork's key: %d", n)
	}
}

// Security C1, B2: the project's test box is the interim attestor for the
// project's releases only. Following any fork ends the interim rule for
// good, switching back included.
func TestOSS9InterimNeverRevivesAfterAFork(t *testing.T) {
	f := newFixture(t)
	f.release(2, func(r *Manifest) { r.Security = true })
	f.publish(0, 1)
	box := newKey(t)
	only := []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	o := Options{Attestors: only, InterimAttestors: only}
	res, err := f.check(o)
	f.must(err)
	if !res.Release.InterimAttestation() {
		t.Fatal("no interim rule before the fork")
	}
	fork := forkOf(t)
	fork.release(2, func(r *Manifest) { r.Security = true })
	fork.publish(0, 1)
	f.must(f.follow(fork.rootFile(1), o))
	res, err = f.checkAt(fork, o)
	f.must(err)
	if v := res.Release; v.InterimAttestation() || v.IndependentPasses([][]byte{pass(t, box, v)}, nil) != 0 {
		t.Fatal("the project's test box vouched for the fork")
	}
	f.must(f.follow(f.rootFile(1), o))
	res, err = f.check(o)
	f.must(err)
	if v := res.Release; v.InterimAttestation() || v.IndependentPasses([][]byte{pass(t, box, v)}, nil) != 0 {
		t.Fatal("switching back revived the interim rule")
	}
}

// Security C7, B4: a fork's root never arrives through Check. A root that
// does not chain from the trusted one (signed by its threshold) is refused
// and changes nothing.
func TestOSS9CheckRefusesAnUnchainedRoot(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	fork := forkOf(t, 2)
	f.must(fork.repo.Rotate(metadata.TIMESTAMP, nil, nil, 0))
	f.must(fork.repo.Sign("root", fork.root[0]))
	f.must(fork.repo.Sign("root", fork.root[1]))
	f.must(fork.repo.publishRoot())
	f.must(os.WriteFile(filepath.Join(f.repo.Dir, "metadata", "2.root.json"), fork.rootFile(2), 0o644))
	before := storeFile(t, f, "root.json")
	if _, err := f.check(Options{}); !errors.Is(err, ErrSignatures) {
		t.Fatalf("an unchained root: %v", err)
	}
	if !bytes.Equal(before, storeFile(t, f, "root.json")) {
		t.Fatal("an unchained root was saved")
	}
}

// A release checked under one root never stages under another, even when
// both chains have the same root and targets versions (Stage compares the
// root itself, not its version).
func TestOSS9ReleaseFromTheOldChainNeverStages(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	f.must(err)
	old := res.Release
	fork := forkOf(t, 2)
	f.must(f.follow(fork.rootFile(1), Options{}))
	if _, err := f.checkAt(fork, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Stage(old); !errors.Is(err, ErrTrustMoved) {
		t.Fatalf("a release from the old chain staged: %v", err)
	}
}

// Security C4: under the store lock, the switch writes the fork's keys to
// seen_keys and the sticky interim flag, then the root, then clears the
// saved timestamp and snapshot, then drops any staged release. A crash at
// any step fails closed: before the root is written the box is wholly on
// the old chain; after it, nothing from the old chain stages or commits,
// and the next store operation finishes the switch.
func TestOSS9FollowIsCrashSafe(t *testing.T) {
	for _, step := range followSteps {
		t.Run(step, func(t *testing.T) {
			f := newFixture(t)
			f.release(2, nil)
			f.publish(0, 1)
			res, err := f.check(Options{})
			f.must(err)
			old := res.Release
			f.must(f.store.Stage(old))
			fork := forkOf(t, 3)
			crashAt = step
			defer func() { crashAt = "" }()
			if err := f.follow(fork.rootFile(1), Options{}); !errors.Is(err, errCrash) {
				t.Fatalf("no crash at %s: %v", step, err)
			}
			crashAt = ""
			switched := !bytes.Equal(storeFile(t, f, "root.json"), f.rootFile(1))
			// Everything the switch wrote before the root only narrows.
			if storeFile(t, f, outsideFile) == nil && step != followSteps[0] && step != followSteps[1] {
				t.Fatal("the interim flag was not written before the root")
			}
			if switched {
				if err := f.store.CommitStaged(2); err == nil {
					t.Fatal("the old chain's staged release committed after the root was written")
				}
				if err := f.store.Stage(old); err == nil {
					t.Fatal("a release from the old chain staged after the root was written")
				}
				res, err := f.checkAt(fork, Options{})
				if err != nil || res.Release == nil || res.Release.Version() != "3" {
					t.Fatal("the switch did not finish:", res.Release, err)
				}
				if mustV(f.store.Following()).Name != "Acme" {
					t.Fatal("the finished switch lost the fork's name")
				}
				for _, n := range []string{"staged.json", followFile} {
					if storeFile(t, f, n) != nil {
						t.Fatalf("%s left after the switch finished", n)
					}
				}
				return
			}
			if res, err := f.check(Options{}); err != nil || res.Release == nil || res.Release.Version() != "2" {
				t.Fatal("before the root was written the old chain must stand:", res.Release, err)
			}
			if _, ok, _ := f.store.Staged(); !ok {
				t.Fatal("a crash before the root dropped the staged release")
			}
			if storeFile(t, f, followFile) != nil || mustV(f.store.Following()).Name != "" {
				t.Fatal("an unfinished switch's marker or source was left")
			}
		})
	}
}

var errCrash = errors.New("crash injected")

// crashAt names the step before which the switch fails, as a crash there.
var crashAt string

func init() {
	followFault = func(s string) error {
		if s == crashAt {
			return errCrash
		}
		return nil
	}
}

// edit replaces the one occurrence of old in b.
func edit(t *testing.T, b []byte, old, new string) []byte {
	t.Helper()
	if n := bytes.Count(b, []byte(old)); n != 1 {
		t.Fatalf("%q occurs %d times", old, n)
	}
	return bytes.Replace(b, []byte(old), []byte(new), 1)
}
