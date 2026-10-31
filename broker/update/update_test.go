package update

// REQ: UPD-2, UPD-8, UPD-1a

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// t0 is years before the real clock, so a check that read the real clock
// instead of Options.Now would see every fixture expired.
var t0 = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

// fixture is a repository with 2-of-3 root and targets keys, plus online
// snapshot and timestamp keys, and a box that has release 1 installed.
type fixture struct {
	t         *testing.T
	dir       string
	repo      Repo
	root, tgt []ed25519.PrivateKey
	snap, ts  ed25519.PrivateKey
	store     *Store
	now       time.Time
	files     map[string]string
	rootHash  string
	// att are the box's allow-listed attestors (Options.Attestors).
	att []ed25519.PrivateKey
}

// attestors is the fixture box's allow-list, plus extra keys.
func (f *fixture) attestors(extra ...ed25519.PrivateKey) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, k := range append(append([]ed25519.PrivateKey(nil), f.att...), extra...) {
		out = append(out, k.Public().(ed25519.PublicKey))
	}
	return out
}

func genKeys(t *testing.T, dir, prefix string, n int) ([]ed25519.PrivateKey, []ed25519.PublicKey) {
	var privs []ed25519.PrivateKey
	var pubs []ed25519.PublicKey
	for i := 0; i < n; i++ {
		base := filepath.Join(dir, fmt.Sprintf("%s%d", prefix, i))
		pub, err := Keygen(base)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := LoadPrivateKey(base + ".key")
		if err != nil {
			t.Fatal(err)
		}
		privs, pubs = append(privs, priv), append(pubs, pub)
	}
	return privs, pubs
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	kdir := filepath.Join(dir, "keys")
	os.Mkdir(kdir, 0o700)
	f := &fixture{t: t, dir: dir, now: t0, rootHash: strings.Repeat("ab", 32)}
	var rp, tp, sp, tsp []ed25519.PublicKey
	f.root, rp = genKeys(t, kdir, "root", 3)
	f.tgt, tp = genKeys(t, kdir, "targets", 3)
	s, sp := genKeys(t, kdir, "snapshot", 1)
	ts, tsp := genKeys(t, kdir, "timestamp", 1)
	f.snap, f.ts = s[0], ts[0]
	f.att, _ = genKeys(t, kdir, "attestor", 2)
	r, err := Init(filepath.Join(dir, "repo"), RootConfig{
		Root: rp, Targets: tp, Snapshot: sp, Timestamp: tsp, RootThreshold: 2, TargetsThreshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Now = func() time.Time { return f.now }
	f.repo = r
	f.must(r.Sign("root", f.root[0]))
	f.must(r.Sign("root", f.root[1]))
	f.must(r.Sign("targets", f.tgt[0]))
	f.must(r.Sign("targets", f.tgt[1]))
	f.must(r.Publish(f.snap, f.ts))
	rootBytes, err := os.ReadFile(filepath.Join(r.Dir, "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.store, err = InitStore(filepath.Join(dir, "box"), rootBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) must(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}

// release stages release v with a boot entry, kernel and /usr image.
func (f *fixture) release(v int64, mod func(*Manifest)) Manifest {
	f.t.Helper()
	files := map[string]string{}
	rel := Manifest{Version: v, Channel: ChannelStable, UsrRootHash: f.rootHash}
	for _, name := range []string{"entry.conf", "vmlinuz", "usr.img"} {
		p := fmt.Sprintf("host-image/%d/%s", v, name)
		local := filepath.Join(f.dir, fmt.Sprintf("%d-%s", v, name))
		f.must(os.WriteFile(local, []byte(fmt.Sprintf("%s of release %d", name, v)), 0o644))
		files[p] = local
		rel.Files = append(rel.Files, p)
	}
	if mod != nil {
		mod(&rel)
	}
	f.must(f.repo.AddRelease(rel, files))
	return rel
}

// publish signs staged targets with the given targets keys and publishes.
func (f *fixture) publish(signers ...int) {
	f.t.Helper()
	for _, i := range signers {
		f.must(f.repo.Sign("targets", f.tgt[i]))
	}
	f.must(f.repo.Publish(f.snap, f.ts))
}

func (f *fixture) check(o Options) (Result, error) {
	if o.Now == nil {
		o.Now = func() time.Time { return f.now }
	}
	if o.Attestors == nil {
		o.Attestors = f.attestors()
	}
	return f.store.Check(DirSource(f.repo.Dir), o)
}

func TestThresholdSignedReleaseVerifies(t *testing.T) {
	f := newFixture(t)
	rel := f.release(2, nil)
	f.publish(0, 2)
	res, err := f.check(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Release == nil {
		t.Fatal("no release offered")
	}
	got := mustV(res.Release.Manifest())
	if got.Version != 2 || got.UsrRootHash != rel.UsrRootHash || !res.Release.Fresh() {
		t.Fatalf("got %+v fresh=%v", got, res.Release.Fresh())
	}
	// UPD-1a: the root hash and every boot file come as one verified unit.
	if len(mustV(res.Release.Files())) != 3 {
		t.Fatalf("files %v", mustV(res.Release.Files()))
	}
	dst := filepath.Join(t.TempDir(), "entry.conf")
	if err := res.Release.Fetch(DirSource(f.repo.Dir), "host-image/2/entry.conf", dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "entry.conf of release 2" {
		t.Fatalf("fetched %q", b)
	}
	f.must(f.store.Commit(res.Release))
	if in, _ := f.store.Installed(); in.Version != 2 || in.UnconfirmedFreshness {
		t.Fatalf("installed %+v", in)
	}
	// Nothing newer now.
	res, err = f.check(Options{})
	if err != nil || res.Release != nil {
		t.Fatalf("after install: %v %v", res.Release, err)
	}
}

func TestTamperedTargetFileIsNotFetched(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	if err != nil || res.Release == nil {
		t.Fatal(res, err)
	}
	var kernel File
	for _, fl := range mustV(res.Release.Files()) {
		if fl.Path == "host-image/2/vmlinuz" {
			kernel = fl
		}
	}
	stored := filepath.Join(f.repo.Dir, filepath.FromSlash(targetFile(kernel.Path, kernel.SHA256)))
	f.must(os.WriteFile(stored, []byte("vmlinuz of release 9"), 0o644))
	dst := filepath.Join(t.TempDir(), "vmlinuz")
	if err := res.Release.Fetch(DirSource(f.repo.Dir), "host-image/2/vmlinuz", dst); !errors.Is(err, ErrBadRepository) {
		t.Fatalf("tampered kernel: %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("tampered bytes reached the destination")
	}
	if err := res.Release.Fetch(DirSource(f.repo.Dir), "host-image/3/vmlinuz", dst); err == nil {
		t.Fatal("fetched a file the release does not name")
	}
}

// forgeTargets publishes staged targets bypassing Publish's threshold
// check, as a thief holding one targets key plus the online keys could.
func (f *fixture) forgeTargets(signers ...int) {
	f.t.Helper()
	m, err := metadata.Targets().FromFile(filepath.Join(f.repo.Dir, "staged", "targets.json"))
	f.must(err)
	m.ClearSignatures()
	for _, i := range signers {
		s, err := Signer(f.tgt[i])
		f.must(err)
		_, err = m.Sign(s)
		f.must(err)
	}
	f.must(writeMeta(filepath.Join(f.repo.Dir, "metadata", fmt.Sprintf("%d.targets.json", m.Signed.Version)), m))
	os.Remove(filepath.Join(f.repo.Dir, "staged", "targets.json"))
	f.must(f.repo.Refresh(f.snap, f.ts))
}

func TestTooFewSignaturesRefusedOnlineAndOffline(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.must(f.repo.Sign("targets", f.tgt[0]))
	if err := f.repo.Publish(f.snap, f.ts); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("Publish with 1 of 2: %v", err)
	}
	f.forgeTargets(0)
	for _, off := range []bool{false, true} {
		if _, err := f.check(Options{Offline: off}); !errors.Is(err, ErrSignatures) {
			t.Fatalf("offline=%v: %v", off, err)
		}
	}
	// The same key twice is still one key.
	f.release(3, nil)
	m, _ := metadata.Targets().FromFile(filepath.Join(f.repo.Dir, "staged", "targets.json"))
	s, _ := Signer(f.tgt[0])
	m.Sign(s)
	m.Sign(s)
	f.must(writeMeta(filepath.Join(f.repo.Dir, "staged", "targets.json"), m))
	if err := f.repo.Publish(f.snap, f.ts); err == nil {
		t.Fatal("published with one key signing twice")
	}
}

func TestSigningRefusesForeignKeys(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	if err := f.repo.Sign("targets", f.root[0]); err == nil {
		t.Fatal("a root key signed targets")
	}
	if err := f.repo.Sign("snapshot", f.snap); err == nil {
		t.Fatal("snapshot signed as an offline role")
	}
	f.must(f.repo.Sign("targets", f.tgt[0]))
	if err := f.repo.Sign("targets", f.tgt[0]); err == nil {
		t.Fatal("same key signed twice")
	}
	if err := f.repo.Refresh(f.ts, f.ts); err == nil {
		t.Fatal("timestamp key signed the snapshot")
	}
}

func TestOlderReleaseRefusedOfflineToo(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.release(3, nil)
	f.publish(0, 1)
	in, _ := f.store.Installed()
	in.Version = 5
	f.must(f.store.writeInstalled(in))
	for _, off := range []bool{false, true} {
		res, err := f.check(Options{Offline: off})
		if err != nil || res.Release != nil {
			t.Fatalf("offline=%v: offered %v, %v", off, res.Release, err)
		}
	}
	if err := f.repo.AddRelease(Manifest{Version: 3, Channel: ChannelStable, UsrRootHash: f.rootHash, Files: []string{"host-image/3/entry.conf"}}, nil); err == nil {
		t.Fatal("re-added release 3")
	}
}

func TestMetadataRollbackRefusedOfflineToo(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	old := t.TempDir()
	copyTree(t, f.repo.Dir, old)
	f.release(3, nil)
	f.publish(0, 1)
	if _, err := f.check(Options{}); err != nil {
		t.Fatal(err)
	}
	// A mirror or drive replaying the older repository.
	for _, off := range []bool{false, true} {
		_, err := f.store.Check(DirSource(old), Options{Offline: off, Now: func() time.Time { return f.now }})
		if !errors.Is(err, ErrRollback) {
			t.Fatalf("offline=%v replay: %v", off, err)
		}
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

func TestExpiredTimestampOnlineOfflineInstallsWithNotice(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	f.now = t0.Add(48 * time.Hour) // the mirror stopped refreshing
	if _, err := f.check(Options{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("online with a frozen mirror: %v", err)
	}
	f.now = t0.Add(400 * 24 * time.Hour) // even root and targets expired
	res, err := f.check(Options{Offline: true})
	if err != nil || res.Release == nil {
		t.Fatalf("offline drive: %v %v", res.Release, err)
	}
	if res.Release.Fresh() {
		t.Fatal("an offline release claims freshness")
	}
	f.must(f.store.Commit(res.Release))
	if in, _ := f.store.Installed(); !in.UnconfirmedFreshness {
		t.Fatal("offline install did not leave the freshness check pending")
	}
	if !strings.Contains(OfflineNotice, "without a freshness check") {
		t.Fatal("notice text")
	}
	// Next online contact with a live repository confirms it.
	f.now = t0.Add(49 * time.Hour)
	f.must(f.repo.Refresh(f.snap, f.ts))
	res, err = f.check(Options{})
	if err != nil || !res.FreshnessConfirmed {
		t.Fatalf("online after offline install: %+v %v", res, err)
	}
	if in, _ := f.store.Installed(); in.UnconfirmedFreshness {
		t.Fatal("freshness still pending after an online check")
	}
}

func TestKeyRotationAndRevocationWithoutReinstall(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	if _, err := f.check(Options{}); err != nil {
		t.Fatal(err)
	}
	kdir := t.TempDir()
	newTgt, newPub := genKeys(t, kdir, "targets-new", 1)
	newRoot, newRootPub := genKeys(t, kdir, "root-new", 1)
	// Revoke targets key 0 (say it was lost) and add a new one; replace
	// root key 0 too. Root v2 needs 2 of the old root keys and 2 of the new.
	f.must(f.repo.Rotate("targets", newPub, []ed25519.PublicKey{f.tgt[0].Public().(ed25519.PublicKey)}, 0))
	f.must(f.repo.Rotate("root", newRootPub, []ed25519.PublicKey{f.root[0].Public().(ed25519.PublicKey)}, 0))
	f.must(f.repo.Sign("root", f.root[0])) // old key, counts for the old threshold only
	f.must(f.repo.Sign("root", newRoot[0]))
	if err := f.repo.Publish(f.snap, f.ts); err == nil {
		t.Fatal("root v2 published with 1 of the new root keys")
	}
	f.must(f.repo.Sign("root", f.root[1]))
	f.must(f.repo.Publish(f.snap, f.ts))

	// The revoked key no longer counts toward a release.
	f.release(3, nil)
	f.must(f.repo.Sign("targets", f.tgt[1]))
	if err := f.repo.Sign("targets", f.tgt[0]); err == nil {
		t.Fatal("revoked key signed targets")
	}
	f.forgeTargets(0, 1)
	if _, err := f.check(Options{}); !errors.Is(err, ErrSignatures) {
		t.Fatalf("release signed with a revoked key: %v", err)
	}
	// The new key does, and the box follows the rotation on its own.
	f.release(4, nil)
	f.tgt = append(f.tgt, newTgt[0])
	f.publish(1, 3)
	res, err := f.check(Options{})
	if err != nil || res.Release == nil || mustV(res.Release.Manifest()).Version != 4 {
		t.Fatalf("after rotation: %v %v", res.Release, err)
	}
	b, _ := os.ReadFile(filepath.Join(f.store.Dir, "root.json"))
	if r, _ := metadata.Root().FromBytes(b); r.Signed.Version != 2 {
		t.Fatal("box did not save the rotated root")
	}
}

func TestRotationWithoutOldThresholdRefused(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	kdir := t.TempDir()
	evil, evilPub := genKeys(t, kdir, "evil", 2)
	// A thief with one root key tries to install their own root keys.
	f.must(f.repo.Rotate("root", evilPub, []ed25519.PublicKey{f.root[1].Public().(ed25519.PublicKey), f.root[2].Public().(ed25519.PublicKey)}, 0))
	m, _ := metadata.Root().FromFile(filepath.Join(f.repo.Dir, "staged", "root.json"))
	for _, k := range []ed25519.PrivateKey{f.root[0], evil[0], evil[1]} {
		s, _ := Signer(k)
		m.Sign(s)
	}
	f.must(writeMeta(filepath.Join(f.repo.Dir, "metadata", "2.root.json"), m))
	for _, off := range []bool{false, true} {
		if _, err := f.check(Options{Offline: off}); !errors.Is(err, ErrSignatures) {
			t.Fatalf("offline=%v: %v", off, err)
		}
	}
}

func TestWeakThresholdRefused(t *testing.T) {
	f := newFixture(t)
	f.must(f.repo.Rotate("targets", nil, nil, 1))
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.release(2, nil)
	f.publish(0)
	if _, err := f.check(Options{}); !errors.Is(err, ErrWeakThreshold) {
		t.Fatalf("targets threshold 1: %v", err)
	}
	// A configured floor below 2 counts as 2: it cannot be lowered.
	for _, min := range []int{-1, 0, 1} {
		if _, err := f.check(Options{MinThreshold: min}); !errors.Is(err, ErrWeakThreshold) {
			t.Fatalf("floor %d: %v", min, err)
		}
	}
}

func TestManifestMustBindSignedFiles(t *testing.T) {
	f := newFixture(t)
	// The tool refuses a release that names a file it was not given.
	err := f.repo.AddRelease(Manifest{Version: 2, Channel: ChannelStable, UsrRootHash: f.rootHash, Files: []string{"host-image/2/entry.conf"}}, nil)
	if err == nil {
		t.Fatal("added a release naming an unsigned file")
	}
	for _, bad := range []Manifest{
		{Version: 2, Channel: ChannelStable, UsrRootHash: "ABC", Files: []string{"host-image/x"}},
		{Version: 2, Channel: "nightly", UsrRootHash: f.rootHash, Files: []string{"host-image/x"}},
		{Version: 2, Channel: ChannelStable, UsrRootHash: f.rootHash, Files: []string{"../etc/passwd"}},
		{Version: 2, Channel: ChannelStable, UsrRootHash: f.rootHash, Files: []string{"boot/2/entry.conf"}},
		{Version: 2, Channel: ChannelStable, UsrRootHash: f.rootHash},
	} {
		if bad.Check() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	// A manifest naming a file that is not a signed target is refused by
	// the box even if signed: the release would not activate as one unit.
	f.release(2, nil)
	m, _ := metadata.Targets().FromFile(filepath.Join(f.repo.Dir, "staged", "targets.json"))
	delete(m.Signed.Targets, "host-image/2/vmlinuz")
	f.must(writeMeta(filepath.Join(f.repo.Dir, "staged", "targets.json"), m))
	f.publish(0, 1)
	if _, err := f.check(Options{}); !errors.Is(err, ErrBadRepository) {
		t.Fatalf("manifest naming an unsigned file: %v", err)
	}
}

func TestFastReleasesOnlyOnFastChannel(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.release(3, func(r *Manifest) { r.Channel = ChannelFast })
	f.publish(0, 1)
	res, err := f.check(Options{})
	if err != nil || mustV(res.Release.Manifest()).Version != 2 {
		t.Fatalf("stable box: %v %v", res.Release, err)
	}
	res, err = f.check(Options{Channel: ChannelFast})
	if err != nil || mustV(res.Release.Manifest()).Version != 3 {
		t.Fatalf("fast box: %v %v", res.Release, err)
	}
	if _, err := f.check(Options{Channel: "pinned"}); err == nil {
		t.Fatal("pinned box checked for automatic updates")
	}
}

func TestCommitOnlyMovesForward(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, _ := f.check(Options{})
	f.must(f.store.Commit(res.Release))
	if err := f.store.Commit(res.Release); !errors.Is(err, ErrRollback) {
		t.Fatalf("second commit: %v", err)
	}
}

func TestDirSourceRefusesEscapes(t *testing.T) {
	for _, n := range []string{"../x", "/etc/passwd", "metadata/../../x", "a//b", ".hidden"} {
		if _, err := DirSource(t.TempDir()).Open(n); err == nil || os.IsNotExist(err) {
			t.Fatalf("%q: %v", n, err)
		}
	}
}

// mustV unwraps a sealed Verified's accessor in tests.
func mustV[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// Every method refuses a Verified that Check did not make.
func TestUnsealedCheckedIsRefused(t *testing.T) {
	f := newFixture(t)
	for _, c := range []*Verified{{}, nil, {release: Manifest{Version: 9}, files: map[string]File{"host-image/x": {Path: "host-image/x"}}}} {
		if _, err := c.Manifest(); !errors.Is(err, ErrNotChecked) {
			t.Fatalf("Manifest: %v", err)
		}
		if _, err := c.ManifestFile(); !errors.Is(err, ErrNotChecked) {
			t.Fatalf("ManifestFile: %v", err)
		}
		if _, err := c.Files(); !errors.Is(err, ErrNotChecked) {
			t.Fatalf("Files: %v", err)
		}
		if err := c.Fetch(DirSource(f.repo.Dir), "host-image/x", filepath.Join(t.TempDir(), "x")); !errors.Is(err, ErrNotChecked) {
			t.Fatalf("Fetch: %v", err)
		}
		if err := c.SecurityAutoStage(nil, nil); !errors.Is(err, ErrNotChecked) {
			t.Fatalf("SecurityAutoStage: %v", err)
		}
		if _, err := Attest(newKey(t), c, Statement{Result: ResultPass}); !errors.Is(err, ErrNotChecked) {
			t.Fatalf("Attest: %v", err)
		}
		if err := f.store.Commit(c); !errors.Is(err, ErrNotChecked) {
			t.Fatalf("Commit: %v", err)
		}
		if c.Fresh() || c.IndependentPasses(nil, nil) != 0 || c.MaintainerPasses(nil, nil) != 0 || c.WithAttestations(nil, nil) != nil {
			t.Fatal("unsealed release reported fresh, attested or verified")
		}
		if c.OK() || c.Security() || c.Version() != "" || c.Images() != nil {
			t.Fatal("unsealed release passed the pipeline accessors")
		}
	}
	if in, _ := f.store.Installed(); in.Version != 1 {
		t.Fatalf("installed moved to %d", in.Version)
	}
}

// Every root in a rotation chain meets the floor, not only the last.
func TestWeakIntermediateRootRefused(t *testing.T) {
	f := newFixture(t)
	f.must(f.repo.Rotate("targets", nil, nil, 1)) // root v2: targets threshold 1
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.must(f.repo.Publish(f.snap, f.ts))
	f.must(f.repo.Rotate("targets", nil, nil, 2)) // root v3 restores 2
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.release(2, nil)
	f.publish(0, 1)
	for _, off := range []bool{false, true} {
		if _, err := f.check(Options{Offline: off}); !errors.Is(err, ErrWeakThreshold) {
			t.Fatalf("offline=%v: root v2 with threshold 1 accepted: %v", off, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(f.store.Dir, "root.json"))
	if r, _ := metadata.Root().FromBytes(b); r.Signed.Version != 1 {
		t.Fatalf("box saved root v%d past a weak one", r.Signed.Version)
	}
}

// A link planted at a store, lock or repository file is refused, not
// followed (REV-CHK-links, #3942): the box reads no file a link names.
func TestPlantedLinksAreRefused(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	plant := func(p string) {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		real := filepath.Join(f.dir, filepath.Base(p)+".real")
		if err := os.WriteFile(real, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, p); err != nil {
			t.Fatal(err)
		}
	}
	installed := f.store.p("installed.json")
	plant(installed)
	if _, err := f.store.Installed(); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("installed.json as a link: %v, want ELOOP", err)
	}
	if _, err := f.check(Options{}); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("check over a linked installed.json: %v, want ELOOP", err)
	}
	g := newFixture(t)
	g.release(2, nil)
	g.publish(0, 1)
	if err := os.Symlink(filepath.Join(g.dir, "elsewhere"), g.store.p(".lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.check(Options{}); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("check with .lock a link: %v, want ELOOP", err)
	}
	if _, err := os.Lstat(filepath.Join(g.dir, "elsewhere")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the lock's link target was created: %v", err)
	}
	h := newFixture(t)
	h.release(2, nil)
	h.publish(0, 1)
	plant(filepath.Join(h.repo.Dir, "metadata", "timestamp.json"))
	if _, err := DirSource(h.repo.Dir).Open("metadata/timestamp.json"); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("repository file as a link: %v, want ELOOP", err)
	}
	if _, err := h.check(Options{}); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("check over a linked repository timestamp: %v, want ELOOP", err)
	}
}

// A saved timestamp or snapshot that cannot be read fails the check, so a
// link planted there cannot drop the rollback floor (REV-CHK-links-update-l,
// #3990).
func TestSavedMetadataReadFailsClosed(t *testing.T) {
	for _, name := range []string{"timestamp.json", "snapshot.json"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.release(2, nil)
			f.publish(0, 1)
			if _, err := f.check(Options{}); err != nil {
				t.Fatal(err)
			}
			p := f.store.p(name)
			b, err := os.ReadFile(p)
			f.must(err)
			real := filepath.Join(f.dir, name+".real")
			f.must(os.WriteFile(real, b, 0o600))
			f.must(os.Remove(p))
			f.must(os.Symlink(real, p))
			if _, err := f.check(Options{}); !errors.Is(err, syscall.ELOOP) {
				t.Fatalf("check over a linked saved %s: %v, want ELOOP", name, err)
			}
			// A directory there is not a missing file either.
			f.must(os.Remove(p))
			f.must(os.Mkdir(p, 0o700))
			if _, err := f.check(Options{}); err == nil {
				t.Fatalf("check over a saved %s that is a directory passed", name)
			}
			// Only a missing file reads as none saved.
			f.must(os.Remove(p))
			if _, err := f.check(Options{}); err != nil {
				t.Fatalf("check with no saved %s: %v", name, err)
			}
		})
	}
}

// The store directory and every parent must be a real directory that only
// root or the box's own uid can change; a sticky parent may be writable by
// all, the store itself may not (REV-CHK-links-update-l, #3990).
func TestStoreParentChainIsOwnOnly(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	box := f.store.Dir
	parent := filepath.Dir(box)
	calls := map[string]func() error{
		"Check":     func() error { _, err := f.check(Options{}); return err },
		"Installed": func() error { _, err := f.store.Installed(); return err },
		"Staged":    func() error { _, _, err := f.store.Staged(); return err },
		"Following": func() error { _, err := f.store.Following(); return err },
		"policy":    func() error { _, err := f.store.policy(); return err },
	}
	refused := func(what string) {
		t.Helper()
		for name, call := range calls {
			if err := call(); err == nil || !strings.Contains(err.Error(), "update store:") {
				t.Errorf("%s: %s: %v, want refused", what, name, err)
			}
		}
	}
	allowed := func(what string) {
		t.Helper()
		for name, call := range calls {
			if err := call(); err != nil {
				t.Errorf("%s: %s: %v", what, name, err)
			}
		}
	}
	allowed("own 0700 chain")

	f.must(os.Chmod(parent, 0o777))
	refused("a parent writable by all")
	root, err := readFile(f.store.p("root.json"))
	f.must(err)
	if _, err := InitStore(filepath.Join(parent, "box2"), root, 1); err == nil || !strings.Contains(err.Error(), "update store:") {
		t.Errorf("InitStore under a parent writable by all: %v, want refused", err)
	}
	f.must(os.Chmod(parent, 0o770))
	refused("a parent writable by its group")
	f.must(os.Chmod(parent, os.ModeSticky|0o777))
	allowed("a sticky parent writable by all")
	f.must(os.Chmod(parent, 0o700))

	f.must(os.Chmod(box, os.ModeSticky|0o777))
	refused("the store itself writable by all, sticky")
	f.must(os.Chmod(box, 0o700))

	// A link anywhere in the chain is refused, not only as the last
	// component: here the store is reached through a linked parent.
	linked := filepath.Join(f.dir, "linked")
	f.must(os.Symlink(parent, linked))
	f.store.Dir = filepath.Join(linked, filepath.Base(box))
	refused("a linked parent")
	f.store.Dir = box
	allowed("the chain restored")

	if os.Geteuid() == 0 {
		// Only root can give a directory to another uid.
		f.must(os.Chown(parent, 65534, 65534))
		refused("a parent owned by another uid")
		f.must(os.Chown(parent, 0, 0))
	}
}
