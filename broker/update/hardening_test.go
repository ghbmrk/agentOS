package update

// REQ: UPD-2, UPD-8, CHG-3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// #34's TestOnlyImages and TestStrictMetadata, ported: a manifest names
// files only under the image namespaces, and decodes strictly.
func TestManifestOnlyImagesAndStrict(t *testing.T) {
	h := strings.Repeat("ab", 32)
	base := `"version":2,"channel":"stable","usr_root_hash":"` + h + `"`
	if _, err := parseManifest([]byte(`{` + base + `,"files":["host-image/a"]}`)); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, m := range []string{
		`{` + base + `,"files":["config/x"]}`,
		`{` + base + `,"files":["host-image/../grants/x"]}`,
		`{` + base + `,"files":["host-image/a","host-image/a"]}`,
		`{` + base + `,"files":["host-image/a"],"grants":["x"]}`,
		`{` + base + `,"files":["host-image/a"]}}`,
		`{` + base + `,"files":["host-image/a"]}]`,
		`{` + base + `,"files":["host-image/a"]}{}`,
		`{` + base + `,"version":3,"files":["host-image/a"]}`,
		`{` + base + `,"Version":3,"files":["host-image/a"]}`,
		`{` + base + `,"security":false,"Security":true,"files":["host-image/a"]}`,
		`{` + base + `,"security":false,"security":true,"files":["host-image/a"]}`,
		`{` + base + `,"Files":["host-image/a"]}`,
		`[` + base + `]`,
	} {
		if _, err := parseManifest([]byte(m)); err == nil {
			t.Fatalf("accepted %s", m)
		}
	}
}

// #34's TestRootKeysCountOnce, ported: one key listed under two IDs is one
// signer, so it cannot meet a threshold of 2.
func TestOneKeyUnderTwoIDsIsOneSigner(t *testing.T) {
	f := newFixture(t)
	f.must(f.repo.Rotate("targets", nil, nil, 0))
	name := filepath.Join(f.repo.Dir, "staged", "root.json")
	root, err := metadata.Root().FromFile(name)
	f.must(err)
	id := mustV(KeyID(f.tgt[0].Public()))
	alias := strings.Repeat("f", 64)
	root.Signed.Keys[alias] = root.Signed.Keys[id]
	tr := root.Signed.Roles[metadata.TARGETS]
	tr.KeyIDs = append(tr.KeyIDs, alias)
	f.must(writeMeta(name, root))
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.release(2, nil)
	// One holder signs and copies the signature under the alias.
	m, err := metadata.Targets().FromFile(filepath.Join(f.repo.Dir, "staged", "targets.json"))
	f.must(err)
	s, _ := Signer(f.tgt[0])
	sig, err := m.Sign(s)
	f.must(err)
	m.Signatures = append(m.Signatures, metadata.Signature{KeyID: alias, Signature: sig.Signature})
	f.must(writeMeta(filepath.Join(f.repo.Dir, "staged", "targets.json"), m))
	f.must(f.repo.publishRoot())
	f.must(f.repo.Refresh(f.snap, f.ts))
	f.must(writeMeta(filepath.Join(f.repo.Dir, "metadata", fmt.Sprintf("%d.targets.json", m.Signed.Version)), m))
	os.Remove(filepath.Join(f.repo.Dir, "staged", "targets.json"))
	f.must(f.repo.Refresh(f.snap, f.ts))
	for _, off := range []bool{false, true} {
		res, err := f.check(Options{Offline: off})
		if !errors.Is(err, ErrSignatures) {
			t.Fatalf("offline=%v: one key under two IDs met threshold 2: %v %v", off, res.Release, err)
		}
	}
}

// GHSA-fphv-w9fq-2525: a role with threshold 0 is refused, for the online
// roles too.
func TestZeroThresholdRefused(t *testing.T) {
	for _, role := range []string{metadata.SNAPSHOT, metadata.TIMESTAMP} {
		t.Run(role, func(t *testing.T) {
			f := newFixture(t)
			f.must(f.repo.Rotate(role, nil, nil, 0))
			name := filepath.Join(f.repo.Dir, "staged", "root.json")
			root, err := metadata.Root().FromFile(name)
			f.must(err)
			root.Signed.Roles[role].Threshold = 0
			f.must(writeMeta(name, root))
			f.must(f.repo.Sign("root", f.root[0]))
			f.must(f.repo.Sign("root", f.root[1]))
			f.must(f.repo.publishRoot()) // the tool's Refresh would refuse; a thief's need not
			for _, off := range []bool{false, true} {
				if _, err := f.check(Options{Offline: off}); !errors.Is(err, ErrSignatures) || !strings.Contains(err.Error(), "threshold (0)") {
					t.Fatalf("offline=%v: %s threshold 0: %v", off, role, err)
				}
			}
		})
	}
}

// Mix-and-match: metadata from different repository states, each validly
// signed, does not combine into a release.
func TestMixAndMatchRefused(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	md := filepath.Join(f.repo.Dir, "metadata")
	oldTargets, _ := os.ReadFile(filepath.Join(md, "2.targets.json"))
	oldSnap, _ := os.ReadFile(filepath.Join(md, "2.snapshot.json"))
	f.release(3, nil)
	f.publish(0, 1)
	for name, old := range map[string][]byte{"3.targets.json": oldTargets, "3.snapshot.json": oldSnap} {
		g := filepath.Join(t.TempDir(), "repo")
		copyTree(t, f.repo.Dir, g)
		f.must(os.WriteFile(filepath.Join(g, "metadata", name), old, 0o644))
		for _, off := range []bool{false, true} {
			if _, err := f.store.Check(DirSource(g), Options{Offline: off, Now: func() time.Time { return f.now }}); !errors.Is(err, ErrBadRepository) {
				t.Fatalf("offline=%v: old %s under the new name: %v", off, name, err)
			}
		}
	}
}

func TestOversizedMetadataRefused(t *testing.T) {
	for _, name := range []string{"timestamp.json", "2.root.json"} {
		f := newFixture(t)
		f.release(2, nil)
		f.publish(0, 1)
		big := append([]byte("{}"), bytes.Repeat([]byte(" "), maxMetadata)...)
		f.must(os.WriteFile(filepath.Join(f.repo.Dir, "metadata", name), big, 0o644))
		if _, err := f.check(Options{Offline: true}); !errors.Is(err, ErrBadRepository) || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("%s over 4 MiB: %v", name, err)
		}
	}
}

// timestampOnly signs a fresh timestamp over the latest snapshot without
// re-signing the snapshot, as a frozen-snapshot mirror would serve.
func (f *fixture) timestampOnly() {
	f.t.Helper()
	sv, sb, err := f.repo.published(metadata.SNAPSHOT)
	f.must(err)
	root, err := f.repo.root()
	f.must(err)
	old, err := metadata.Timestamp().FromFile(filepath.Join(f.repo.Dir, "metadata", "timestamp.json"))
	f.must(err)
	ts := metadata.Timestamp(f.now.Add(TimestampExpiry))
	ts.Signed.Version = old.Signed.Version + 1
	raw, err := hex.DecodeString(Digest(sb))
	f.must(err)
	ts.Signed.Meta["snapshot.json"] = &metadata.MetaFiles{Version: sv, Length: int64(len(sb)), Hashes: metadata.Hashes{"sha256": raw}}
	f.must(signAs(root, metadata.TIMESTAMP, ts, f.ts))
	f.must(writeMeta(filepath.Join(f.repo.Dir, "metadata", "timestamp.json"), ts))
}

// Online, each expired role is refused: snapshot, targets and root, not
// only the timestamp; and a clock far in the future refuses everything.
func TestExpiredRolesRefusedOnline(t *testing.T) {
	day := 24 * time.Hour
	t.Run("snapshot", func(t *testing.T) {
		f := newFixture(t)
		f.release(2, nil)
		f.publish(0, 1)
		f.now = t0.Add(8 * day)
		f.timestampOnly()
		if _, err := f.check(Options{}); !errors.Is(err, ErrExpired) || !strings.Contains(err.Error(), "snapshot") {
			t.Fatalf("expired snapshot: %v", err)
		}
	})
	t.Run("targets", func(t *testing.T) {
		f := newFixture(t)
		f.release(2, nil)
		f.publish(0, 1)
		f.now = t0.Add(300 * day) // a new root, so only targets expires
		f.must(f.repo.Rotate("root", nil, nil, 0))
		f.must(f.repo.Sign("root", f.root[0]))
		f.must(f.repo.Sign("root", f.root[1]))
		f.must(f.repo.Publish(f.snap, f.ts))
		f.now = t0.Add(366 * day)
		f.must(f.repo.Refresh(f.snap, f.ts))
		if _, err := f.check(Options{}); !errors.Is(err, ErrExpired) || !strings.Contains(err.Error(), "targets") {
			t.Fatalf("expired targets: %v", err)
		}
	})
	t.Run("root", func(t *testing.T) {
		f := newFixture(t)
		// Init dates root v1 by the real clock; root v2 is dated t0.
		f.must(f.repo.Rotate("root", nil, nil, 0))
		f.must(f.repo.Sign("root", f.root[0]))
		f.must(f.repo.Sign("root", f.root[1]))
		f.must(f.repo.Publish(f.snap, f.ts))
		f.now = t0.Add(300 * day) // a new targets, so only root expires
		f.release(2, nil)
		f.publish(0, 1)
		f.now = t0.Add(366 * day)
		f.must(f.repo.Refresh(f.snap, f.ts))
		if _, err := f.check(Options{}); !errors.Is(err, ErrExpired) || !strings.Contains(err.Error(), "root") {
			t.Fatalf("expired root: %v", err)
		}
	})
	t.Run("far future clock", func(t *testing.T) {
		f := newFixture(t)
		f.release(2, nil)
		f.publish(0, 1)
		far := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
		if _, err := f.check(Options{Now: func() time.Time { return far }}); !errors.Is(err, ErrExpired) {
			t.Fatalf("year 3000: %v", err)
		}
	})
}

// installOffline installs release 2 from a drive, leaving freshness pending.
func installOffline(t *testing.T) *fixture {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(Options{Offline: true})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	f.must(f.store.Commit(res.Release))
	in, _ := f.store.Installed()
	if !in.UnconfirmedFreshness || in.ManifestPath != "releases/2.json" || in.ManifestSHA256 != mustV(res.Release.ManifestFile()).SHA256 {
		t.Fatalf("installed %+v", in)
	}
	return f
}

func pending(f *fixture) bool {
	in, err := f.store.Installed()
	f.must(err)
	return in.UnconfirmedFreshness
}

// Freshness is confirmed only by fresh targets listing the exact manifest
// installed, and only after the whole check succeeds.
func TestOfflineFreshnessNeedsTheExactManifest(t *testing.T) {
	t.Run("withdrawn", func(t *testing.T) {
		f := installOffline(t)
		m, err := f.repo.stagedTargets()
		f.must(err)
		m.ClearSignatures()
		delete(m.Signed.Targets, ReleasePath(2))
		f.must(writeMeta(filepath.Join(f.repo.Dir, "staged", "targets.json"), m))
		f.publish(0, 1)
		res, err := f.check(Options{})
		if err != nil || res.FreshnessConfirmed || !res.FreshnessFailed || !pending(f) {
			t.Fatalf("withdrawn release: %+v %v", res, err)
		}
		if !strings.Contains(NotConfirmedNotice, "not in the latest signed release list") {
			t.Fatal("notice text")
		}
	})
	t.Run("changed", func(t *testing.T) {
		f := installOffline(t)
		m, err := f.repo.stagedTargets()
		f.must(err)
		other := filepath.Join(t.TempDir(), "m.json")
		f.must(os.WriteFile(other, []byte(`{"version":2}`), 0o644))
		tf, err := f.repo.storeTarget(ReleasePath(2), other)
		f.must(err)
		m.ClearSignatures()
		m.Signed.Targets[ReleasePath(2)] = tf
		f.must(writeMeta(filepath.Join(f.repo.Dir, "staged", "targets.json"), m))
		f.publish(0, 1)
		res, err := f.check(Options{})
		if res.FreshnessConfirmed || !pending(f) {
			t.Fatalf("changed manifest confirmed: %+v %v", res, err)
		}
	})
	t.Run("check fails later", func(t *testing.T) {
		f := installOffline(t)
		f.release(3, nil)
		f.publish(0, 1)
		// Release 3's manifest names a file the mirror does not serve
		// correctly: the check fails after the metadata passed.
		m, _ := metadata.Targets().FromFile(filepath.Join(f.repo.Dir, "metadata", "3.targets.json"))
		man := m.Signed.Targets[ReleasePath(3)]
		f.must(os.WriteFile(filepath.Join(f.repo.Dir, filepath.FromSlash(targetFile(ReleasePath(3), mustV(fileOf(ReleasePath(3), man)).SHA256))), []byte("{}"), 0o644))
		res, err := f.check(Options{})
		if err == nil || res.FreshnessConfirmed || !pending(f) {
			t.Fatalf("failed check confirmed freshness: %+v %v", res, err)
		}
	})
	t.Run("listed", func(t *testing.T) {
		f := installOffline(t)
		f.release(3, nil)
		f.publish(0, 1)
		res, err := f.check(Options{})
		if err != nil || !res.FreshnessConfirmed || res.FreshnessFailed || pending(f) {
			t.Fatalf("listed manifest: %+v %v", res, err)
		}
	})
}

// go-tuf dereferences null map entries while parsing, before any
// signature check, so an unsigned mirror could crash the box with one.
// Every metadata file with a null is refused as malformed.
func TestNullInMetadataRefused(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	md := filepath.Join(f.repo.Dir, "metadata")
	for name, edit := range map[string][2]string{
		"timestamp.json":  {`"snapshot.json": {`, `"snapshot.json": null, "x": {`},
		"2.snapshot.json": {`"targets.json": {`, `"targets.json": null, "x": {`},
		"2.targets.json":  {`"releases/2.json": {`, `"releases/2.json": null, "x": {`},
		"1.root.json":     {`"roles": {`, `"roles": {"x": null, `},
	} {
		g := filepath.Join(t.TempDir(), "repo")
		copyTree(t, f.repo.Dir, g)
		b, err := os.ReadFile(filepath.Join(md, name))
		f.must(err)
		if !bytes.Contains(b, []byte(edit[0])) {
			t.Fatalf("fixture: %s lacks %s", name, edit[0])
		}
		b = bytes.Replace(b, []byte(edit[0]), []byte(edit[1]), 1)
		if name == "1.root.json" {
			name = "2.root.json" // served as a rotation
		}
		f.must(os.WriteFile(filepath.Join(g, "metadata", name), b, 0o644))
		for _, off := range []bool{false, true} {
			if _, err := f.store.Check(DirSource(g), Options{Offline: off, Now: func() time.Time { return f.now }}); !errors.Is(err, ErrBadRepository) {
				t.Fatalf("offline=%v: %s with a null: %v", off, name, err)
			}
		}
	}
}

// go-tuf parses targets (after the snapshot's hash check, before its
// signatures) and dereferences a null entry. A thief holding only the
// online snapshot and timestamp keys could pin such a targets file and
// crash every box that checks; the null guard refuses it first.
func TestOnlineKeysCannotServeNullTargets(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	md := filepath.Join(f.repo.Dir, "metadata")
	b, err := os.ReadFile(filepath.Join(md, "2.targets.json"))
	f.must(err)
	for old, new := range map[string]string{`"version": 2`: `"version": 3`, `"releases/2.json": {`: `"releases/3.json": null, "releases/2.json": {`} {
		if !bytes.Contains(b, []byte(old)) {
			t.Fatalf("fixture: no %s", old)
		}
		b = bytes.Replace(b, []byte(old), []byte(new), 1)
	}
	f.must(os.WriteFile(filepath.Join(md, "3.targets.json"), b, 0o644))
	f.must(f.repo.Refresh(f.snap, f.ts))
	for _, off := range []bool{false, true} {
		if _, err := f.check(Options{Offline: off}); !errors.Is(err, ErrBadRepository) {
			t.Fatalf("offline=%v: %v", off, err)
		}
	}
}

// Security R1: a private key file others can read is refused.
func TestOpenPrivateKeyFileRefused(t *testing.T) {
	base := filepath.Join(t.TempDir(), "k")
	if _, err := Keygen(base); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
		if err := os.Chmod(base+".key", mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(base + ".key"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("mode %v: %v", mode, err)
		}
	}
	os.Chmod(base+".key", 0o400)
	if _, err := LoadPrivateKey(base + ".key"); err != nil {
		t.Fatal(err)
	}
}

// Security lens C2: a security fix followed by an ordinary release is
// still reported, so the newest is treated as carrying the fix.
func TestSecurityFixNotHiddenByNewerRelease(t *testing.T) {
	f := newFixture(t)
	f.release(2, func(r *Manifest) { r.Security = true })
	f.release(3, nil)
	f.release(4, func(r *Manifest) { r.Channel = ChannelFast; r.Security = true })
	f.publish(0, 1)
	res, err := f.check(Options{})
	if err != nil || mustV(res.Release.Manifest()).Version != 3 || res.SecurityFix != 2 {
		t.Fatalf("stable: %+v %v", res, err)
	}
	res, err = f.check(Options{Channel: ChannelFast})
	if err != nil || mustV(res.Release.Manifest()).Version != 4 || res.SecurityFix != 4 {
		t.Fatalf("fast: %+v %v", res, err)
	}
	g := newFixture(t)
	g.release(2, nil)
	g.publish(0, 1)
	if res, _ := g.check(Options{}); res.SecurityFix != 0 {
		t.Fatalf("no security fix, got %d", res.SecurityFix)
	}
}

// Security lens C3: concurrent checks on one store (two mirrors, or the
// updater beside Loop 3) are serialized and all succeed.
func TestConcurrentChecksSerialize(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			st := &Store{Dir: f.store.Dir} // as a second process would open it
			_, err := st.Check(DirSource(f.repo.Dir), Options{Now: func() time.Time { return f.now }})
			errs <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.store.Dir, ".lock")); err != nil {
		t.Fatal(err)
	}
}

type panicSource struct{}

func (panicSource) Open(string) (io.ReadCloser, error) { panic("malformed input") }

// A panic while reading what a source serves fails the check closed.
func TestPanicDuringCheckFailsClosed(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.Check(panicSource{}, Options{}); !errors.Is(err, ErrBadRepository) {
		t.Fatal(err)
	}
	// The lock was released: a normal check still runs.
	f.release(2, nil)
	f.publish(0, 1)
	if res, err := f.check(Options{}); err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
}

// Mark, 2026-10-05: offline, a drive whose root expired more than 180 days
// ago is refused unless the owner overrides with a tier-4 code.
func TestOldDriveRefusedOfflineUnlessOverridden(t *testing.T) {
	f := newFixture(t)
	// Root v2 is dated by the fixture clock (Init dates v1 by the real one).
	f.must(f.repo.Rotate("root", nil, nil, 0))
	f.must(f.repo.Sign("root", f.root[0]))
	f.must(f.repo.Sign("root", f.root[1]))
	f.release(2, nil)
	f.publish(0, 1)
	rootExp := t0.Add(RootExpiry)
	f.now = rootExp.Add(MaxOfflineRootAge - time.Hour)
	if res, err := f.check(Options{Offline: true}); err != nil || res.Release == nil {
		t.Fatalf("root expired 179 days ago: %v %v", res.Release, err)
	}
	f.now = rootExp.Add(MaxOfflineRootAge + time.Hour)
	res, err := f.check(Options{Offline: true})
	if !errors.Is(err, ErrDriveTooOld) || res.Release != nil {
		t.Fatalf("root expired 181 days ago: %v %v", res.Release, err)
	}
	if in, _ := f.store.Installed(); in.Version != 1 {
		t.Fatal("installed moved")
	}
	if res, err := f.check(Options{Offline: true, AllowOldDrive: true}); err != nil || res.Release == nil {
		t.Fatalf("owner override: %v %v", res.Release, err)
	}
	if DriveTooOldNotice != "This drive's update is too old to trust offline. Use a newer drive, or connect once." {
		t.Fatal("notice text")
	}
}
