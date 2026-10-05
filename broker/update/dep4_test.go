package update

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// REQ: DEP-4

// memMirror is a mirror the project does not run: a copy of the
// repository's bytes served from anywhere, here from memory.
type memMirror map[string][]byte

func (m memMirror) Open(name string) (io.ReadCloser, error) {
	b, ok := m[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// copyRepo reads every file of the published repository, keyed by its
// repository-relative path.
func copyRepo(t *testing.T, dir string) memMirror {
	t.Helper()
	m := memMirror{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		m[filepath.ToSlash(rel)], err = os.ReadFile(p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// toDrive writes a mirror's files under dir, as a drive carries them.
func toDrive(t *testing.T, m memMirror, dir string) DirSource {
	t.Helper()
	for name, b := range m {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return DirSource(dir)
}

// newBox is a second box shipped with the same image root, release 1.
func (f *fixture) newBox() *Store {
	f.t.Helper()
	root, err := os.ReadFile(filepath.Join(f.repo.Dir, "metadata", "1.root.json"))
	f.must(err)
	s, err := InitStore(filepath.Join(f.t.TempDir(), "box"), root, 1)
	f.must(err)
	return s
}

func (f *fixture) checkOn(s *Store, src Source, o Options) (Result, error) {
	o.Now = func() time.Time { return f.now }
	o.Attestors = f.attestors()
	return s.Check(src, o)
}

// DEP-4: a release verifies from content hashes and signatures alone, so
// any copy of the repository serves it: a mirror nobody vouches for
// online, or a drive with no network at all. Trust comes from the root in
// the box's image, never from where the bytes came from.
func TestReleaseVerifiesFromAnyMirrorOrDrive(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	mirror := copyRepo(t, f.repo.Dir)

	res, err := f.checkOn(f.store, mirror, Options{})
	if err != nil || res.Release == nil || !res.Release.Fresh() {
		t.Fatalf("online from a third-party mirror: %v %v", res.Release, err)
	}
	dst := filepath.Join(t.TempDir(), "vmlinuz")
	f.must(res.Release.Fetch(mirror, "host-image/2/vmlinuz", dst))
	if b, _ := os.ReadFile(dst); string(b) != "vmlinuz of release 2" {
		t.Fatalf("mirror served %q", b)
	}

	// A mirror that alters a file is caught by its hash, whatever it
	// claims, and the altered bytes never land.
	bad := memMirror{}
	for k, v := range mirror {
		bad[k] = v
	}
	for _, fl := range mustV(res.Release.Files()) {
		if fl.Path == "host-image/2/vmlinuz" {
			bad[targetFile(fl.Path, fl.SHA256)] = []byte("vmlinuz of release 9")
		}
	}
	dst2 := filepath.Join(t.TempDir(), "vmlinuz")
	if err := res.Release.Fetch(bad, "host-image/2/vmlinuz", dst2); !errors.Is(err, ErrBadRepository) {
		t.Fatalf("altered file from a mirror: %v", err)
	}
	if _, err := os.Stat(dst2); !os.IsNotExist(err) {
		t.Fatal("altered bytes reached the destination")
	}

	// Another box, never online, installs the same release from a drive
	// long after every online role expired.
	box := f.newBox()
	drive := toDrive(t, mirror, filepath.Join(t.TempDir(), "drive"))
	f.now = t0.Add(30 * 24 * time.Hour)
	res, err = f.checkOn(box, drive, Options{Offline: true})
	if err != nil || res.Release == nil {
		t.Fatalf("offline from a drive: %v %v", res.Release, err)
	}
	f.must(res.Release.Fetch(drive, "host-image/2/usr.img", filepath.Join(t.TempDir(), "usr.img")))
	f.must(box.Commit(res.Release))
	if in, _ := box.Installed(); in.Version != 2 || !in.UnconfirmedFreshness {
		t.Fatalf("drive install: %+v", in)
	}
}

// DEP-4: no update is required to keep working. With no mirror reachable
// a check fails, the installed release stays as it was, and a later check
// from any source still works.
func TestNoUpdateRequiredToKeepWorking(t *testing.T) {
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	before, err := f.store.Installed()
	f.must(err)
	if _, err := f.checkOn(f.store, memMirror{}, Options{}); err == nil {
		t.Fatal("a check with no mirror passed")
	}
	if after, _ := f.store.Installed(); after != before {
		t.Fatalf("a failed check changed the installed release: %+v -> %+v", before, after)
	}
	f.now = t0.Add(365 * 24 * time.Hour)
	if _, err := f.checkOn(f.store, memMirror{}, Options{Offline: true}); err == nil {
		t.Fatal("an offline check with nothing to read passed")
	}
	if after, _ := f.store.Installed(); after != before {
		t.Fatal("a year without updates changed the installed release")
	}
	res, err := f.checkOn(f.store, copyRepo(t, f.repo.Dir), Options{Offline: true})
	if err != nil || res.Release == nil {
		t.Fatalf("store not usable after failed checks: %v", err)
	}
}
