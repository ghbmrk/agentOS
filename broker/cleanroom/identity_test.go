package cleanroom

// SR3-8-f1: an artifact's identity is its directory name. A manifest
// cannot name another artifact, or a path outside the store, as the one to
// quarantine, and one damaged file cannot stop the builder opening.
//
// REQ: OSS-2 (SR3-8-f1a, SR3-8-f1b)

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// putArtifact commits an artifact with job ID job directly to the store.
func putArtifact(t *testing.T, s *Store, job string) Artifact {
	t.Helper()
	a, err := s.put(Manifest{ID: "a-" + job, Job: job, Output: "skill"}, nestedFiles)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// tamper rewrites an artifact's manifest with its ID set to id and one
// file digest changed, so its output no longer verifies.
func tamper(t *testing.T, a Artifact, id string) {
	t.Helper()
	m := a.Manifest()
	m.ID = id
	m.Files[0].SHA256 = strings.Repeat("0", 64)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.dir, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// tree lists every path under root.
func tree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A damaged manifest that names a healthy artifact gets itself
// quarantined, not the artifact it names.
func TestDamagedManifestCannotQuarantineAnother(t *testing.T) {
	r := newRig(t, nil)
	a := putArtifact(t, r.b.store, "A")
	b := putArtifact(t, r.b.store, "B")
	tamper(t, b, a.m.ID)
	reopen(t, r)
	got, err := r.b.store.Get(a.m.ID)
	if err != nil {
		t.Fatalf("healthy %s not served: %v", a.m.ID, err)
	}
	if err := got.verify(); err != nil {
		t.Fatal(err)
	}
	if q := quarantined(r, a.m.ID); len(q) != 0 {
		t.Fatalf("healthy artifact quarantined: %v", q)
	}
	if q := quarantined(r, b.m.ID); len(q) != 1 {
		t.Fatalf("damaged %s quarantine %v", b.m.ID, q)
	}
	if _, err := os.Stat(b.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("damaged artifact still in place: %v", err)
	}
}

// get refuses a manifest whose ID is not the one asked for.
func TestGetRefusesManifestOfAnotherID(t *testing.T) {
	r := newRig(t, nil)
	a := putArtifact(t, r.b.store, "A")
	b := putArtifact(t, r.b.store, "B")
	m := b.Manifest()
	m.ID = a.m.ID
	if err := writeJSON(filepath.Join(b.dir, "manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	if got, err := r.b.store.Get(b.m.ID); err == nil {
		t.Fatalf("Get(%s) served a manifest naming %s", b.m.ID, got.m.ID)
	}
}

// A manifest ID that is a path, or empty, is never used as one: reopen
// quarantines the damaged directory by its own name, touches nothing
// outside the store, and succeeds.
func TestDamagedManifestIDIsNotAPath(t *testing.T) {
	for name, id := range map[string]string{"parent": "../victim", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			victim := filepath.Join(r.cfg.Dir, "victim")
			if err := os.Mkdir(victim, 0o700); err != nil {
				t.Fatal(err)
			}
			b := putArtifact(t, r.b.store, "B")
			tamper(t, b, id)
			b2, err := New(r.cfg)
			if err != nil {
				t.Fatalf("open failed on one damaged manifest: %v", err)
			}
			r.b = b2
			if fi, err := os.Stat(victim); err != nil || !fi.IsDir() {
				t.Fatalf("directory outside the store moved: %v", err)
			}
			for _, p := range tree(t, r.b.store.dir) {
				if strings.HasPrefix(filepath.Base(p), "victim") {
					t.Fatalf("moved into the store: %s", p)
				}
			}
			if q := quarantined(r, b.m.ID); len(q) != 1 {
				t.Fatalf("damaged %s quarantine %v", b.m.ID, q)
			}
		})
	}
}

// quarantine refuses an ID that is not one plain, visible name, and
// renames nothing.
func TestQuarantineRefusesBadID(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	s, _, err := openStore(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"a/b", ".x", ".quarantine"} {
		if err := os.MkdirAll(filepath.Join(s.dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	before := tree(t, root)
	for _, id := range []string{"..", ".x", "a/b", "", ".", "../store"} {
		if err := s.quarantine(id); err == nil {
			t.Errorf("quarantine(%q) accepted", id)
		}
		if after := tree(t, root); !slices.Equal(before, after) {
			t.Fatalf("quarantine(%q) changed the tree:\n%v\n%v", id, before, after)
		}
	}
}

// A symlink in place of the quarantine directory is refused: the artifact
// stays in the store and nothing reaches the symlink's target.
func TestQuarantineRefusesSymlinkedDir(t *testing.T) {
	root := t.TempDir()
	s, _, err := openStore(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.put(Manifest{ID: "a-x", Job: "x", Output: "skill"}, nestedFiles)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(s.dir, ".quarantine")); err != nil {
		t.Fatal(err)
	}
	if err := s.quarantine("a-x"); err == nil {
		t.Error("quarantine through a symlinked .quarantine accepted")
	}
	if _, err := os.Stat(a.dir); err != nil {
		t.Errorf("artifact moved: %v", err)
	}
	if got := tree(t, outside); len(got) != 1 {
		t.Errorf("artifact moved out of the store: %v", got)
	}
}
