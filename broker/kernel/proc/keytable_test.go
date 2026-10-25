package proc

// REQ: LOG-4

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

const (
	subA = "00112233445566778899aabbccddeeff"
	subB = "ffeeddccbbaa99887766554433221100"
)

// A deleted key does not come back when the table is reopened, and a key
// file sealed for one subject does not open as another's (LOG-4).
func TestFileKeysDeleteIsDurable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	logKey := [32]byte{5}
	f, err := OpenFileKeys(dir, logKey)
	if err != nil {
		t.Fatal(err)
	}
	ka, kb := kernel.SubjectKey{1}, kernel.SubjectKey{2}
	if err := f.Put(subA, ka); err != nil {
		t.Fatal(err)
	}
	if err := f.Put(subB, kb); err != nil {
		t.Fatal(err)
	}
	if err := f.Delete(subA); err != nil {
		t.Fatal(err)
	}
	if err := f.Delete(subA); err != nil {
		t.Fatalf("a second delete: %v", err)
	}
	os.WriteFile(filepath.Join(dir, subA+".key.tmp"), []byte("torn"), 0o600) // a crash's temporary

	g, err := OpenFileKeys(dir, logKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := g.List(); err != nil || !slices.Equal(got, []string{subB}) {
		t.Fatalf("list after reopen: %v %v", got, err)
	}
	if _, ok, err := g.Get(subA); ok || err != nil {
		t.Fatalf("a deleted key: %v %v", ok, err)
	}
	if k, ok, err := g.Get(subB); !ok || err != nil || k != kb {
		t.Fatalf("a kept key: %v %v", ok, err)
	}

	// B's file under A's name does not open as A's.
	b, _ := os.ReadFile(filepath.Join(dir, subB+".key"))
	os.WriteFile(filepath.Join(dir, subA+".key"), b, 0o600)
	if _, _, err := g.Get(subA); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("a moved file: %v", err)
	}
	// Nor under another log key.
	h, _ := OpenFileKeys(dir, [32]byte{6})
	if _, _, err := h.Get(subB); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("another log key: %v", err)
	}
	if err := g.Put("../escape", ka); err == nil {
		t.Fatal("a subject that is not an id was put")
	}
}

// A table directory or key file open to another uid is refused, as the
// log's own files are (privfile).
func TestFileKeysRefusesALooseDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileKeys(dir, [32]byte{}); err == nil {
		t.Fatal("a directory open to other uids was opened")
	}
	os.Chmod(dir, 0o700)
	f, err := OpenFileKeys(dir, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Put(subA, kernel.SubjectKey{1}); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(dir, subA+".key"), 0o644)
	if _, _, err := f.Get(subA); err == nil {
		t.Fatal("a key file open to other uids was read")
	}
}
