package proc

// REQ: LOG-4
//
// MUT-kill-6305-proc (#6367): the subject-key table's refusals, each checked
// by what it returns or leaves on disk.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// A name that is not a subject ID is refused by every call, and nothing is
// written for it.
func TestFileKeysRefuseANameThatIsNoSubject(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	f, err := OpenFileKeys(dir, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Put("notasubject", kernel.SubjectKey{1}); err == nil {
		t.Fatal("put under a name that is no subject ID was taken")
	}
	if des, _ := os.ReadDir(dir); len(des) != 0 {
		t.Fatalf("the refused put left %d files", len(des))
	}
	if _, _, err := f.Get("notasubject"); err == nil {
		t.Fatal("get under a name that is no subject ID was answered")
	}
	if err := f.Delete("notasubject"); err == nil {
		t.Fatal("delete under a name that is no subject ID was taken")
	}
}

// A key file that is a link is an error, never read as no key; a short or
// foreign file is ErrKeyFile.
func TestFileKeysGetRefusesALinkAndAShortFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	f, err := OpenFileKeys(dir, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, subA+keyExt)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := f.Get(subA); !errors.Is(err, syscall.ELOOP) || ok {
		t.Fatalf("get of a linked key file: ok %v, %v; want ELOOP", ok, err)
	}
	for _, n := range []int{0, 5, 12, 27} {
		if err := os.WriteFile(filepath.Join(dir, subB+keyExt), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := f.Get(subB); !errors.Is(err, ErrKeyFile) || ok {
			t.Fatalf("get of a %d-byte key file: ok %v, %v; want ErrKeyFile", n, ok, err)
		}
	}
}

// Get closes the key file it read.
func TestFileKeysGetClosesTheFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	f, err := OpenFileKeys(dir, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Put(subA, kernel.SubjectKey{9}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, subA+keyExt)
	for range 4 {
		if k, ok, err := f.Get(subA); err != nil || !ok || k != (kernel.SubjectKey{9}) {
			t.Fatalf("get: %v %v %v", k, ok, err)
		}
		if n := openFDsTo(t, p); n != 0 {
			t.Fatalf("%d descriptors to the key file stay open after a get", n)
		}
	}
}

// openFDsTo counts this process's descriptors open on path.
func openFDsTo(t *testing.T, path string) int {
	t.Helper()
	des, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, de := range des {
		if l, err := os.Readlink(filepath.Join("/proc/self/fd", de.Name())); err == nil && l == path {
			n++
		}
	}
	return n
}

// Delete syncs the directory after it unlinks a key (a delete a crash undoes
// is a key that comes back), and List of a table whose directory is gone is
// an error, never an empty table.
func TestFileKeysDeleteSyncsAndListReportsAGoneDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	f, err := OpenFileKeys(dir, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{subB, subA} {
		if err := f.Put(s, kernel.SubjectKey{2}); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := f.List(); err != nil || strings.Join(got, ",") != subA+","+subB {
		t.Fatalf("list %v %v, want both in order", got, err)
	}
	synced := 0
	was := privfile.SyncFile
	privfile.SyncFile = func(d *os.File) error { synced++; return was(d) }
	defer func() { privfile.SyncFile = was }()
	if err := f.Delete(subA); err != nil || synced != 1 {
		t.Fatalf("delete: %v, %d syncs; want one", err, synced)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := f.List(); err == nil {
		t.Fatalf("list of a gone table: %v, no error", got)
	}
}
