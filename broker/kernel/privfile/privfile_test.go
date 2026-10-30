package privfile

// REQ: KRN-2

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// WriteAtomic refuses a directory another uid can write, since that uid
// could swap the closed name.tmp for a link that the rename installs at name
// (#3954); a directory only this uid can write passes, readable or not.
func TestWriteAtomicRefusesADirOtherUidsCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o720, 0o702, 0o777, 0o777 | os.ModeSticky} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := WriteAtomic(dir, "f", []byte("canary"), nil); err == nil {
			t.Errorf("a %v directory was written", mode)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("a refused %v directory holds %d entries", mode, len(ents))
		}
	}
	for _, mode := range []os.FileMode{0o700, 0o750, 0o755} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := WriteAtomic(dir, "f", []byte("canary"), nil); err != nil {
			t.Errorf("a %v directory: %v", mode, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != "canary" {
			t.Errorf("a %v directory holds %q", mode, b)
		}
	}
}

// A directory owned by another uid is refused: that uid can chmod it open.
func TestWriteAtomicRefusesADirOfAnotherUid(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(dir, "f", []byte("canary"), nil); err == nil {
		t.Fatal("a directory of uid 12345 was written")
	}
}

// A link planted at dir is not followed, by WriteAtomic or by SyncDir.
func TestWriteAtomicRefusesALinkedDir(t *testing.T) {
	target, link := t.TempDir(), filepath.Join(t.TempDir(), "d")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(link, "f", []byte("canary"), nil); err == nil {
		t.Fatal("WriteAtomic followed a link at dir")
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("the link's target holds %d entries", len(ents))
	}
	if err := SyncDir(link); err == nil {
		t.Fatal("SyncDir followed a link at dir")
	}
}

// WriteAtomic works in the directory it opened: dir swapped for a link
// after name.tmp is closed (as another uid that can write dir's parent
// could) still gets the rename and the sync, and the link's target gets
// nothing.
func TestWriteAtomicStaysInTheDirItOpened(t *testing.T) {
	parent, decoy := t.TempDir(), t.TempDir()
	dir, moved := filepath.Join(parent, "d"), filepath.Join(parent, "moved")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent-canary", filepath.Join(decoy, "f.tmp")); err != nil {
		t.Fatal(err)
	}
	swap := func(i int) bool {
		if i == 3 { // after Close, before Rename
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(decoy, dir); err != nil {
				t.Fatal(err)
			}
		}
		return false
	}
	err := WriteAtomic(dir, "f", []byte("canary"), swap)
	if err != nil {
		t.Errorf("a write whose dir was swapped mid-way: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(moved, "f")); string(b) != "canary" {
		t.Errorf("the opened directory holds %q", b)
	}
	if _, err := os.Lstat(filepath.Join(decoy, "f")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the decoy got f: %v", err)
	}
}

// Neither WriteAtomic nor SyncDir hangs on a FIFO at dir or follows a link
// to one (#3954 comment; #3991 Security 1).
func TestSyncDirRefusesAFIFO(t *testing.T) {
	d := t.TempDir()
	fifo, link := filepath.Join(d, "fifo"), filepath.Join(d, "link")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	calls := map[string]func(string) error{
		"SyncDir":     SyncDir,
		"WriteAtomic": func(dir string) error { return WriteAtomic(dir, "f", []byte("canary"), nil) },
	}
	for name, call := range calls {
		for _, p := range []string{fifo, link} {
			done := make(chan error, 1)
			go func() { done <- call(p) }()
			select {
			case err := <-done:
				if err == nil {
					t.Errorf("%s(%s) took a FIFO for a directory", name, filepath.Base(p))
				}
			case <-time.After(5 * time.Second):
				t.Errorf("%s(%s) hangs on a FIFO", name, filepath.Base(p))
			}
		}
	}
}
