package quota

// A link or FIFO planted at a directory this package opens is refused, not followed
// (REV-CHK-links, #3945).

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPlantedLinksAreRefused(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("Open of a linked directory: %v, want ENOTDIR (O_DIRECTORY|O_NOFOLLOW)", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&FS{dir: dir}).Limit(fifo, 1, 0, 0); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("Limit on a FIFO: %v, want ENOTDIR, not a hang", err)
	}
}
