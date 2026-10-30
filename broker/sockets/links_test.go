package sockets

// REQ: KRN-2

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A link planted at the socket directory's .lock is refused, never followed
// to create or lock its target (REV-CHK-links-daemon-a, #3944).
func TestLockDirRefusesPlantedLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(dir, ".lock")); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDir(dir)
	if err == nil {
		unlock()
		t.Fatal("lockDir followed a link planted at .lock")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("lockDir: %v, want ELOOP", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the link's target was created: %v", err)
	}
}
