package bootab

// REQ: UPD-1a

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenStagedRefusesALink: a symlink planted in place of a staged file
// is not followed, so the slot is never written from the link's target.
func TestOpenStagedRefusesALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("not the release"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "usr.img")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openStaged(link); err == nil {
		f.Close()
		t.Fatal("openStaged followed a link")
	}
	f, err := openStaged(target)
	if err != nil {
		t.Fatalf("openStaged on a regular file: %v", err)
	}
	f.Close()
}
