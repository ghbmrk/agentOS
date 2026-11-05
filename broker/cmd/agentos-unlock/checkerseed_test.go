package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// A -checker-seed whose directory the check refuses (open to others, or a
// link) is left alone: the fallback remove runs only in a directory found
// to be root's alone, so a planted link never has root unlink a file
// elsewhere (REV-CHK-links-kernel, #4966 L3 finding 1).
// REQ: CH-4
func TestCheckerSeedRefusedDirectoryIsNotRemovedIn(t *testing.T) {
	d := t.TempDir()
	st, err := seal.Create(filepath.Join(d, "store"), seal.Recovery{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	open := filepath.Join(d, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(d, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"open to others": open, "a link": link} {
		victim := filepath.Join(dir, "seed")
		if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeCheckerSeed(victim, st, new([32]byte))
		if _, err := os.Lstat(victim); err != nil {
			t.Errorf("%s: the seed's name was removed in a refused directory: %v", name, err)
		}
	}
}
