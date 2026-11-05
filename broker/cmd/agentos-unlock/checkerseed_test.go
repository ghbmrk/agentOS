package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
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

// ownDir makes a missing directory with its mode and takes it as this
// uid's alone (mutgate: the Mkdir is not dead code).
// REQ: CH-4
func TestOwnDirMakesAMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "made")
	if err := ownDir(dir, 0o700, 0o077); err != nil {
		t.Fatalf("ownDir on a missing directory: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("ownDir made %v (%v), want a 0700 directory", fi, err)
	}
}

// ownDir names the cause when there is no directory to check: a missing
// parent says ENOENT, not only "not mine", and is still errNotMine
// (REV-CHK-links-kernel-f1, #4985 finding 1).
// REQ: CH-4
func TestOwnDirNamesTheCauseOfAFailedLstat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-parent", "dir")
	err := ownDir(dir, 0o700, 0o077)
	if !errors.Is(err, errNotMine) {
		t.Fatalf("ownDir under a missing parent: %v, want errNotMine", err)
	}
	if !strings.Contains(err.Error(), syscall.ENOENT.Error()) {
		t.Errorf("ownDir under a missing parent said %q, want it to name %q", err, syscall.ENOENT.Error())
	}
}

// ownDir refuses a regular file at the directory's name, and a 0700
// directory another uid owns (#4985 finding 2a, 2c): each clause has a
// test that fails without it.
// REQ: CH-4
func TestOwnDirRefusesAFileAndAnotherUidsDirectory(t *testing.T) {
	d := t.TempDir()
	file := filepath.Join(d, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ownDir(file, 0o700, 0o077); !errors.Is(err, errNotMine) {
		t.Errorf("ownDir on a regular file: %v, want errNotMine", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	theirs := filepath.Join(d, "theirs")
	if err := os.Mkdir(theirs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(theirs, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := ownDir(theirs, 0o700, 0o077); !errors.Is(err, errNotMine) {
		t.Errorf("ownDir on another uid's 0700 directory: %v, want errNotMine", err)
	}
}

// putClerkAnchors takes a 0755 directory and refuses a group-writable one,
// leaving the name in it alone (#4985 finding 2b).
// REQ: CH-4
func TestClerkAnchorsRefuseAGroupWritableDirectory(t *testing.T) {
	d := t.TempDir()
	ok := filepath.Join(d, "ok")
	if err := os.Mkdir(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := putClerkAnchors(filepath.Join(ok, "anchors"), nil); err != nil {
		t.Errorf("putClerkAnchors in a 0755 directory of mine: %v", err)
	}
	open := filepath.Join(d, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o775); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(open, "anchors")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := putClerkAnchors(victim, nil); !errors.Is(err, errNotMine) {
		t.Errorf("putClerkAnchors in a group-writable directory: %v, want errNotMine", err)
	}
	if _, err := os.Lstat(victim); err != nil {
		t.Errorf("putClerkAnchors removed a name in a refused directory: %v", err)
	}
}

// A seed that cannot be written in a directory of this uid's alone (here a
// store entry that is not a code seed) removes the earlier boot's file, so
// a checker never starts on a stale seed (mutgate: the fallback remove is
// not dead code).
// REQ: CH-4
func TestCheckerSeedFailureRemovesTheStaleSeed(t *testing.T) {
	d := t.TempDir()
	st, err := seal.Create(filepath.Join(d, "store"), seal.Recovery{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Put(handoff.CheckerSeedEntry, []byte("not a seed")); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(d, "mine")
	if err := os.Mkdir(mine, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(mine, "seed")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := putCheckerSeed(stale, st, new([32]byte)); err == nil || errors.Is(err, errNotMine) {
		t.Fatalf("putCheckerSeed = %v, want a failure past the directory check", err)
	}
	writeCheckerSeed(stale, st, new([32]byte))
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the stale seed was kept after a failed write: %v", err)
	}
}
