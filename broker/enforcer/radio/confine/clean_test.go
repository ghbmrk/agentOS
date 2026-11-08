package confine

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
)

// REQ: NET-2

// outside makes a directory beside the stack's, holding a file and a
// subdirectory with a file: what a planted link would reach.
func outside(t *testing.T, root string) string {
	t.Helper()
	o := filepath.Join(root, "outside")
	for _, d := range []string{o, filepath.Join(o, "sub")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(o, "keys"), filepath.Join(o, "sub", "keys")} {
		if err := os.WriteFile(f, []byte("canary"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

// intact fails unless the outside directory still holds all it was made with.
func intact(t *testing.T, o string) {
	t.Helper()
	for _, f := range []string{filepath.Join(o, "keys"), filepath.Join(o, "sub", "keys")} {
		if b, err := os.ReadFile(f); err != nil || string(b) != "canary" {
			t.Errorf("%s after Empty: %q, %v; a link was followed", f, b, err)
		}
	}
}

// TestEmptyFollowsNoPlantedLink (NET-2 Confined radio stacks; #4459): a
// stack directory holding links the stack planted, to a file, to a
// directory and to /, at the top and nested, plus a file, a socket-like
// FIFO and nested directories, is emptied, and every link's target is
// untouched. The directory itself stays, with its mode and inode. Catches
// an Empty that resolves a link (os.RemoveAll of each entry's resolved
// path, or a walk that stats through links).
func TestEmptyFollowsNoPlantedLink(t *testing.T) {
	root := t.TempDir()
	o := outside(t, root)
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink(filepath.Join(o, "keys"), filepath.Join(dir, "to-file")))
	must(os.Symlink(o, filepath.Join(dir, "to-dir")))
	must(os.Symlink("/", filepath.Join(dir, "to-root")))
	must(os.Symlink("../outside", filepath.Join(dir, "relative")))
	must(os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0o700))
	must(os.Symlink(filepath.Join(o, "sub"), filepath.Join(dir, "a", "b", "deep")))
	must(os.WriteFile(filepath.Join(dir, "a", "core"), []byte("x"), 0o600))
	must(syscall.Mkfifo(filepath.Join(dir, "a", "b", "fifo"), 0o600))
	var before syscall.Stat_t
	must(syscall.Lstat(dir, &before))

	must(Empty(dir))

	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 0 {
		t.Fatalf("after Empty, %s holds %v (%v)", dir, ents, err)
	}
	var after syscall.Stat_t
	must(syscall.Lstat(dir, &after))
	if after.Ino != before.Ino || after.Mode != before.Mode || after.Uid != before.Uid {
		t.Errorf("Empty replaced the directory: inode %d mode %#o uid %d, was %d %#o %d",
			after.Ino, after.Mode, after.Uid, before.Ino, before.Mode, before.Uid)
	}
	intact(t, o)
}

// TestEmptyRefusesALinkedPath: a stack directory that is itself a link,
// or is reached through one, is refused with the target untouched; the
// enforcer names its directories, so a link there is a stack's plant.
func TestEmptyRefusesALinkedPath(t *testing.T) {
	root := t.TempDir()
	o := outside(t, root)
	if err := os.Symlink(o, filepath.Join(root, "state")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(root, "via")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(root, "state"), filepath.Join(root, "via", "outside")} {
		if err := Empty(p); err == nil {
			t.Errorf("Empty(%s) through a link succeeded", p)
		}
	}
	intact(t, o)
}

// TestEmptyRaceSwapsDirForLink: the stack swaps a subdirectory for a link
// to the outside directory between Empty finding it a directory and
// opening it. The open does not follow the link, and the next pass
// removes it. Catches an Empty that opens subdirectories without
// O_NOFOLLOW, which empties the outside directory instead.
func TestEmptyRaceSwapsDirForLink(t *testing.T) {
	root := t.TempDir()
	o := outside(t, root)
	dir := filepath.Join(root, "run")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	var swapped []string
	emptyRace = func(name string) {
		if name != "sub" || len(swapped) > 0 {
			return
		}
		swapped = append(swapped, name)
		if err := os.Rename(filepath.Join(dir, "sub"), filepath.Join(root, "moved")); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(o, filepath.Join(dir, "sub")); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { emptyRace = nil })
	if err := Empty(dir); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(swapped, []string{"sub"}) {
		t.Fatalf("the race hook ran for %v, want [sub]", swapped)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("after Empty, %s holds %v", dir, ents)
	}
	intact(t, o)
}

// TestEmptyFailsWhileWritten: a directory that is not empty after every
// pass (something still writes it) is an error, not an endless chase.
func TestEmptyFailsWhileWritten(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d0"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := 0
	emptyRace = func(string) {
		// A live writer: each directory visited, another appears.
		n++
		if err := os.Mkdir(filepath.Join(dir, "d"+strconv.Itoa(n)), 0o700); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { emptyRace = nil })
	if err := Empty(dir); err == nil {
		t.Fatal("Empty of a directory still being written succeeded")
	}
	if n != emptyPasses {
		t.Errorf("Empty made %d passes, want %d", n, emptyPasses)
	}
}
