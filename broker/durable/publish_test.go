package durable

// REQ: CAP-3, OP-4

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// recordPublish is record plus PublishDir's own steps: the stage's
// creation, the fill, and each file fsync, by base name.
func recordPublish(t *testing.T, fail string) *recorder {
	t.Helper()
	r := record(t, fail)
	fsys.mkdir = func(name string, perm os.FileMode) error {
		if err := r.step("mkdir " + filepath.Base(name)); err != nil {
			return err
		}
		return os.Mkdir(name, perm)
	}
	fsys.syncFile = func(name string) error {
		if err := r.step("fsync " + filepath.Base(name)); err != nil {
			return err
		}
		return syncFile(name)
	}
	return r
}

// fillTree writes a small tree: two files, a hard link, a symbolic link, a
// whiteout-like device node's stand-in (a fifo) and a nested directory.
func fillTree(r *recorder) func(string) error {
	return func(stage string) error {
		if err := r.step("fill"); err != nil {
			return err
		}
		sub := filepath.Join(stage, "fs", "etc")
		if err := os.MkdirAll(sub, 0o700); err != nil {
			return err
		}
		for _, p := range []string{filepath.Join(stage, "fs", "a"), filepath.Join(sub, "b")} {
			if err := os.WriteFile(p, []byte(filepath.Base(p)), 0o600); err != nil {
				return err
			}
		}
		if err := os.Link(filepath.Join(sub, "b"), filepath.Join(sub, "c")); err != nil {
			return err
		}
		if err := os.Symlink("b", filepath.Join(sub, "l")); err != nil {
			return err
		}
		return syscall.Mkfifo(filepath.Join(sub, "p"), 0o600)
	}
}

// Every file and directory is fsynced, deepest directory first, before
// the stage is renamed into place; the parent is fsynced after (CAP-3:
// nothing is published before the barrier).
func TestCAP3PublishDirOrder(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "s1")
	r := recordPublish(t, "")
	if err := PublishDir(dir, 0o700, fillTree(r)); err != nil {
		t.Fatal(err)
	}
	stage := TempPrefix + "s1"
	want := []string{
		"mkdir " + stage, "fill",
		"fsync a", "fsync b", "fsync c", // links, fifos: their directory's sync
		"sync dir etc", "sync dir fs", "sync dir " + stage,
		"rename", "sync dir " + filepath.Base(parent),
	}
	if !reflect.DeepEqual(r.log, want) {
		t.Fatalf("order %q\nwant  %q", r.log, want)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "fs", "etc", "l")); err != nil || string(b) != "b" {
		t.Fatalf("published tree: %q, %v", b, err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v, %v", fi, err)
	}
	assertNoTemp(t, parent)
}

// A failure at any step before the rename leaves no dir and no stage; a
// failed sync of the parent after it is the uncertain result: ErrDirSync,
// with dir complete.
func TestCAP3PublishDirFailures(t *testing.T) {
	for _, step := range []string{"mkdir", "fill", "fsync b", "sync dir etc", "sync dir stage", "rename", "sync dir parent"} {
		t.Run(step, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "s1")
			fail := map[string]string{
				"mkdir":           "mkdir " + TempPrefix + "s1",
				"sync dir stage":  "sync dir " + TempPrefix + "s1",
				"sync dir parent": "sync dir " + filepath.Base(parent),
			}[step]
			if fail == "" {
				fail = step
			}
			r := recordPublish(t, fail)
			err := PublishDir(dir, 0o700, fillTree(r))
			if err == nil {
				t.Fatal("no error")
			}
			uncertain := step == "sync dir parent"
			if errors.Is(err, ErrDirSync) != uncertain {
				t.Fatalf("ErrDirSync %v on a failed %s: %v", errors.Is(err, ErrDirSync), step, err)
			}
			_, serr := os.Stat(filepath.Join(dir, "fs", "etc", "c"))
			if uncertain != (serr == nil) {
				t.Fatalf("after a failed %s, published tree: %v", step, serr)
			}
			if _, err := os.Lstat(dir); !uncertain && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("dir left after a failed %s: %v", step, err)
			}
			for i, s := range r.log {
				if s == "rename" && i < len(r.log)-1 && !uncertain {
					t.Fatalf("steps after a rename that failed: %q", r.log)
				}
			}
			assertNoTemp(t, parent)
		})
	}
}

// An existing dir, even an empty one a rename would replace, is refused
// and left as it was; nothing is staged.
func TestCAP3PublishDirRefusesExisting(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "s1")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := recordPublish(t, "")
	if err := PublishDir(dir, 0o700, fillTree(r)); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err %v, want ErrExist", err)
	}
	if len(r.log) != 0 {
		t.Fatalf("steps taken: %q", r.log)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o755 {
		t.Fatal("existing dir changed")
	}
	assertNoTemp(t, parent)
}
