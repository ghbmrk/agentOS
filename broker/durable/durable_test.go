package durable

// REQ: OP-4, RES-4

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// recorder wraps the real file system and logs each step WriteFile and
// Rename take, by kind and base name.
type recorder struct {
	log  []string
	fail string // a step that returns an error instead of running
}

type recFile struct {
	*os.File
	r *recorder
}

func (f recFile) Write(b []byte) (int, error) {
	if err := f.r.step("write"); err != nil {
		return 0, err
	}
	return f.File.Write(b)
}

func (f recFile) Sync() error {
	if err := f.r.step("sync file"); err != nil {
		return err
	}
	return f.File.Sync()
}

func (r *recorder) step(s string) error {
	r.log = append(r.log, s)
	if s == r.fail {
		return errors.New("injected: " + s)
	}
	return nil
}

func record(t *testing.T, fail string) *recorder {
	t.Helper()
	r := &recorder{fail: fail}
	saved := fsys
	t.Cleanup(func() { fsys = saved })
	fsys.createTemp = func(dir, pattern string) (file, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return recFile{f, r}, nil
	}
	fsys.rename = func(o, n string) error {
		if err := r.step("rename"); err != nil {
			return err
		}
		return os.Rename(o, n)
	}
	fsys.syncDir = func(dir string) error {
		if err := r.step("sync dir " + filepath.Base(dir)); err != nil {
			return err
		}
		return syncDir(dir)
	}
	return r
}

func TestWriteFileSyncsDir(t *testing.T) {
	dir := t.TempDir()
	r := record(t, "")
	path := filepath.Join(dir, "state")
	if err := WriteFile(path, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	want := []string{"write", "sync file", "rename", "sync dir " + filepath.Base(dir)}
	if !reflect.DeepEqual(r.log, want) {
		t.Fatalf("order %q, want %q", r.log, want)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("read %q, %v", got, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	assertNoTemp(t, dir)
}

// A failure before the rename leaves the old file and no temporary file; a
// failed directory sync is reported, not swallowed.
func TestWriteFileFailures(t *testing.T) {
	for _, step := range []string{"write", "sync file", "rename", "sync dir"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			fail := step
			if step == "sync dir" {
				fail = "sync dir " + filepath.Base(dir)
			}
			record(t, fail)
			err := WriteFile(path, []byte("new"), 0o600)
			if err == nil {
				t.Fatal("no error")
			}
			if errors.Is(err, ErrDirSync) != (step == "sync dir") {
				t.Fatalf("ErrDirSync %v on a failed %s", errors.Is(err, ErrDirSync), step)
			}
			got, _ := os.ReadFile(path)
			want := "old"
			if step == "sync dir" {
				want = "new"
			}
			if string(got) != want {
				t.Fatalf("target changed to %q", got)
			}
			assertNoTemp(t, dir)
		})
	}
}

func TestRenameSyncsBothDirs(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	for _, d := range []string{a, b} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(a, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := record(t, "")
	if err := Rename(filepath.Join(a, "f"), filepath.Join(b, "f")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"rename", "sync dir b", "sync dir a"}; !reflect.DeepEqual(r.log, want) {
		t.Fatalf("order %q, want %q", r.log, want)
	}
	r.log = nil
	if err := Rename(filepath.Join(b, "f"), filepath.Join(b, "g")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"rename", "sync dir b"}; !reflect.DeepEqual(r.log, want) {
		t.Fatalf("same-dir order %q, want %q", r.log, want)
	}
}

func TestSweepTemp(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "state")
	for _, n := range []string{keep, filepath.Join(dir, TempPrefix+"123")} {
		if err := os.WriteFile(n, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := SweepTemp(dir); err != nil {
		t.Fatal(err)
	}
	assertNoTemp(t, dir)
	if _, err := os.Stat(keep); err != nil {
		t.Fatal(err)
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), TempPrefix) {
			t.Fatalf("temporary file left: %s", e.Name())
		}
	}
}
