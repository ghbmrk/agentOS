package change

// REQ: OP-4
//
// The store outlived the pipeline (#2785 c3), whose tests exercised it
// incidentally; these exercise it directly until c4 moves it.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreKeepsOldOrNew(t *testing.T) {
	f := FileStore{Path: filepath.Join(t.TempDir(), "state.json")}
	if b, err := f.Load(); b != nil || err != nil {
		t.Fatalf("empty store: %q %v", b, err)
	}
	for _, want := range []string{"old", "new"} {
		if err := f.Save([]byte(want)); err != nil {
			t.Fatal(err)
		}
		if b, err := f.Load(); string(b) != want || err != nil {
			t.Fatalf("%q %v, want %q", b, err, want)
		}
	}
	// A save that fails leaves the old content: here the rename target is
	// a directory, so the write cannot publish.
	bad := FileStore{Path: t.TempDir()}
	if err := bad.Save([]byte("x")); err == nil {
		t.Fatal("save over a directory succeeded")
	}
	if b, err := f.Load(); string(b) != "new" || err != nil {
		t.Fatalf("%q %v", b, err)
	}
	if fi, err := os.Stat(f.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi.Mode(), err)
	}
}

func TestDirContentRoundTrip(t *testing.T) {
	f := FileStore{Path: filepath.Join(t.TempDir(), "state.json")}
	c := f.Bodies()
	if d, ok := c.(DirContent); !ok || d.Dir != f.Path+".d" {
		t.Fatalf("%#v", c)
	}
	if b, err := c.Get("a/../b"); b != nil || err != nil {
		t.Fatalf("missing: %q %v", b, err)
	}
	if err := c.Put("a/../b", []byte("body")); err != nil {
		t.Fatal(err)
	}
	// The name is hashed, so it never names a path.
	if _, err := os.Stat(filepath.Join(f.Path+".d", "b")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("name used as a path: %v", err)
	}
	if b, err := c.Get("a/../b"); string(b) != "body" || err != nil {
		t.Fatalf("%q %v", b, err)
	}
	if err := c.Delete("a/../b"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete("a/../b"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if b, err := c.Get("a/../b"); b != nil || err != nil {
		t.Fatalf("deleted: %q %v", b, err)
	}
}

func TestMemStoreSharesItsBodies(t *testing.T) {
	m := &MemStore{}
	if err := m.Bodies().Put("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if b, _ := m.Bodies().Get("k"); string(b) != "v" {
		t.Fatalf("%q", b)
	}
	m.Fail = errors.New("full")
	if err := m.Save([]byte("x")); err == nil {
		t.Fatal("Fail ignored")
	}
	if b, err := m.Load(); b != nil || err != nil {
		t.Fatalf("%q %v", b, err)
	}
}
