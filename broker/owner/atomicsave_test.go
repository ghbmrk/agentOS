package owner

import (
	"os"
	"path/filepath"
	"testing"
)

// #2778: the save is kernel/privfile's atomic replace, which durable's
// WriteFile was: a temporary a crash left is replaced, the new form lands
// whole and owner-only, and no temporary stays beside it.
func TestSaveReplacesACrashLeftTemporary(t *testing.T) {
	dir := t.TempDir()
	f := FileStore{Path: filepath.Join(dir, "state.json")}
	if err := os.WriteFile(f.Path+".tmp", []byte("{half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(State{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Load(); err != nil {
		t.Fatalf("load after save: %v", err)
	}
	fi, err := os.Stat(f.Path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved file %v, %v", fi, err)
	}
	if _, err := os.Stat(f.Path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary left beside it: %v", err)
	}
}
