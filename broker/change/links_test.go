package change

// A link planted at a file this package reads is refused, not followed
// (REV-CHK-links, #3945).

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// plantLink makes p a link to a real file holding b, as another uid that could
// write p's directory would.
func plantLink(t *testing.T, p string, b []byte) {
	t.Helper()
	real := p + ".real"
	if err := os.WriteFile(real, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, p); err != nil {
		t.Fatal(err)
	}
}

func TestPlantedLinksAreRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	plantLink(t, p, []byte("{}"))
	if _, err := (FileStore{Path: p}).Load(); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("Load of a linked state file: %v, want ELOOP", err)
	}
	d := DirContent{Dir: t.TempDir()}
	plantLink(t, d.path("body"), []byte("x"))
	if _, err := d.Get("body"); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("Get of a linked body: %v, want ELOOP", err)
	}
}
