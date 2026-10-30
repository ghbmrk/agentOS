package question

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
	r := newRig(t, nil)
	p := filepath.Join(t.TempDir(), "questions.json")
	plantLink(t, p, []byte("{}"))
	cfg := r.cfg
	cfg.Path = p
	if _, err := New(cfg); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("New over a linked book: %v, want ELOOP", err)
	}
}
