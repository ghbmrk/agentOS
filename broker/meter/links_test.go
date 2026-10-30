package meter

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
	p := filepath.Join(t.TempDir(), "meter.json")
	plantLink(t, p, []byte("{}"))
	if _, err := Open(Config{Path: p, MachineCap: big, OverallCap: big}); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("Open over a linked state file: %v, want ELOOP", err)
	}
}
