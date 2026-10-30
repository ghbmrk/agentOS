package clock

// A link planted at a file this package reads is refused, not followed
// (REV-CHK-links, #3945).

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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
	p := filepath.Join(t.TempDir(), "clock.json")
	plantLink(t, p, []byte(`{"have_offset":true,"offset":1}`))
	if _, ok := BootEstimate(p, time.Unix(1e9, 0), ""); ok {
		t.Fatal("BootEstimate read a linked state file")
	}
	if _, err := readFile(p); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("readFile of a link: %v, want ELOOP", err)
	}
}
