package follow

// A link planted at a file this package reads is refused, not followed
// (REV-CHK-links, #3945).

import (
	"context"
	"errors"
	"os"
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
	r := newRig(t)
	plantLink(t, r.pending, []byte("owed"))
	_, err := New(Config{Store: r.store, Shipped: r.shipped, Clock: r.clk, Pending: r.pending,
		Alert: func(context.Context, string) error { return nil }})
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("New over a linked pending alert: %v, want ELOOP", err)
	}
}
