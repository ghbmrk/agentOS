package seal_test

// REQ: STO-2

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// ReadID gives the ID the open store has, without a factor; a file that
// does not parse gives none.
func TestReadID(t *testing.T) {
	path, s := create(t, recovery(t))
	id, err := seal.ReadID(path)
	if err != nil || len(id) == 0 || !bytes.Equal(id, s.ID()) {
		t.Fatalf("ReadID = %x, %v; the store's is %x", id, err, s.ID())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := seal.ReadID(path); !errors.Is(err, seal.ErrCorrupt) {
		t.Fatalf("a changed file: %v, want ErrCorrupt", err)
	}
}
