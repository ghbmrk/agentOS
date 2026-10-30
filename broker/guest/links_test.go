package guest

// REQ: KRN-2

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A link planted at the inbox file is refused, never read through
// (REV-CHK-links-daemon-a, #3944).
func TestOpenStoreRefusesPlantedLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"inbox":{"m1":[{"id":"x","text":"planted"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(dir, "guest-inbox.json")
	if err := os.Symlink(target, inbox); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(inbox); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("openStore through a planted link: %v, want ELOOP", err)
	}
}
