package imapsmtp

// REQ: SR3-mail-k18

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The build compiles the vendored go-imap, so every vendored file must be
// the patched copy's (third_party/go-imap/PATCH.md): a patch made to one
// copy only would pass every test and change nothing.
func TestVendoredGoIMAPIsThePatchedCopy(t *testing.T) {
	const patched, vendored = "../../../third_party/go-imap", "../../../vendor/github.com/emersion/go-imap"
	n := 0
	err := filepath.WalkDir(vendored, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(vendored, p)
		v, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		w, err := os.ReadFile(filepath.Join(patched, rel))
		if err != nil || !bytes.Equal(v, w) {
			t.Errorf("vendored %s is not the patched copy (%v)", rel, err)
		}
		n++
		return nil
	})
	if err != nil || n == 0 {
		t.Fatalf("walked %d vendored files: %v", n, err)
	}
}
