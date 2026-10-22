package imapsmtp

// REQ: SR3-mail-k18

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The build compiles the vendored go-imap, so the vendored files must be
// the patched copy's (third_party/go-imap/PATCH.md), each way: a patch made
// to one copy only, or a file added to one only, would pass every test and
// change nothing. go mod vendor leaves out the copy's go.mod.
func TestVendoredGoIMAPIsThePatchedCopy(t *testing.T) {
	patched, vendored := files(t, "../../../third_party/go-imap"), files(t, "../../../vendor/github.com/emersion/go-imap")
	delete(patched, "go.mod")
	if len(vendored) == 0 {
		t.Fatal("no vendored files")
	}
	for rel, v := range vendored {
		if w, ok := patched[rel]; !ok || !bytes.Equal(v, w) {
			t.Errorf("vendored %s is not the patched copy's", rel)
		}
	}
	for rel := range patched {
		if _, ok := vendored[rel]; !ok {
			t.Errorf("patched %s is not vendored", rel)
		}
	}
}

// files is every file under dir, by its path in dir.
func files(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out[rel], err = os.ReadFile(p)
		return err
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return out
}
