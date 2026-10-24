package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/claim"
)

// The owned marker is made once, empty and root's 0600, and a path already
// there (a box set up before the marker, or one the loader replaced) is
// left as it is rather than failing agentosd's start.
func TestMarkOwned(t *testing.T) {
	p := filepath.Join(t.TempDir(), "owned")
	if err := markOwned(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || fi.Size() != 0 {
		t.Fatalf("marker = %v, %v; want an empty 0600 file", fi, err)
	}
	if err := markOwned(p); err != nil {
		t.Fatalf("a second start: %v", err)
	}
	d := filepath.Join(t.TempDir(), "owned")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := markOwned(d); err != nil {
		t.Fatalf("an existing directory: %v", err)
	}
	if err := markOwned(""); err != nil {
		t.Fatal(err)
	}
}

// The loader's three files share one directory, the only one under
// /var/lib/agentos its unit binds in (#2626).
func TestLoaderFilesShareItsDirectory(t *testing.T) {
	for _, p := range []string{apnet.Path, apnet.Owned, claim.SetupNetPath, defaultSetupNet} {
		if filepath.Dir(p) != apnet.Dir {
			t.Errorf("%s is not in %s", p, apnet.Dir)
		}
	}
}
