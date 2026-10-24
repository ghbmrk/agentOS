package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// markOwned makes the owned marker (apnet.Owned, #2626) once the owner's
// number is known: setup's finish recorded, or -owner given. agentos-ap
// reads its presence where it once read the owner state, which the
// loader's namespace no longer holds, and burns the setup network and
// serves only the card's network from then on. It is made at every such
// start, so a box set up before the marker existed gets one; a path that
// is already there, of any kind, is left as it is. An empty path makes
// none.
func markOwned(path string) error {
	if path == "" {
		return nil
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Empty, it needs no temp file and rename: O_EXCL makes it once, and
	// the file and its directory are synced so it survives a power cut.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
