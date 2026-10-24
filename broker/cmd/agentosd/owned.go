package main

import (
	"errors"
	"io/fs"
	"os"

	"github.com/ghbmrk/agentos/broker/durable"
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
	return durable.WriteFile(path, nil, 0o600)
}
