package cgroup

import (
	"errors"
	"os"
	"path/filepath"
)

// EffectivePidsMax is the tightest process cap on g and every ancestor
// up to the cgroup v2 mount root, or 0 when none is capped. A group whose
// own pids.max reads "max" under a capped slice is held to the slice's
// cap, so a reserve taken from PidsMax alone would not be guaranteed (L3
// carry on SR2-4i). The walk stops at the first directory that is not a
// cgroup (no cgroup.controllers); an ancestor without pids.max (the mount
// root) adds no cap. g's own pids.max must exist, and a bad value at any
// level is an error, never no cap.
func (g *Group) EffectivePidsMax() (int64, error) {
	least, err := g.PidsMax()
	if err != nil {
		return 0, err
	}
	dir := filepath.Clean(g.Path)
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return least, nil
		}
		if _, err := os.Stat(filepath.Join(parent, "cgroup.controllers")); err != nil {
			return least, nil
		}
		dir = parent
		n, err := (&Group{Path: dir}).PidsMax()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n > 0 && (least == 0 || n < least) {
			least = n
		}
	}
}
