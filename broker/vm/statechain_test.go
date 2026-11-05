package vm

// REQ: KRN-2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The vm allow lines in broker/kernel/privfile/pathops_allow.txt call
// every directory vm.Open makes "root-held": no other uid can swap a
// component of StateDir's path for a link, so root's mkdir, chmod and
// removals land where they were meant. That held only for the default
// -machines (/var/lib/agentos/machines, under tmpfiles' 0700 root
// /var/lib/agentos), and nothing checked it for another value (#3995
// item 2). Open now refuses a StateDir whose path no other uid may be
// kept out of, before it makes or changes anything.
func TestOpenRefusesStateDirOthersCanSwap(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, top string) string{
		"world-writable parent": func(t *testing.T, top string) string {
			return mode(t, filepath.Join(top, "pub"), 0o777)
		},
		"group-writable parent": func(t *testing.T, top string) string {
			return mode(t, filepath.Join(top, "grp"), 0o770)
		},
		"group-writable grandparent": func(t *testing.T, top string) string {
			return mode(t, filepath.Join(mode(t, filepath.Join(top, "grp"), 0o775), "mid"), 0o700)
		},
		"link in the path": func(t *testing.T, top string) string {
			real := mode(t, filepath.Join(top, "real"), 0o700)
			if err := os.Symlink(real, filepath.Join(top, "link")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(top, "link")
		},
		"StateDir a link": func(t *testing.T, top string) string {
			real := mode(t, filepath.Join(top, "real"), 0o700)
			if err := os.Symlink(real, filepath.Join(top, "state")); err != nil {
				t.Fatal(err)
			}
			return top // StateDir is top/state, below
		},
		"StateDir a file": func(t *testing.T, top string) string {
			if err := os.WriteFile(filepath.Join(top, "state"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return top
		},
	} {
		t.Run(name, func(t *testing.T) {
			top := mode(t, filepath.Join(t.TempDir(), "top"), 0o700)
			dir := filepath.Join(setup(t, top), "state")
			before := snapshotTree(t, top)
			cfg := newCfg(t)
			cfg.StateDir = dir
			if m, err := Open(context.Background(), cfg); !errors.Is(err, ErrStateDirExposed) {
				if m != nil {
					t.Errorf("Open(%s) = a manager, want ErrStateDirExposed", dir)
				} else {
					t.Errorf("Open(%s) = %v, want ErrStateDirExposed", dir, err)
				}
			}
			if after := snapshotTree(t, top); after != before {
				t.Errorf("Open changed the tree before refusing:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// A path another uid owns any directory of is refused too, and so is a
// StateDir another uid owns; this needs root to make such a path.
func TestOpenRefusesStateDirAnotherUidOwns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	for name, chown := range map[string]func(top string) string{
		"parent":   func(top string) string { return filepath.Join(top, "theirs") },
		"StateDir": func(top string) string { return filepath.Join(top, "theirs", "state") },
	} {
		t.Run(name, func(t *testing.T) {
			top := mode(t, filepath.Join(t.TempDir(), "top"), 0o700)
			theirs := mode(t, filepath.Join(top, "theirs"), 0o700)
			mode(t, filepath.Join(theirs, "state"), 0o700)
			if err := os.Lchown(chown(top), 65534, 65534); err != nil {
				t.Fatal(err)
			}
			cfg := newCfg(t)
			cfg.StateDir = filepath.Join(theirs, "state")
			if _, err := Open(context.Background(), cfg); !errors.Is(err, ErrStateDirExposed) {
				t.Errorf("Open = %v, want ErrStateDirExposed", err)
			}
		})
	}
}

// A sticky world-writable directory such as /tmp is kept: another uid
// can make a name in it but cannot rename or remove one it does not own,
// so the directories below it that Open checks stay where they are.
// t.TempDir sits in one, so every other vm test opens through it too.
// Open also accepts a StateDir it makes from scratch below a checked
// parent, and one that already exists.
func TestOpenAcceptsAHeldStateDir(t *testing.T) {
	sticky := mode(t, filepath.Join(t.TempDir(), "sticky"), 0o777|os.ModeSticky)
	mine := mode(t, filepath.Join(sticky, "mine"), 0o755)
	for _, dir := range []string{filepath.Join(mine, "a", "b", "state"), mine} {
		cfg := newCfg(t)
		cfg.StateDir = dir
		for range 2 { // made, then reopened
			if _, err := Open(context.Background(), cfg); err != nil {
				t.Fatalf("Open(%s) = %v", dir, err)
			}
		}
	}
}

// mode makes dir with exactly perm (no umask) and returns it.
func mode(t *testing.T, dir string, perm os.FileMode) string {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, perm); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newCfg is newEnv's Config without opening it.
func newCfg(t *testing.T) Config {
	t.Helper()
	e := newEnv(t, 1024)
	return e.cfg
}

// snapshotTree lists every name under top with its mode.
func snapshotTree(t *testing.T, top string) string {
	t.Helper()
	var s string
	if err := filepath.Walk(top, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		s += p + " " + fi.Mode().String() + "; "
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s
}
