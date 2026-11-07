package vm

// REQ: KRN-2

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
		"other-writable parent": func(t *testing.T, top string) string {
			return mode(t, filepath.Join(top, "oth"), 0o757)
		},
		// machines and snapshots are checked too: a sticky world-writable
		// StateDir passes, so another uid could plant either as a link.
		"machines a link in a sticky StateDir": func(t *testing.T, top string) string {
			state := mode(t, filepath.Join(top, "state"), 0o777|os.ModeSticky)
			if err := os.Symlink(mode(t, filepath.Join(top, "elsewhere"), 0o700), filepath.Join(state, "machines")); err != nil {
				t.Fatal(err)
			}
			return top
		},
		"snapshots other-writable": func(t *testing.T, top string) string {
			state := mode(t, filepath.Join(top, "state"), 0o700)
			mode(t, filepath.Join(state, "machines"), 0o700)
			mode(t, filepath.Join(state, "snapshots"), 0o707)
			return top
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
		// The check and the mkdirs must act on one path: "l/.." is
		// l's target's parent to the kernel, not l's (Security on #4968).
		"dot-dot through a link": func(t *testing.T, top string) string {
			held := mode(t, filepath.Join(top, "held"), 0o700)
			pub := mode(t, filepath.Join(top, "pub"), 0o777)
			if err := os.Symlink(mode(t, filepath.Join(pub, "real"), 0o700), filepath.Join(held, "l")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(held, "l") + "/.."
		},
		"relative": func(t *testing.T, top string) string {
			t.Chdir(top)
			return "."
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
			dir := setup(t, top) + "/state"
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
			// uid 65534, gid 0: they differ, so an owner check that read the gid
			// would pass this path and fail the test.
			if err := os.Lchown(chown(top), 65534, 0); err != nil {
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

// The owner check without root: stateDirOwner reports a foreign uid (or
// none) for the directory named "theirs", so the refusal is pinned in
// every CI job, not only one that runs as root.
func TestOpenRefusesStateDirAForeignOwnerReports(t *testing.T) {
	foreign := uint32(65534)
	if os.Geteuid() == int(foreign) {
		foreign--
	}
	for name, tc := range map[string]struct {
		uid  uint32
		ok   bool
		path func(top string) string
	}{
		"parent another uid owns":   {foreign, true, func(top string) string { return filepath.Join(top, "theirs", "state") }},
		"StateDir another uid owns": {foreign, true, func(top string) string { return filepath.Join(top, "x", "theirs") }},
		"parent with no owner":      {0, false, func(top string) string { return filepath.Join(top, "theirs", "state") }},
	} {
		t.Run(name, func(t *testing.T) {
			top := mode(t, filepath.Join(t.TempDir(), "top"), 0o700)
			dir := tc.path(top)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			cfg := newCfg(t)
			cfg.StateDir = dir
			real := stateDirOwner
			t.Cleanup(func() { stateDirOwner = real })
			stateDirOwner = func(fi fs.FileInfo) (uint32, bool) {
				if fi.Name() == "theirs" {
					return tc.uid, tc.ok
				}
				return real(fi)
			}
			before := snapshotTree(t, top)
			if _, err := Open(context.Background(), cfg); !errors.Is(err, ErrStateDirExposed) {
				t.Errorf("Open = %v, want ErrStateDirExposed", err)
			}
			if after := snapshotTree(t, top); after != before {
				t.Errorf("Open changed the tree before refusing:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// An Lstat error other than a missing name is returned, not read past:
// a name longer than NAME_MAX fails Lstat with ENAMETOOLONG, as root too.
func TestOpenReturnsAStateDirLstatError(t *testing.T) {
	top := mode(t, filepath.Join(t.TempDir(), "top"), 0o700)
	cfg := newCfg(t)
	cfg.StateDir = filepath.Join(top, strings.Repeat("n", 300), "state")
	before := snapshotTree(t, top)
	if m, err := Open(context.Background(), cfg); !errors.Is(err, syscall.ENAMETOOLONG) || m != nil {
		t.Errorf("Open = %v, %v; want ENAMETOOLONG and no manager", m, err)
	}
	if after := snapshotTree(t, top); after != before {
		t.Errorf("Open changed the tree:\nbefore %s\nafter  %s", before, after)
	}
}

// Open checks again once all three directories exist, before its chmods
// follow their names: a snapshots swapped for a link after the mkdirs is
// refused, and the link's target keeps its mode.
func TestOpenRechecksStateDirsAfterMaking(t *testing.T) {
	top := mode(t, filepath.Join(t.TempDir(), "top"), 0o700)
	elsewhere := mode(t, filepath.Join(top, "elsewhere"), 0o755)
	cfg := newCfg(t)
	cfg.StateDir = filepath.Join(top, "state")
	t.Cleanup(func() { stateDirsMade = func() {} })
	stateDirsMade = func() {
		snaps := filepath.Join(cfg.StateDir, "snapshots")
		if err := os.Remove(snaps); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, snaps); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(context.Background(), cfg); !errors.Is(err, ErrStateDirExposed) {
		t.Errorf("Open = %v, want ErrStateDirExposed", err)
	}
	if fi, err := os.Stat(elsewhere); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("link target after Open: %v, %v; want mode 0755 unchanged", fi, err)
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
		// Open narrows all three to 0700, mine's 0755 included.
		for _, d := range []string{dir, filepath.Join(dir, "machines"), filepath.Join(dir, "snapshots")} {
			if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
				t.Errorf("%s after Open: %v, %v; want mode 0700", d, fi, err)
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
