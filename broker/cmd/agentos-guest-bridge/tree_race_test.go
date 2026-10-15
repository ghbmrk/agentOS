//go:build linux

package main

// REQ: CHG-6, ARC-7

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TREE-symlink-race (#1732, #1728 R1): a guest process that swaps a
// directory on a tree path with a symlink while a sync runs cannot send
// a write or a removal into a directory of the tree directory outside the
// namespaces. The swap is renameat2(RENAME_EXCHANGE), so the name is
// always a directory or the link, never missing; each case runs many
// syncs against a flipper and then checks other, the directory the link
// points at.
func TestBridgeMirrorSurvivesASymlinkSwapRace(t *testing.T) {
	for _, tc := range []struct {
		name string
		real string // the directory the flipper exchanges with the link
		link string // the link's name, beside real
		to   string // the link's target
		seed []string
		// other's own files: a sync must leave exactly these.
		other []string
		files map[string][]byte
	}{
		// Security delta review of #1728, finding 1: a namespace swapped
		// while a tree with no file in it is synced; the removal walk must
		// not enumerate other.
		{"namespace with no file in the tree", "skills", "sl", "other",
			[]string{"skills/old"}, []string{"keep"},
			map[string][]byte{"procedures/p": []byte("p")}},
		// A directory below a namespace: the removal walk must not delete
		// other's files, and the write must not land in other.
		{"directory under a namespace", "skills/a", "skills/sl", "../other",
			[]string{"skills/a/z"}, []string{"keep", "z"},
			map[string][]byte{"skills/a/new": []byte("n"), "skills/b": []byte("b")}},
		// clearWay: a directory where the tree needs a file is removed
		// whole; the removal must not follow a swapped ancestor into other.
		{"directory in a file's way", "skills/a", "skills/sl", "../other",
			[]string{"skills/a/x/k"}, []string{"keep", "x/keep"},
			map[string][]byte{"skills/a/x": []byte("x")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deadline := time.Now().Add(2 * time.Second)
			for run := 0; run < 400 || time.Now().Before(deadline) && run < 3000; run++ {
				dir := t.TempDir()
				for _, p := range tc.seed {
					mustWrite(t, filepath.Join(dir, p))
				}
				for _, p := range tc.other {
					mustWrite(t, filepath.Join(dir, "other", p))
				}
				real, link := filepath.Join(dir, tc.real), filepath.Join(dir, tc.link)
				if err := os.Symlink(tc.to, link); err != nil {
					t.Fatal(err)
				}
				stop := make(chan struct{})
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						unix.Renameat2(unix.AT_FDCWD, real, unix.AT_FDCWD, link, unix.RENAME_EXCHANGE)
					}
				}()
				mirror(dir, tc.files) // a refusal is fine; what it touched is not
				close(stop)
				wg.Wait()
				if got := listFiles(t, filepath.Join(dir, "other")); !slices.Equal(got, sorted(tc.other)) {
					t.Fatalf("run %d: other holds %v, want %v: the sync reached outside the namespaces", run, got, sorted(tc.other))
				}
			}
		})
	}
}

func mustWrite(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// listFiles lists the regular files below dir, relative to it, sorted.
func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			r, _ := filepath.Rel(dir, p)
			out = append(out, r)
		}
		return nil
	})
	slices.Sort(out)
	return out
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
