package recall

// REQ: CAP-3

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/durable"
)

// dirSyncFault swaps the segment write and reopen seams for one test:
// mode "sync" replaces the file then fails the directory sync, "pre" fails
// before the rename, "reopen" replaces the file and fails its reopen.
type dirSyncFault struct {
	mode  string
	fired int
}

func injectRewriteFault(t *testing.T) *dirSyncFault {
	t.Helper()
	f := &dirSyncFault{}
	w, o := writeSegment, openSegment
	t.Cleanup(func() { writeSegment, openSegment = w, o })
	reopening := false
	writeSegment = func(p string, data []byte, perm os.FileMode) error {
		switch f.mode {
		case "pre":
			return errors.New("injected: disk full")
		case "sync":
			f.fired++
			if err := w(p, data, perm); err != nil {
				return err
			}
			return fmt.Errorf("%w: injected", durable.ErrDirSync)
		case "reopen":
			reopening = true
		}
		return w(p, data, perm)
	}
	openSegment = func(p string, flag int, perm os.FileMode) (*os.File, error) {
		if reopening && f.mode == "reopen" {
			return nil, errors.New("injected: too many open files")
		}
		return o(p, flag, perm)
	}
	return f
}

func segFiles(t *testing.T, path string) string {
	t.Helper()
	names, _ := filepath.Glob(filepath.Join(path, "seg-*.jsonl"))
	var all []byte
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return string(all)
}

// A segment rewrite that renames the new file into place and then fails
// the directory sync, or cannot reopen it, has still replaced the bytes:
// the index must follow the new layout, so live notes stay readable at
// once, after the retry from prune or the next deletion, and after a
// restart, and the deleted note is erased (CAP-3, #1318).
func TestRewriteAfterRenameKeepsLiveNotes(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		repeat     bool // the fault persists across retries before clearing
		failClosed bool // reads of the segment fail rather than read stale offsets
	}{
		{"dir sync fails", "sync", false, false},
		{"dir sync fails repeatedly", "sync", true, false},
		{"fails before rename", "pre", false, false},
		{"fails before rename repeatedly", "pre", true, false},
		{"reopen fails", "reopen", false, true},
		{"reopen fails repeatedly", "reopen", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir()
			st, err := OpenDir(path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
			clock := WithClock(func() time.Time { return now })
			ix := open(t, st, WithKeyer(testKeyer(t)), clock)
			gone := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<gone@x>"}, Text: "quokkacanary synthetic deleted note"})
			var live []string
			for i := 0; i < 5; i++ {
				live = append(live, mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: fmt.Sprintf("/n%d", i)}, Text: fmt.Sprintf("live note %d", i)}))
			}
			readable := func(when string) {
				t.Helper()
				for i, id := range live {
					it, ok := ix.Get(id)
					if !ok || it.Text != fmt.Sprintf("live note %d", i) {
						t.Fatalf("%s: live note %d unreadable", when, i)
					}
				}
			}
			f := injectRewriteFault(t)
			f.mode = tc.mode
			if _, err := ix.Delete(gone); err == nil {
				t.Fatal("an unfinished erase must be reported")
			}
			if _, ok := ix.Get(gone); ok {
				t.Fatal("deleted note still readable")
			}
			if tc.failClosed {
				for _, id := range live {
					if _, ok := ix.Get(id); ok {
						t.Fatal("a segment that could not be reopened must fail closed")
					}
				}
			} else {
				readable("after the failed rewrite")
			}
			now = now.Add(40 * 24 * time.Hour)
			if tc.repeat {
				if _, err := ix.PruneTombstones(30 * 24 * time.Hour); err == nil {
					t.Fatal("tombstones pruned while the erase is unfinished")
				}
				if !tc.failClosed {
					readable("after a failed retry")
				}
			}
			f.mode = ""
			if _, err := ix.PruneTombstones(30 * 24 * time.Hour); err != nil {
				t.Fatal(err)
			}
			readable("after prune")
			if strings.Contains(segFiles(t, path), "quokkacanary") {
				t.Fatal("deleted note left in a segment")
			}
			// New notes still land and read back.
			extra := mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: "/extra"}, Text: "extra note"})
			if it, ok := ix.Get(extra); !ok || it.Text != "extra note" {
				t.Fatal("note written after the retry unreadable")
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = OpenDir(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			ix = open(t, st, WithKeyer(testKeyer(t)), clock)
			readable("after restart")
			if _, ok := ix.Get(extra); !ok || ix.Len() != len(live)+1 {
				t.Fatalf("after restart: %d items", ix.Len())
			}
		})
	}
}

// The same holds for a compaction of a mostly superseded segment: a dir
// sync failure after the rename leaves every live note readable, before
// and after the retry and a restart.
func TestCompactionDirSyncKeepsLiveNotes(t *testing.T) {
	smallSegments(t, 70)
	path := t.TempDir()
	st, err := OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	clock := WithClock(func() time.Time { return now })
	ix := open(t, st, WithKeyer(testKeyer(t)), clock)
	src := func(i int) Source { return Source{Kind: "file", Ref: fmt.Sprintf("/c%d", i)} }
	ids := make([]string, 71)
	for i := range ids {
		ids[i] = mustIngest(t, ix, Item{Source: src(i), Text: fmt.Sprintf("first %d", i)})
	}
	want := func(i int) string {
		if i < 40 {
			return fmt.Sprintf("second %d", i)
		}
		return fmt.Sprintf("first %d", i)
	}
	readable := func(when string) {
		t.Helper()
		for i, id := range ids {
			if it, ok := ix.Get(id); !ok || it.Text != want(i) {
				t.Fatalf("%s: note %d unreadable", when, i)
			}
		}
	}
	f := injectRewriteFault(t)
	f.mode = "sync"
	// A failed compaction is not an ingest error: later writes retry it.
	for i := 0; i < 40; i++ {
		mustIngest(t, ix, Item{Source: src(i), Text: want(i)})
	}
	if f.fired == 0 {
		t.Fatal("test needs a compaction whose dir sync fails")
	}
	readable("after the failed compaction")
	f.mode = ""
	now = now.Add(40 * 24 * time.Hour)
	if _, err := ix.PruneTombstones(30 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	readable("after the retry")
	if strings.Contains(segFiles(t, path), `"first 0"`) {
		t.Fatal("compaction kept a superseded version")
	}
	st.Close()
	if st, err = OpenDir(path); err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ix = open(t, st, WithKeyer(testKeyer(t)), clock)
	readable("after restart")
}
