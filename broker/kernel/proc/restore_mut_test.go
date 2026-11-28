package proc

// REQ: BAK-1
//
// MUT-kill-6305-proc (#6367): a restore's failure paths and syncs, each
// checked by what it returns, what it puts in place and what it syncs.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// fakeSections hands a restore its sections in order, then ends with end
// (io.EOF for a whole object).
type fakeSections struct {
	secs []backup.Section
	body [][]byte
	end  error
}

func (f *fakeSections) Next() (backup.Section, io.Reader, error) {
	if len(f.secs) == 0 {
		return backup.Section{}, nil, f.end
	}
	s, b := f.secs[0], f.body[0]
	f.secs, f.body = f.secs[1:], f.body[1:]
	return s, bytes.NewReader(b), nil
}

func sectionsOf(end error, nb ...any) *fakeSections {
	f := &fakeSections{end: end}
	for i := 0; i < len(nb); i += 2 {
		f.secs = append(f.secs, backup.Section{Name: nb[i].(string)})
		f.body = append(f.body, nb[i+1].([]byte))
	}
	return f
}

// syncs records the path of every directory synced while it runs, and fails
// those fail names.
func syncs(t *testing.T, fail func(string) bool) func() []string {
	var mu sync.Mutex
	var got []string
	was := privfile.SyncFile
	privfile.SyncFile = func(d *os.File) error {
		mu.Lock()
		got = append(got, d.Name())
		mu.Unlock()
		if fail != nil && fail(d.Name()) {
			return errFault
		}
		return was(d)
	}
	t.Cleanup(func() { privfile.SyncFile = was })
	return func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(got) }
}

// A whole restore puts each store, an empty one too, in place under the
// content folder and nothing for the log section; it syncs every store,
// the staging and the parent; an item of exactly maxSealed bytes goes back.
func TestARestoreSyncsEveryStoreAndTheParent(t *testing.T) {
	parent := t.TempDir()
	content := filepath.Join(parent, "content")
	big := bytes.Repeat([]byte{5}, maxSealed)
	got := syncs(t, nil)
	err := restoreSections(sectionsOf(io.EOF, "log", []byte("log"), "content/mail", []byte{},
		"content/vision", frame(big, uint32(len(big)))), io.Discard, content, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := names(t, content); !slices.Equal(n, []string{"mail", "vision"}) {
		t.Fatalf("the content folder holds %q, want mail and vision", n)
	}
	if n := names(t, filepath.Join(content, "vision")); !slices.Equal(n, []string{itemName(sha256.Sum256(big))}) {
		t.Fatalf("vision holds %q", n)
	}
	var mail, stage, par int
	for _, d := range got() {
		switch {
		case strings.HasSuffix(d, "/mail") && strings.Contains(d, restoreStage):
			mail++
		case filepath.Dir(d) == parent && strings.HasPrefix(filepath.Base(d), restoreStage):
			stage++
		case d == parent:
			par++
		}
	}
	if mail != 1 || stage != 1 || par != 1 {
		t.Fatalf("synced the empty store %d, the staging %d and the parent %d times, want each once: %q", mail, stage, par, got())
	}
}

// A section the object cannot give, a staging that cannot be made or
// synced, stops the restore with that error and puts nothing in place.
func TestARestoreStopsOnASectionItCannotRead(t *testing.T) {
	parent := t.TempDir()
	content := filepath.Join(parent, "content")
	err := restoreSections(sectionsOf(errFault, "log", []byte("log")), io.Discard, content, nil)
	if !errors.Is(err, errFault) {
		t.Fatalf("a section the object cannot give: %v, want its error", err)
	}
	syncs(t, func(d string) bool { return strings.Contains(d, restoreStage) && !strings.Contains(d, "/vision") })
	ct := []byte("an item")
	err = restoreSections(sectionsOf(io.EOF, "content/vision", frame(ct, uint32(len(ct)))), io.Discard, content, nil)
	if !errors.Is(err, errFault) {
		t.Fatalf("a staging that does not sync: %v, want the sync's error", err)
	}
	if _, err := os.Stat(content); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the content folder is in place: %v", err)
	}
}

// A parent the restore cannot make its staging in stops it.
func TestARestoreStopsWhenItCannotStage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the modes; CI runs these as a plain user")
	}
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, restoreLock), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	err := restoreSections(sectionsOf(io.EOF, "log", []byte("log")), io.Discard, filepath.Join(parent, "content"), nil)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a parent closed to the staging: %v, want a permission error", err)
	}
}
