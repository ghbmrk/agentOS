package machprobe

// REQ: LOOP-7

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// LOOP-7 (tamper script): a writable file is overwritten, a writable
// directory gains a file, and a read-only or missing path is refused
// without stopping the round.
func TestTamperWritesWhatItCanAndCarriesOn(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "grader.json")
	os.WriteFile(f, []byte("{}"), 0o644)
	ro := filepath.Join(dir, "ro")
	os.Mkdir(ro, 0o555)
	paths := []string{f, dir, filepath.Join(dir, "missing", "x"), ro}
	want := 2
	if os.Geteuid() == 0 {
		want = 3 // root writes through mode bits
	}
	if n := Tamper(paths); n != want {
		t.Fatalf("accepted %d writes, want %d", n, want)
	}
	if b, _ := os.ReadFile(f); string(b) != Marker {
		t.Fatalf("file holds %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, ".agentos-tamper")); err != nil {
		t.Fatal(err)
	}
}

// LOOP-7 (pressure scripts): each kind holds for its duration, releases
// what it took, and an unknown kind is refused.
func TestPressHoldsEachKindThenReleases(t *testing.T) {
	dir := t.TempDir()
	o := Options{MemMB: 4, DiskMB: 2, Dir: dir, Procs: 3, Child: []string{"/bin/sleep", "30"}}
	if _, err := os.Stat(o.Child[0]); err != nil {
		t.Skip("no /bin/sleep")
	}
	for _, k := range Kinds {
		start := time.Now()
		if err := Press(context.Background(), k, 50*time.Millisecond, o); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if took := time.Since(start); took < 50*time.Millisecond || took > 5*time.Second {
			t.Fatalf("%s held %v", k, took)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("disk pressure left %v", ents)
	}
	if err := Press(context.Background(), "network", time.Millisecond, o); err == nil {
		t.Fatal("unknown pressure accepted")
	}
}
