package machprobe

// REQ: LOOP-7

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// LOOP-7 (tamper script): a writable file is overwritten with the round's
// marker, a writable directory gains a file named by it, and a read-only
// or missing path is refused without stopping the round. Another round's
// nonce writes different bytes; a nonce that is not lowercase hex writes
// nothing.
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
	const n1, n2 = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	if n := Tamper(n1, paths); n != want {
		t.Fatalf("accepted %d writes, want %d", n, want)
	}
	first, _ := os.ReadFile(f)
	if string(first) != Marker+n1+"\n" {
		t.Fatalf("file holds %q", first)
	}
	if _, err := os.Stat(filepath.Join(dir, ".agentos-tamper-"+n1)); err != nil {
		t.Fatal(err)
	}
	Tamper(n2, paths)
	if b, _ := os.ReadFile(f); string(b) == string(first) {
		t.Fatal("a new round's nonce wrote the same bytes")
	}
	for _, bad := range []string{"", "../x", "ABC", "0123/56789abcdef"} {
		if n := Tamper(bad, []string{dir}); n != 0 {
			t.Fatalf("nonce %q accepted %d writes", bad, n)
		}
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

// REQ: ARC-2
//
// P3-4b-3r-env requirement 3: a process-pressure child starts with an
// empty environment, not the caller's (#548 Security 4a point 4).
func TestPressChildrenInheritNoEnvironment(t *testing.T) {
	const canary = "agentos-machprobe-canary"
	t.Setenv("AGENTOS_MACHPROBE_CANARY", canary)
	dir := t.TempDir()
	out := filepath.Join(dir, "env")
	o := Options{Dir: dir, Procs: 1, Child: []string{"/bin/sh", "-c", "{ /usr/bin/env; echo END; } >" + out + ".tmp && /bin/mv " + out + ".tmp " + out + " && exec /bin/sleep 30"}}
	for _, p := range []string{"/bin/sh", "/usr/bin/env", "/bin/mv", "/bin/sleep"} {
		if _, err := os.Stat(p); err != nil {
			t.Skip("no " + p)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Press(ctx, "processes", time.Minute, o) }()
	var got []byte
	var err error
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if got, err = os.ReadFile(out); err == nil {
			break
		}
	}
	cancel()
	if perr := <-done; perr != nil {
		t.Fatal(perr)
	}
	if err != nil {
		t.Fatalf("the child wrote no environment: %v", err)
	}
	if strings.Contains(string(got), canary) {
		t.Fatalf("child inherits the caller's environment:\n%s", got)
	}
}
