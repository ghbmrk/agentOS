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

// LOOP-7 (tamper script, P3-4b-4c-restore): every write is a new
// sibling named by the round's nonce, created exclusively: a file
// target's in its directory, a directory target's inside it. A target is
// never opened for writing, truncated or removed, so a writable grader
// keeps its bytes. A read-only or missing path is refused without
// stopping the round, a sibling already there is not overwritten, and a
// nonce that is not lowercase hex writes nothing.
func TestTamperWritesOnlyFreshSiblingsAndNeverTheTarget(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "grader.json")
	os.WriteFile(f, []byte(`{"pass":0.5}`), 0o644)
	suite := filepath.Join(dir, "suite")
	os.Mkdir(suite, 0o755)
	ro := filepath.Join(dir, "ro")
	os.Mkdir(ro, 0o755)
	roFile := filepath.Join(ro, "cases.json")
	os.WriteFile(roFile, []byte("[]"), 0o644)
	os.Chmod(ro, 0o555)
	t.Cleanup(func() { os.Chmod(ro, 0o755) })
	paths := []string{f, suite, filepath.Join(dir, "missing", "x"), filepath.Join(dir, "absent"), ro, roFile}
	want := 2
	if os.Geteuid() == 0 {
		want = 3 // root writes through mode bits
	}
	const n1, n2 = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	if n := Tamper(n1, paths); n != want {
		t.Fatalf("accepted %d writes, want %d", n, want)
	}
	if b, _ := os.ReadFile(f); string(b) != `{"pass":0.5}` {
		t.Fatalf("the file target was changed: %q", b)
	}
	for _, d := range []string{dir, suite} {
		b, err := os.ReadFile(filepath.Join(d, Sibling(n1)))
		if err != nil || string(b) != Marker+n1+"\n" {
			t.Fatalf("sibling in %s: %q %v", d, b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing path's parent was created")
	}
	// A sibling already there is not overwritten (O_EXCL).
	os.WriteFile(filepath.Join(suite, Sibling(n2)), []byte("kept"), 0o644)
	Tamper(n2, []string{suite})
	if b, _ := os.ReadFile(filepath.Join(suite, Sibling(n2))); string(b) != "kept" {
		t.Fatalf("an existing sibling was overwritten: %q", b)
	}
	for _, bad := range []string{"", "../x", "ABC", "0123/56789abcdef"} {
		if n := Tamper(bad, []string{suite}); n != 0 {
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

// REQ: LOOP-7, RES-2
//
// P3-4b-4c-bounds requirement 3 (Security README, "a guard fails open on
// a missing, invalid or out-of-range value"): Press refuses, at once and
// leaving nothing behind, a pressure it cannot apply: an unknown kind, a
// duration that is not positive, and for each kind an option that is
// unset, zero or negative (memory's MiB, which panicked when negative;
// disk's MiB and directory; processes' count and child command). On main
// all but the unknown kind and the missing child returned nil, so a
// guest log said it pressed when it did not (M1: logs only). fill
// refuses a size that is not positive.
func TestPressRefusesWhatItCannotPress(t *testing.T) {
	dir := t.TempDir()
	ok := Options{MemMB: 1, DiskMB: 1, Dir: dir, Procs: 1, Child: []string{"/bin/sleep", "30"}}
	for _, c := range []struct {
		name, kind string
		d          time.Duration
		set        func(o *Options)
	}{
		{"unknown kind", "network", time.Millisecond, nil},
		{"no kind", "", time.Millisecond, nil},
		{"zero duration", "cpu", 0, nil},
		{"negative duration", "memory", -time.Second, nil},
		{"zero memory", "memory", time.Millisecond, func(o *Options) { o.MemMB = 0 }},
		{"negative memory", "memory", time.Millisecond, func(o *Options) { o.MemMB = -1 }},
		{"zero disk", "disk", time.Millisecond, func(o *Options) { o.DiskMB = 0 }},
		{"negative disk", "disk", time.Millisecond, func(o *Options) { o.DiskMB = -1 }},
		{"no disk directory", "disk", time.Millisecond, func(o *Options) { o.Dir = "" }},
		{"zero processes", "processes", time.Millisecond, func(o *Options) { o.Procs = 0 }},
		{"negative processes", "processes", time.Millisecond, func(o *Options) { o.Procs = -1 }},
		{"no child", "processes", time.Millisecond, func(o *Options) { o.Child = nil }},
		{"empty child", "processes", time.Millisecond, func(o *Options) { o.Child = []string{""} }},
	} {
		o := ok
		if c.set != nil {
			c.set(&o)
		}
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = nil
					t.Errorf("%s: panicked: %v", c.name, r)
				}
			}()
			err = Press(context.Background(), c.kind, c.d, o)
		}()
		if err == nil {
			t.Errorf("%s: pressed", c.name)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("a refused press left %v", ents)
	}
	for _, mb := range []int{0, -1} {
		p := filepath.Join(dir, "fill")
		if err := fill(p, mb); err == nil {
			t.Errorf("fill %d MiB passed", mb)
		}
		if _, err := os.Stat(p); err == nil {
			t.Errorf("fill %d MiB created its file", mb)
		}
	}
}
