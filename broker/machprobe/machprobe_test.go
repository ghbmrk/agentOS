package machprobe

// REQ: LOOP-7

import (
	"context"
	"os"
	"path/filepath"
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
