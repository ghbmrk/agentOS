package recall

// REQ: CAP-3, SEC-BAL-1, SEC-BAL-2

import (
	"os"
	"path/filepath"
	"testing"
)

// SEC-backs-append-latch: a FileStore append that fails leaves no part of
// its line behind, or the store refuses appends until it is rewritten, so
// a later line is never joined onto the remains of a failed one (which a
// reader skips as one bad line, losing the later line too).

func openAppendStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.jsonl")
	s, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Append([]byte("{\"a\":1}\n")); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func fileIs(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Fatalf("file %q, want %q", b, want)
	}
}

// A partial write is cut back to the end of the last good line, and the
// next append starts a line of its own (mutants: no cut; cut to 0).
func TestFailedAppendIsCutBack(t *testing.T) {
	s, path := openAppendStore(t)
	fault(s, func(f *faultFile) { f.keep = 3 })
	if err := s.Append([]byte("{\"b\":2}\n")); err == nil {
		t.Fatal("a partial write reported nothing")
	}
	fileIs(t, path, "{\"a\":1}\n")
	if err := s.Append([]byte("{\"c\":3}\n")); err != nil {
		t.Fatal(err)
	}
	fileIs(t, path, "{\"a\":1}\n{\"c\":3}\n")
}

// A line written whole but not synced is cut back too, so an error means
// the line is not in the store (mutant: cut only on a write error).
func TestFailedSyncIsCutBack(t *testing.T) {
	s, path := openAppendStore(t)
	fault(s, func(f *faultFile) { f.failSyncs = 1 })
	if err := s.Append([]byte("{\"b\":2}\n")); err == nil {
		t.Fatal("a failed sync reported nothing")
	}
	fileIs(t, path, "{\"a\":1}\n")
	if err := s.Append([]byte("{\"c\":3}\n")); err != nil {
		t.Fatal(err)
	}
	fileIs(t, path, "{\"a\":1}\n{\"c\":3}\n")
}

// A failed append that cannot be cut back latches the store: later
// appends fail, even once the disk works, until a Rewrite replaces the
// file (mutant: no latch).
func TestUncutAppendRefusesAppendsUntilRewrite(t *testing.T) {
	s, path := openAppendStore(t)
	f := fault(s, func(f *faultFile) { f.keep = 3; f.failTruncate = true })
	if err := s.Append([]byte("{\"b\":2}\n")); err == nil {
		t.Fatal("a partial write reported nothing")
	}
	s.f = f.File // the disk works again
	if err := s.Append([]byte("{\"c\":3}\n")); err == nil {
		t.Fatal("an append after an uncut failure was taken")
	}
	fileIs(t, path, "{\"a\":1}\n{\"b")
	if err := s.Rewrite([]byte("{\"a\":1}\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Append([]byte("{\"c\":3}\n")); err != nil {
		t.Fatalf("append after rewrite: %v", err)
	}
	fileIs(t, path, "{\"a\":1}\n{\"c\":3}\n")
}

// A cut that cannot be synced latches the store too (mutant: no latch on
// the cut's sync).
func TestUnsyncedCutRefusesAppends(t *testing.T) {
	s, _ := openAppendStore(t)
	f := fault(s, func(f *faultFile) { f.failSyncs = 2 })
	if err := s.Append([]byte("{\"b\":2}\n")); err == nil {
		t.Fatal("a failed sync reported nothing")
	}
	s.f = f.File
	if err := s.Append([]byte("{\"c\":3}\n")); err == nil {
		t.Fatal("an append after an unsynced cut was taken")
	}
}
