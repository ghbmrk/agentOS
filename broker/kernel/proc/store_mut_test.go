package proc

// REQ: LOG-1
//
// MUT-kill-6305-proc (#6367): the log file's size and truncate, each checked
// by what it returns and what it syncs.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Truncate takes any length from 0 to the file's size and syncs it, refuses
// one past either end, and a log it cannot stat answers an error for both
// calls.
func TestTruncateTakesEveryLengthInTheFileAndSyncs(t *testing.T) {
	s, err := OpenFileStore(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f := &faultFile{File: s.f.(*os.File), failAfter: -1}
	s.f = f
	if err := s.Append([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{-1, 7} {
		if err := s.Truncate(n); !errors.Is(err, kernel.ErrCorrupt) {
			t.Fatalf("truncate to %d of 6: %v, want ErrCorrupt", n, err)
		}
	}
	for _, n := range []int{6, 3, 0} {
		before := f.syncs
		if err := s.Truncate(n); err != nil || f.syncs != before+1 {
			t.Fatalf("truncate to %d: %v, %d syncs; want one", n, err, f.syncs-before)
		}
		if size, err := s.Size(); err != nil || size != int64(n) {
			t.Fatalf("size after truncate to %d: %d %v", n, size, err)
		}
	}
	f.File.Close()
	if _, err := s.Size(); err == nil {
		t.Fatal("size of a closed log: no error")
	}
	if err := s.Truncate(0); err == nil {
		t.Fatal("truncate of a closed log: no error")
	}
}
