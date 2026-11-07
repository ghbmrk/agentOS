package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
)

// REV-CHK-save (#4192): a checker-seed write that stops before its rename,
// as a crash would, fails and leaves the earlier boot's file whole and
// untouched (putCheckerSeed), and the unlock step then removes it
// (writeCheckerSeed), so the checker never starts on a stale seed.
// REQ: CH-4
func TestStoppedCheckerSeedWriteRemovesTheStaleSeed(t *testing.T) {
	d := t.TempDir()
	st, err := seal.Create(filepath.Join(d, "store"), seal.Recovery{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v, err := handoff.EncodeCodeSeed(handoff.CodeSeed{Seed: secret.Hide(bytes.Repeat([]byte{9}, 20))})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(handoff.CheckerSeedEntry, v); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(d, "mine")
	if err := os.Mkdir(mine, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(mine, "seed")
	root := &[32]byte{5}
	for step := 0; step < 4; step++ {
		if err := os.WriteFile(stale, []byte("an earlier boot's seed"), 0o600); err != nil {
			t.Fatal(err)
		}
		stop := func(i int) bool { return i == step }
		if err := putCheckerSeed(stale, st, root, stop); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: putCheckerSeed = %v, want ErrStopped", step, err)
		}
		if b, err := os.ReadFile(stale); err != nil || string(b) != "an earlier boot's seed" {
			t.Fatalf("step %d: a stopped write changed the earlier file: %q, %v", step, b, err)
		}
		writeCheckerSeed(stale, st, root, stop)
		if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("step %d: the stale seed was kept after a stopped write: %v", step, err)
		}
	}
	// The same store and root write a seed once the write goes through.
	if err := putCheckerSeed(stale, st, root, nil); err != nil {
		t.Fatal(err)
	}
}
