//go:build linux

package pacingfile

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: CH-15, OP-1, OP-8
func TestLeaseRefusesSymbolicAncestorBeforeLockCreation(t *testing.T) {
	for _, kind := range []string{"outer", "middle", "chain"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			real := filepath.Join(root, "real")
			parent := filepath.Join(real, "inside", "private")
			if err := os.MkdirAll(parent, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(parent, "ledger")
			link := filepath.Join(root, "linked")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(link, "inside", "private", "ledger")
			switch kind {
			case "middle":
				link = filepath.Join(real, "linked")
				if err := os.Symlink(filepath.Join(real, "inside"), link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "private", "ledger")
			case "chain":
				chain := filepath.Join(root, "chain")
				if err := os.Symlink(link, chain); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(chain, "inside", "private", "ledger")
			}
			s, err := OpenExclusive(path)
			if s != nil {
				s.Close()
			}
			if s != nil || err != ErrStorage {
				t.Fatal("symbolic ancestor admitted", err)
			}
			if _, err = os.Stat(target + ".lock"); !os.IsNotExist(err) {
				t.Fatal("refused acquisition created lock", err)
			}
			if _, err = os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("refused acquisition initialized ledger", err)
			}
		})
	}
}

// REQ: CH-15, OP-1
func TestLeaseAncestorLinkBackLatchesActualGateWithoutChangingDebt(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "outer")
	parent := filepath.Join(outer, "private")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "ledger")
	s := openLease(t, path)
	now := time.Now()
	cfg := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 2, PacingStore: s, PacingMaxStoreLatency: time.Second}
	g := grants.New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) {
		t.Fatal("fixture initial debt")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(outer, outer+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outer+".old", outer); err != nil {
		t.Fatal(err)
	}
	// Final parent inode is unchanged; lookup policy changed. A path-only final
	// O_NOFOLLOW check would accept the ancestor symlink back to the held inode.
	b, err := s.Load()
	if b != nil || err != ErrStorage {
		t.Fatal("ancestor link to same inode accepted", err)
	}
	if g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(true) {
		t.Fatal("actual Gate bypassed held ancestor custody")
	}
	oldPath := filepath.Join(outer+".old", "private", "ledger")
	after, err := os.ReadFile(oldPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("fault changed debt", err)
	}
	if err = os.Remove(outer); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(outer+".old", outer); err != nil {
		t.Fatal(err)
	}
	if b, err = s.Load(); b != nil || err != ErrStorage {
		t.Fatal("live lease repaired after restoring ancestor", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	next := openLease(t, path)
	cfg.PacingStore = next
	cfg.PacingRequireExisting = true
	g = grants.New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) || g.Reserve(false) {
		t.Fatal("strict reopen reset debt")
	}
}

// REQ: OP-8, OP-1
func TestLeaseParentDepthLimitBeforeLockCreation(t *testing.T) {
	for _, depth := range []int{64, 65} {
		t.Run(strconv.Itoa(depth), func(t *testing.T) {
			dir := t.TempDir()
			current := len(strings.Split(strings.TrimPrefix(dir, "/"), "/"))
			if current >= 64 {
				t.Skip("test root already exceeds documented depth")
			}
			for current < depth {
				dir = filepath.Join(dir, "d")
				current++
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "ledger")
			s, err := OpenExclusive(path)
			if depth == 64 {
				if err != nil || s == nil {
					t.Fatal("exact depth cap refused", err)
				}
				if err = s.Save([]byte("synthetic-depth-boundary")); err != nil {
					s.Close()
					t.Fatal(err)
				}
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if s != nil {
					s.Close()
				}
				if s != nil || err != ErrStorage {
					t.Fatal("over-depth acquisition admitted", err)
				}
				if _, err = os.Stat(path + ".lock"); !os.IsNotExist(err) {
					t.Fatal("over-depth acquisition created lock", err)
				}
			}
		})
	}
}

// REQ: OP-8
func TestLeaseLongPathRefusedBeforeLockCreation(t *testing.T) {
	root := t.TempDir()
	dir := root
	// Each segment fits NAME_MAX and the parent fits PATH_MAX; only the entire
	// ledger path exceeds the new 4095-byte boundary. No symlink/missing dir excuse.
	targetParentLength := 4090
	for len(dir) < targetParentLength {
		remaining := targetParentLength - len(dir) - 1
		if remaining == 0 {
			break
		}
		n := remaining
		if n > 200 {
			n = 200
		}
		dir = filepath.Join(dir, strings.Repeat("a", n))
	}
	if len(dir) != targetParentLength {
		t.Fatal("fixture parent length", len(dir))
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger")
	if len(path) != 4097 {
		t.Fatal("fixture ledger length", len(path))
	}
	s, err := OpenExclusive(path)
	if s != nil {
		s.Close()
	}
	if s != nil || err != ErrStorage {
		t.Fatal("over-long ledger admitted", err)
	}
	// Full lock pathname exceeds PATH_MAX: observe through the actual parent fd.
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := privateAt(int(f.Fd()), "ledger.lock", true)
	if st != nil || err != nil {
		t.Fatal("over-long acquisition created lock", err)
	}
}

// REQ: OP-8, OP-1
func TestLeaseParentLookupFailuresDoNotLeakDescriptors(t *testing.T) {
	root := t.TempDir()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		if s, err := OpenExclusive(filepath.Join(root, "missing", "private", "ledger")); s != nil || err != ErrStorage {
			if s != nil {
				s.Close()
			}
			t.Fatal("failed lookup admitted", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+2 {
		t.Fatal("failed parent walks leaked descriptors", len(before), len(after))
	}
}

// REQ: OP-8, OP-1
func TestLeaseExactByteCapUsesAnchoredLedgerOperations(t *testing.T) {
	dir := t.TempDir()
	for len(dir) < 4090 {
		n := 4090 - len(dir) - 1
		if n > 200 {
			n = 200
		}
		if n < 1 {
			t.Fatal("fixture length")
		}
		dir = filepath.Join(dir, strings.Repeat("b", n))
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cell")
	if len(path) != 4095 {
		t.Fatal("exact byte fixture")
	}
	s := openLease(t, path)
	if err := s.Save([]byte("synthetic-exact-byte-cap")); err != nil {
		t.Fatal(err)
	}
	b, err := s.Load()
	if err != nil || string(b) != "synthetic-exact-byte-cap" {
		t.Fatal("exact byte cap I/O", err)
	}
}
