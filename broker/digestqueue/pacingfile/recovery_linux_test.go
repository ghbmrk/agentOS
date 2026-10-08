//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/grants"
)

func recoveryFixture(t *testing.T) (string, []byte) {
	t.Helper()
	path, _ := sessionFixture(t)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".tmp", b, 0600); err != nil {
		t.Fatal(err)
	}
	return path, b
}
func assertRecoveryLedger(t *testing.T, path string, want []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(b, want) {
		t.Fatal("ledger changed", err)
	}
}

// REQ: CH-15, OP-1
func TestDuplicateRecoveryRequiresTotalSessionDrainAndPreservesDebt(t *testing.T) {
	path, cfg := sessionFixture(t)
	s, err := OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	image := make(chan []byte, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		s.Close(context.Background())
	})
	go func() {
		done <- s.Use(func(g *grants.Gate) error {
			if !g.Reserve(false) {
				return ErrStorage
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if e = os.WriteFile(path+".tmp", b, 0600); e != nil {
				return e
			}
			image <- b
			if g.Reserve(false) || g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(true) {
				return ErrStorage
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case e := <-done:
		t.Fatal("scope ended early", e)
	case <-t.Context().Done():
		t.Fatal("scope timeout")
	}
	b := <-image
	pin := sha256.Sum256(b)
	if e := DiscardDuplicateTemporary(path, pin); e != ErrStorage {
		t.Fatal("live session bypassed", e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e := s.Close(ctx); e != context.Canceled {
		t.Fatal(e)
	}
	if e := DiscardDuplicateTemporary(path, pin); e != ErrStorage {
		t.Fatal("incomplete drain bypassed", e)
	}
	assertRecoveryLedger(t, path, b)
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := s.Close(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e := DiscardDuplicateTemporary(path, pin); e != nil {
		t.Fatal(e)
	}
	assertRecoveryLedger(t, path, b)
	if _, e := os.Stat(path + ".tmp"); !os.IsNotExist(e) {
		t.Fatal("residue retained", e)
	}
	next, e := OpenSession(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close(context.Background())
	if e = next.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || !g.Reserve(false) || g.Reserve(false) {
			t.Fatal("spent debt changed")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

// REQ: OP-1, CH-15
func TestDuplicateRecoveryPinsAndBytesRefuseWithoutMutation(t *testing.T) {
	for _, kind := range []string{"zero-pin", "wrong-pin", "different", "partial", "missing-temp", "missing-ledger", "empty", "oversize-temp", "oversize-ledger"} {
		t.Run(kind, func(t *testing.T) {
			path, b := recoveryFixture(t)
			pin := sha256.Sum256(b)
			switch kind {
			case "zero-pin":
				pin = [32]byte{}
				os.Remove(path + ".lock")
			case "wrong-pin":
				pin = sha256.Sum256([]byte("synthetic-wrong-image"))
			case "different":
				if e := os.WriteFile(path+".tmp", []byte("synthetic-different"), 0600); e != nil {
					t.Fatal(e)
				}
			case "partial":
				if e := os.WriteFile(path+".tmp", b[:len(b)/2], 0600); e != nil {
					t.Fatal(e)
				}
			case "missing-temp":
				if e := os.Remove(path + ".tmp"); e != nil {
					t.Fatal(e)
				}
			case "missing-ledger":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case "empty":
				b = []byte{}
				pin = sha256.Sum256(b)
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path+".tmp", b, 0600); e != nil {
					t.Fatal(e)
				}
			case "oversize-temp", "oversize-ledger":
				name := path + ".tmp"
				if kind == "oversize-ledger" {
					name = path
				}
				f, e := os.OpenFile(name, os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if e = f.Truncate(grants.MaxPacingStateBytes + 1); e != nil {
					t.Fatal(e)
				}
				f.Close()
			}
			ledgerBefore, ledgerErr := os.ReadFile(path)
			tempBefore, tempErr := os.ReadFile(path + ".tmp")
			if e := DiscardDuplicateTemporary(path, pin); e != ErrStorage {
				t.Fatal("unsafe recovery", e)
			}
			after, e := os.ReadFile(path)
			if !bytes.Equal(after, ledgerBefore) || (e == nil) != (ledgerErr == nil) {
				t.Fatal("ledger mutation")
			}
			after, e = os.ReadFile(path + ".tmp")
			if !bytes.Equal(after, tempBefore) || (e == nil) != (tempErr == nil) {
				t.Fatal("temp mutation")
			}
			if kind == "zero-pin" {
				if _, e = os.Stat(path + ".lock"); !os.IsNotExist(e) {
					t.Fatal("pin checked after acquisition", e)
				}
			}
		})
	}
}

// REQ: OP-1, CH-15
func TestDuplicateRecoveryRefusesUnsafeTemporaryObjects(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "mode"} {
		t.Run(kind, func(t *testing.T) {
			path, b := recoveryFixture(t)
			if e := os.Remove(path + ".tmp"); e != nil {
				t.Fatal(e)
			}
			victim := filepath.Join(filepath.Dir(path), "synthetic-victim")
			if e := os.WriteFile(victim, b, 0600); e != nil {
				t.Fatal(e)
			}
			var e error
			switch kind {
			case "symlink":
				e = os.Symlink(victim, path+".tmp")
			case "hardlink":
				e = os.Link(victim, path+".tmp")
			case "fifo":
				e = syscall.Mkfifo(path+".tmp", 0600)
			case "mode":
				e = os.WriteFile(path+".tmp", b, 0644)
				if e == nil {
					e = os.Chmod(path+".tmp", 0644)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = DiscardDuplicateTemporary(path, sha256.Sum256(b)); e != ErrStorage {
				t.Fatal("unsafe object removed", e)
			}
			if _, e = os.Lstat(path + ".tmp"); e != nil {
				t.Fatal("unsafe object mutated", e)
			}
			assertRecoveryLedger(t, path, b)
			assertRecoveryLedger(t, victim, b)
		})
	}
}

// REQ: OP-1, CH-15
func TestDuplicateRecoveryExactReadCapAndSymbolicAncestor(t *testing.T) {
	t.Run("exact-cap", func(t *testing.T) {
		path, _ := recoveryFixture(t)
		image := bytes.Repeat([]byte("x"), grants.MaxPacingStateBytes)
		for _, name := range []string{path, path + ".tmp"} {
			if e := os.WriteFile(name, image, 0600); e != nil {
				t.Fatal(e)
			}
		}
		if e := DiscardDuplicateTemporary(path, sha256.Sum256(image)); e != nil {
			t.Fatal(e)
		}
		assertRecoveryLedger(t, path, image)
	})
	t.Run("symbolic-parent", func(t *testing.T) {
		path, b := recoveryFixture(t)
		alias := filepath.Join(t.TempDir(), "synthetic-alias")
		if e := os.Symlink(filepath.Dir(path), alias); e != nil {
			t.Fatal(e)
		}
		if e := DiscardDuplicateTemporary(filepath.Join(alias, filepath.Base(path)), sha256.Sum256(b)); e != ErrStorage {
			t.Fatal(e)
		}
		assertRecoveryLedger(t, path, b)
		temp, e := os.ReadFile(path + ".tmp")
		if e != nil || !bytes.Equal(temp, b) {
			t.Fatal("symlink recovery mutated residue", e)
		}
	})
}

// REQ: CH-15, OP-1
func TestDuplicateRecoveryDoesNotRepairMalformedLedger(t *testing.T) {
	path, cfg := sessionFixture(t)
	image := []byte("synthetic malformed accounting image")
	for _, name := range []string{path, path + ".tmp"} {
		if e := os.WriteFile(name, image, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := DiscardDuplicateTemporary(path, sha256.Sum256(image)); e != nil {
		t.Fatal(e)
	}
	s, e := OpenSession(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if e = s.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(false) || g.Reserve(true) {
			t.Fatal("byte cleanup bypassed invalid-input hold")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	assertRecoveryLedger(t, path, image)
}
