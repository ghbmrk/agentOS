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
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: CH-15, OP-1, OP-8
func TestAnchoredLeaseIOIgnoresLaterParentPathRedirect(t *testing.T) {
	path := leasePath(t)
	s := openLease(t, path)
	if err := s.Save([]byte("synthetic-original")); err != nil {
		t.Fatal(err)
	}
	// Model displacement AFTER the outer custody check but BEFORE actual I/O.
	// The internal operations run under the lease mutex, as their wrappers do.
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verifyLocked(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic-replacement-directory"), 0600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "synthetic-victim")
	if err := os.WriteFile(victim, []byte("synthetic-untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	b, err := s.loadAnchored()
	if err != nil || string(b) != "synthetic-original" {
		t.Fatal("read redirected", err)
	}
	if err = s.saveAnchored([]byte("synthetic-new")); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(dir+".old", filepath.Base(path)))
	if err != nil || string(old) != "synthetic-new" {
		t.Fatal("pinned directory lost", err)
	}
	for _, check := range []struct{ path, want string }{{path, "synthetic-replacement-directory"}, {victim, "synthetic-untouched"}} {
		got, err := os.ReadFile(check.path)
		if err != nil || string(got) != check.want {
			t.Fatal("replacement directory or victim modified", err)
		}
	}
	if s.verifyLocked() != ErrStorage || s.PacingHealth() != ErrStorage {
		t.Fatal("displaced custody did not latch")
	}
	// This fixture proves descriptor anchoring, not same-UID name/lock custody.
}

// REQ: CH-15, OP-1, OP-8
func TestExclusiveLeaseRefusesExistingPrivateTemporaryWithoutOverwrite(t *testing.T) {
	path := leasePath(t)
	s := openLease(t, path)
	if err := s.Save([]byte("synthetic-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", []byte("synthetic-orphan"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("synthetic-replacement")); err != ErrStorage {
		t.Fatal("existing temporary file reused", err)
	}
	for _, check := range []struct{ path, want string }{{path, "synthetic-original"}, {path + ".tmp", "synthetic-orphan"}} {
		b, err := os.ReadFile(check.path)
		if err != nil || string(b) != check.want {
			t.Fatal("existing image overwritten", err)
		}
	}
	if s.PacingHealth() != ErrStorage {
		t.Fatal("storage failure not latched")
	}
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("synthetic-repair")); err != ErrStorage {
		t.Fatal("live lease recovered", err)
	}
}

// REQ: OP-8, CH-15
func TestAnchoredLoadChecksActualOpenedDescriptor(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "symlink", "fifo", "mode", "hardlink", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			path := leasePath(t)
			s := openLease(t, path)
			switch kind {
			case "missing":
			case "symlink":
				if err := os.Symlink(path+".missing", path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "mode":
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(path, path+".other"); err != nil {
						t.Fatal(err)
					}
				case "oversize":
					if err := os.Truncate(path, int64(grants.MaxPacingStateBytes)+1); err != nil {
						t.Fatal(err)
					}
				}
			}
			s.mu.Lock()
			b, err := s.loadAnchored()
			s.mu.Unlock()
			if kind == "missing" {
				if b != nil || err != nil {
					t.Fatal("missing image distinction", err)
				}
				return
			}
			if kind == "empty" {
				if len(b) != 0 || b == nil || err != nil {
					t.Fatal("empty image distinction", err)
				}
				return
			}
			if b != nil || err != ErrStorage {
				t.Fatal("unsafe descriptor accepted", err)
			}
		})
	}
}

// REQ: CH-15, OP-1
func TestAnchoredSaveOverflowDoesNotCreateTemporary(t *testing.T) {
	path := leasePath(t)
	s := openLease(t, path)
	if err := s.Save([]byte("synthetic-original")); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	err := s.saveAnchored(make([]byte, grants.MaxPacingStateBytes+1))
	s.mu.Unlock()
	if err != ErrStorage {
		t.Fatal("over-cap write accepted", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "synthetic-original" {
		t.Fatal("overflow replaced ledger", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("overflow created temporary", err)
	}
}

// REQ: CH-15, OP-1
func TestManifestGateResidueHoldAndAnchoredDebtReopen(t *testing.T) {
	path, _ := sessionFixture(t)
	now := time.Now() // Capture after the inherited fixture provisions its ledger.
	image := manifestImage(t, path, 2, 1000)
	settings, err := ReadProvisionedManifest(bytes.NewReader(image), sha256.Sum256(image))
	if err != nil {
		t.Fatal(err)
	}
	var slot StartupSlot
	start, err := settings.Start(&slot, grants.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	<-start.done
	defer slot.Drain(context.Background())
	if err = start.Use(func(g *grants.Gate) error {
		if !g.Reserve(false) {
			t.Fatal("first reservation")
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path+".tmp", []byte("synthetic-orphan"), 0600); err != nil {
			t.Fatal(err)
		}
		if g.Reserve(true) || g.PacingHealth() != grants.ErrPacingRecovery {
			t.Fatal("temporary residue bypassed urgent hold")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("failed write changed ledger", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Trusted fixture recovery removes only its own synthetic orphan after drain.
	if err = os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	next, err := settings.Start(&slot, grants.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	<-next.done
	if err = next.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || !g.Reserve(false) || g.Reserve(false) {
			t.Fatal("strict reopen lost prior debt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
