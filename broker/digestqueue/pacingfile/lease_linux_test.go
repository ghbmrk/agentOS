package pacingfile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

func leasePath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "pacing")
}
func openLease(t *testing.T, path string) *ExclusiveStore {
	t.Helper()
	s, err := OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// REQ: CH-15, OP-1
func TestLeaseExcludesIndependentOpenAndChildProcess(t *testing.T) {
	path := leasePath(t)
	s := openLease(t, path)
	if other, err := OpenExclusive(path); other != nil || err != ErrStorage {
		if other != nil {
			other.Close()
		}
		t.Fatal("second writer admitted", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLeaseChildProcessProbe$")
	cmd.Env = append(os.Environ(), "AGENTOS_SYNTHETIC_LEASE_PATH="+path)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child exclusion: %v %s", err, b)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	openLease(t, path)
}
func TestLeaseChildProcessProbe(t *testing.T) {
	path := os.Getenv("AGENTOS_SYNTHETIC_LEASE_PATH")
	if path == "" {
		t.Skip("subprocess-only lease probe")
	}
	if s, err := OpenExclusive(path); s != nil || err != ErrStorage {
		if s != nil {
			s.Close()
		}
		t.Fatal("parent lease not excluded", err)
	}
}

// REQ: CH-15, OP-8
func TestLeaseRefusesUnsafeDirectoryAndLockMetadata(t *testing.T) {
	for _, kind := range []string{"relative", "reserved-lock", "reserved-temp", "directory-mode", "directory-link", "lock-mode", "lock-link", "lock-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path := leasePath(t)
			switch kind {
			case "relative":
				path = "synthetic-relative-ledger"
			case "reserved-lock":
				path += ".lock"
			case "reserved-temp":
				path += ".tmp"
			case "directory-mode":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "directory-link":
				link := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(filepath.Dir(path), link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "pacing")
			default:
				target := path + ".lock"
				if err := os.WriteFile(target, []byte{}, 0600); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "lock-mode":
					os.Chmod(target, 0644)
				case "lock-link":
					os.Remove(target)
					os.Symlink(path+".absent", target)
				case "lock-hardlink":
					if err := os.Link(target, path+".other"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if s, err := OpenExclusive(path); s != nil || err != ErrStorage {
				if s != nil {
					s.Close()
				}
				t.Fatal("unsafe lease admitted", err)
			}
		})
	}
}

// REQ: CH-15, OP-8
func TestLeaseRefusesUnsafeLedgerAndTempWithoutChangingTargets(t *testing.T) {
	for _, kind := range []string{"ledger-mode", "ledger-hardlink", "temp-link", "temp-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path := leasePath(t)
			s := openLease(t, path)
			if err := s.Save([]byte("synthetic-original")); err != nil {
				t.Fatal(err)
			}
			target := path
			if kind == "temp-link" || kind == "temp-hardlink" {
				target = path + ".tmp"
			}
			switch kind {
			case "ledger-mode":
				os.Chmod(path, 0644)
			case "ledger-hardlink":
				os.Link(path, path+".other")
			case "temp-link":
				os.Symlink(path, target)
			case "temp-hardlink":
				os.Link(path, target)
			}
			if err := s.Save([]byte("synthetic-replacement")); err != ErrStorage {
				t.Fatal("unsafe file admitted", err)
			}
			b, err := os.ReadFile(path)
			if err != nil || string(b) != "synthetic-original" {
				t.Fatal("unsafe path changed state", err)
			}
			os.Remove(path + ".tmp")
			os.Remove(path + ".other")
			os.Chmod(path, 0600)
			if err := s.Save([]byte("synthetic-replacement")); err != ErrStorage {
				t.Fatal("faulted lease repaired live", err)
			}
		})
	}
}

// REQ: CH-15, OP-1
func TestLeaseReplacementLatchesAndPreservesBytes(t *testing.T) {
	for _, kind := range []string{"parent", "lock"} {
		t.Run(kind, func(t *testing.T) {
			path := leasePath(t)
			s := openLease(t, path)
			if err := s.Save([]byte("synthetic-original")); err != nil {
				t.Fatal(err)
			}
			if kind == "parent" {
				dir := filepath.Dir(path)
				if err := os.Rename(dir, dir+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(path+".lock", path+".lock.old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if b, err := s.Load(); b != nil || err != ErrStorage {
				t.Fatal("replaced custody accepted", err)
			}
			if err := s.Save([]byte("synthetic-replacement")); err != ErrStorage {
				t.Fatal("replacement restored live lease", err)
			}
		})
	}
}

// REQ: CH-15, OP-1
func TestLeaseStrictGateReopenRetainsDebtAndClosedStoreRefuses(t *testing.T) {
	path := leasePath(t)
	s := openLease(t, path)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 1, PacingStore: s, PacingMaxStoreLatency: time.Second}
	g := grants.New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) {
		t.Fatal("fixture provision/reservation")
	}
	// No live operations/permissions remain in this fixture before release.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Load(); b != nil || err != ErrStorage {
		t.Fatal("closed store read", err)
	}
	if err := s.Save([]byte("synthetic")); err != ErrStorage {
		t.Fatal("closed store wrote", err)
	}
	next := openLease(t, path)
	cfg.PacingStore = next
	cfg.PacingRequireExisting = true
	g = grants.New(cfg)
	if g.PacingHealth() != nil || g.Reserve(false) {
		t.Fatal("lease reopen reset spent debt")
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatal("lock inode removed", err)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("writer left temp file", err)
	}
}
