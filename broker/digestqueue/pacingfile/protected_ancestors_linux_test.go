//go:build linux

package pacingfile

import (
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// REQ: OP-1, CH-15
func TestProtectedLeaseRejectsInvalidTrustBeforeLockCreation(t *testing.T) {
	for _, kind := range []string{"nil", "empty", "duplicate", "overbound"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ledger")
			var owners []uint32
			switch kind {
			case "empty":
				owners = []uint32{}
			case "duplicate":
				owners = []uint32{uint32(os.Geteuid()), uint32(os.Geteuid())}
			case "overbound":
				for i := uint32(0); i < 17; i++ {
					owners = append(owners, i)
				}
			}
			if s, e := OpenExclusiveProtected(path, owners); s != nil || e != ErrStorage {
				if s != nil {
					s.Close()
				}
				t.Fatal("invalid trust admitted", e)
			}
			files, e := os.ReadDir(dir)
			if e != nil || len(files) != 0 {
				t.Fatal("invalid trust mutated filesystem", e)
			}
		})
	}
}

// REQ: OP-1, CH-15
func TestProtectedLeaseRejectsWritableAncestorsWithoutLegacyChange(t *testing.T) {
	for _, mode := range []os.FileMode{0770, 0777, os.ModeSticky | 0777} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			ancestor := filepath.Join(dir, "ancestor")
			if e := os.Mkdir(ancestor, 0700); e != nil {
				t.Fatal(e)
			}
			private := filepath.Join(ancestor, "private")
			if e := os.Mkdir(private, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(ancestor, mode); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(private, "ledger")
			owners := []uint32{0, uint32(os.Geteuid()), 65534}
			// Deduplicate synthetic fixture policy when test UID is root/nobody.
			seen := map[uint32]bool{}
			trusted := []uint32{}
			for _, u := range owners {
				if !seen[u] {
					seen[u] = true
					trusted = append(trusted, u)
				}
			}
			if s, e := OpenExclusiveProtected(path, trusted); s != nil || e != ErrStorage {
				if s != nil {
					s.Close()
				}
				t.Fatal("writable ancestor admitted", e)
			}
			if _, e := os.Stat(path + ".lock"); !os.IsNotExist(e) {
				t.Fatal("refusal created lock", e)
			}
			// Ordinary lease behavior remains unchanged; this does not qualify its custody.
			s, e := OpenExclusive(path)
			if e != nil {
				t.Fatal("legacy behavior changed", e)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// Positive fixtures need a protected ancestry. Explicit runner configuration
// wins; otherwise use the user's home. Fail rather than skip/fallback if unsafe.
func protectedFixture(t *testing.T) (string, []uint32) {
	t.Helper()
	base := os.Getenv("AGENTOS_PROTECTED_TEST_ROOT")
	if base == "" {
		var e error
		base, e = os.UserHomeDir()
		if e != nil {
			t.Fatal(e)
		}
	}
	dir, e := os.MkdirTemp(base, "agentos-protected-test-")
	if e != nil {
		t.Fatal("configure AGENTOS_PROTECTED_TEST_ROOT to a compatible writable root", e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	owners := []uint32{0, 65534, uint32(os.Geteuid())}
	seen := map[uint32]bool{}
	trusted := []uint32{}
	for _, u := range owners {
		if !seen[u] {
			seen[u] = true
			trusted = append(trusted, u)
		}
	}
	// These are explicit synthetic test trustees, not discovered production trust.
	return filepath.Join(dir, "ledger"), trusted
}

// REQ: OP-1, CH-15
func TestProtectedActualGateCopiesTrustAndStrictReopensDebt(t *testing.T) {
	path, owners := protectedFixture(t)
	s, e := OpenExclusiveProtected(path, owners)
	if e != nil {
		t.Fatal(e)
	}
	for i := range owners {
		owners[i] = 4294967295
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 2, PacingStore: s, PacingMaxStoreLatency: time.Second}
	g := grants.New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) {
		s.Close()
		t.Fatal("protected accounting/copy failed")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	_, trusted := protectedFixture(t)
	reopen, e := OpenExclusiveProtected(path, trusted)
	if e != nil {
		t.Fatal(e)
	}
	defer reopen.Close()
	cfg.PacingStore = reopen
	cfg.PacingRequireExisting = true
	g = grants.New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) || g.Reserve(false) {
		t.Fatal("spent debt lost")
	}
}

// REQ: OP-1, CH-15
func TestProtectedLaterAncestorPermissionFaultLatchesActualGate(t *testing.T) {
	path, owners := protectedFixture(t)
	ancestor := filepath.Dir(path)
	private := filepath.Join(ancestor, "private")
	if e := os.Mkdir(private, 0700); e != nil {
		t.Fatal(e)
	}
	path = filepath.Join(private, "ledger")
	s, e := OpenExclusiveProtected(path, owners)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	g := grants.New(grants.Config{Now: time.Now, RequestsPerHour: 2, PacingStore: s, PacingMaxStoreLatency: time.Second})
	if g.PacingHealth() != nil {
		t.Fatal("fixture init")
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(ancestor, 0770); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(ancestor, 0700)
	if g.Reserve(false) || g.Reserve(true) || g.PacingHealth() != grants.ErrPacingRecovery {
		t.Fatal("ancestor fault bypass")
	}
	if e = os.Chmod(ancestor, 0700); e != nil {
		t.Fatal(e)
	}
	if g.Reserve(true) || s.PacingHealth() == nil {
		t.Fatal("fault repaired itself")
	}
	after, e := os.ReadFile(path)
	if e != nil || string(after) != string(before) {
		t.Fatal("fault wrote accounting", e)
	}
}

// REQ: OP-1, CH-15
func TestProtectedRootAndOwnerMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		uid, mode uint32
		want      bool
	}{{"root-trusted", 65534, syscall.S_IFDIR | 0755, true}, {"untrusted", 42, syscall.S_IFDIR | 0755, false}, {"group-write", 65534, syscall.S_IFDIR | 0775, false}, {"sticky-other-write", 65534, syscall.S_IFDIR | 01777, false}, {"non-directory", 65534, syscall.S_IFREG | 0600, false}} {
		t.Run(tc.name, func(t *testing.T) {
			st := syscall.Stat_t{Uid: tc.uid, Mode: tc.mode}
			if protectedAncestor(&st, []uint32{65534}) != tc.want {
				t.Fatal("root/owner policy")
			}
		})
	}
}

// REQ: OP-1, CH-15
func TestProtectedUntrustedRootRefusesAndClosesTraversalFDs(t *testing.T) {
	path, _ := protectedFixture(t)
	before, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 40; i++ {
		if s, e := OpenExclusiveProtected(path, []uint32{4294967295}); s != nil || e != ErrStorage {
			if s != nil {
				s.Close()
			}
			t.Fatal("untrusted root admitted", e)
		}
	}
	after, e := os.ReadDir("/proc/self/fd")
	if e != nil || len(after) != len(before) {
		t.Fatal("traversal fd leak", len(before), len(after), e)
	}
	if _, e = os.Stat(path + ".lock"); !os.IsNotExist(e) {
		t.Fatal("root refusal created lock", e)
	}
}
