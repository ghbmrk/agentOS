//go:build linux

package pacingfile

import (
	"context"
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sessionFixture(t *testing.T) (string, grants.Config) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger")
	lease, err := OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := grants.Config{RequestsPerHour: 2, PacingStore: lease, PacingMaxStoreLatency: time.Second}
	if grants.New(cfg).PacingHealth() != nil {
		t.Fatal("synthetic provisioning")
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.PacingStore = nil
	cfg.PacingRequireExisting = true
	return path, cfg
}

// REQ: CH-15, CH-11
func TestSessionStrictConfigurationAndMissingState(t *testing.T) {
	path, cfg := sessionFixture(t)
	for _, bad := range []grants.Config{{}, {PacingRequireExisting: true}, {PacingRequireExisting: true, PacingMaxStoreLatency: 6 * time.Minute}, {PacingRequireExisting: true, PacingMaxStoreLatency: time.Second, PacingStore: &Store{Path: path}}} {
		if s, err := OpenSession(path, bad); s != nil || err != ErrSessionConfig {
			t.Fatal("unsafe session config", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if err = s.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(true) {
			t.Fatal("missing accounting accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing state initialized", err)
	}
}

// REQ: CH-15, CH-11, CH-2
func TestSessionRetiresBeforeDrainAndRetainsLeaseOnCancellation(t *testing.T) {
	path, cfg := sessionFixture(t)
	s, err := OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	entered := make(chan struct{})
	health := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		done <- s.Use(func(g *grants.Gate) error { close(entered); <-release; health <- g.PacingHealth(); return nil })
	}()
	<-entered
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		s.Close(context.Background())
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.Close(ctx); err != context.Canceled {
		t.Fatal("cancelled drain released lease", err)
	}
	if err = s.Use(func(*grants.Gate) error { t.Fatal("retired callback ran"); return nil }); err != ErrSessionRetired {
		t.Fatal(err)
	}
	if other, err := OpenExclusive(path); err == nil {
		other.Close()
		t.Fatal("lease released before user drain")
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-health; err != grants.ErrPacingRecovery {
		t.Fatal("retirement not visible before close", err)
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal("idempotent close", err)
	}
	other, err := OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
}

// REQ: CH-15
func TestSessionSharesOneGateAndPreservesDebtAcrossLeaseReopen(t *testing.T) {
	path, cfg := sessionFixture(t)
	s, err := OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	var first *grants.Gate // test-only identity; never used after its scopes.
	for i := 0; i < 2; i++ {
		if err = s.Use(func(g *grants.Gate) error {
			if first == nil {
				first = g
			}
			if first != g || !g.Reserve(false) {
				t.Fatal("Gate identity/debt")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Use(func(g *grants.Gate) error {
		if g.Reserve(false) {
			t.Fatal("fresh allowance")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close(context.Background())
	if err = s2.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || g.Reserve(false) {
			t.Fatal("reopen lost debt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// REQ: CH-11, CH-15
func TestSessionPanicReleasesRegistrationAndNilCallbackRefused(t *testing.T) {
	path, cfg := sessionFixture(t)
	s, err := OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Use(nil); err != ErrSessionConfig {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		s.Use(func(*grants.Gate) error { panic("synthetic") })
	}()
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
