//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"strings"
	"testing"
	"time"
)

// REQ: CH-11, CH-15
func TestSessionConstructorPanicReleasesItsActualLease(t *testing.T) {
	path, cfg := sessionFixture(t)
	cfg.Now = func() time.Time { panic("synthetic private clock canary") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("constructor panic missing")
			}
		}()
		OpenSession(path, cfg)
	}()
	lease, err := OpenExclusive(path)
	if err != nil {
		t.Fatal("failed constructor retained lease", err)
	}
	lease.Close()
}

// REQ: CH-11, CH-15, OP-1, OP-2
func TestStartupRetirementDuringActualBlockedGateConstructor(t *testing.T) {
	path, cfg := sessionFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	cfg.Now = func() time.Time { close(entered); <-release; return time.Now() }
	p, err := StartSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		p.Close(context.Background())
	})
	<-entered
	if p.State() != StartupOpening || p.Use(func(*grants.Gate) error { t.Fatal("published incomplete Gate"); return nil }) != ErrSessionOpening {
		t.Fatal("constructor not held")
	}
	if other, err := OpenExclusive(path); err == nil {
		other.Close()
		t.Fatal("blocked constructor lost custody")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = p.Close(ctx); err != context.Canceled {
		t.Fatal("cancelled constructor wait", err)
	}
	if p.State() != StartupRetired || p.Use(func(*grants.Gate) error { t.Fatal("retired callback ran"); return nil }) != ErrSessionRetired {
		t.Fatal("retirement waited for constructor")
	}
	if other, err := OpenExclusive(path); err == nil {
		other.Close()
		t.Fatal("retirement released blocked constructor lease")
	}
	close(release)
	if err = p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retired constructor wrote accounting", err)
	}
	if other, err := OpenExclusive(path); err != nil {
		t.Fatal("late retired result not cleaned", err)
	} else {
		other.Close()
	}
	if p.Use(func(*grants.Gate) error { t.Fatal("late result published"); return nil }) != ErrSessionRetired {
		t.Fatal("retirement reset")
	}
}

// REQ: CH-15, OP-1, OP-2
func TestStartupReadySharesSessionAndDoesNotReserveAutomatically(t *testing.T) {
	path, cfg := sessionFixture(t)
	p, err := StartSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	<-p.done
	if p.State() != StartupReady {
		t.Fatal("healthy constructor failed", p.State())
	}
	if err = p.Use(func(g *grants.Gate) error {
		if !g.Reserve(false) || !g.Reserve(false) || g.Reserve(false) {
			t.Fatal("startup consumed or reset allowance")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close(context.Background())
	if err = next.Use(func(g *grants.Gate) error {
		if g.Reserve(false) {
			t.Fatal("startup session debt lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// REQ: CH-11, CH-15
func TestStartupContainsConstructorFailureAndPanicWithoutPrivateDisclosure(t *testing.T) {
	for _, kind := range []string{"path", "panic"} {
		t.Run(kind, func(t *testing.T) {
			path, cfg := sessionFixture(t)
			original := path
			if kind == "path" {
				path += "/synthetic-private-canary"
			} else {
				cfg.Now = func() time.Time { panic("synthetic-private-canary") }
			}
			p, err := StartSession(path, cfg)
			if err != nil {
				t.Fatal(err)
			}
			<-p.done
			if p.State() != StartupRecovery || p.Use(func(*grants.Gate) error { t.Fatal("failed constructor exposed Gate"); return nil }) != ErrSessionRecovery {
				t.Fatal("failure not held")
			}
			if strings.Contains(p.State().Line(), "canary") || strings.Contains(ErrSessionRecovery.Error(), original) {
				t.Fatal("private failure disclosed")
			}
			if err = p.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			lease, err := OpenExclusive(original)
			if err != nil {
				t.Fatal("constructor failure leaked custody", err)
			}
			lease.Close()
		})
	}
}

// REQ: CH-15, OP-1
func TestStartupRejectsInvalidConfigurationBeforeLaunching(t *testing.T) {
	path, _ := sessionFixture(t)
	if p, err := StartSession(path, grants.Config{}); p != nil || err != ErrSessionConfig {
		t.Fatal("invalid config launched", err)
	}
	var zero Startup
	if zero.State() != StartupRecovery || zero.Use(func(*grants.Gate) error { return nil }) != ErrSessionConfig || zero.Close(context.Background()) != ErrSessionConfig {
		t.Fatal("zero startup usable")
	}
}

// REQ: CH-11, CH-15
func TestStartupMissingLedgerExposesOnlyFaultedScopedRecoveryGate(t *testing.T) {
	path, cfg := sessionFixture(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	p, err := StartSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	<-p.done
	if p.State() != StartupRecovery {
		t.Fatal("missing ledger not held")
	}
	if err = p.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(true) {
			t.Fatal("missing ledger accepted")
		}
		return nil
	}); err != nil {
		t.Fatal("recovery controls cannot access faulted Gate", err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("startup initialized missing image", err)
	}
}

// REQ: CH-11, CH-15
func TestStartupPreservesUncertainLeaseCleanupError(t *testing.T) {
	path, cfg := sessionFixture(t)
	p, err := StartSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	<-p.done
	// Deliberately invalidate the actual private lock descriptor to exercise a
	// cleanup fault. This is synthetic descriptor corruption, not custody proof.
	if err = p.session.lease.lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(context.Background()); err != ErrStorage {
		t.Fatal("cleanup failure lost", err)
	}
	if err = p.Close(context.Background()); err != ErrStorage {
		t.Fatal("retry erased uncertain cleanup", err)
	}
	if p.State() != StartupRetired {
		t.Fatal("cleanup error reactivated")
	}
}
