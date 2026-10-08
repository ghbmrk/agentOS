//go:build linux

package pacingfile

import (
	"context"
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"testing"
	"time"
)

// REQ: OP-1, CH-15
func TestActualLeaseCloseFaultIsImmutableForRepeatAndConcurrentObservers(t *testing.T) {
	for _, kind := range []string{"lock", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path, image := recoveryFixture(t)
			s, e := OpenExclusive(path)
			if e != nil {
				t.Fatal(e)
			}
			// Safely preclose the owned os.File object, not a reused numeric descriptor.
			// This models actual OS close failure, never media or retained-custody proof.
			if kind == "lock" {
				e = s.lock.Close()
			} else {
				e = s.dir.Close()
			}
			if e != nil {
				t.Fatal("fault fixture", e)
			}
			if e = s.Close(); e != ErrStorage {
				t.Fatal("actual fault not observed", e)
			}
			if e = s.Close(); e != ErrStorage {
				t.Error("repeat erased close failure", e)
			}
			done := make(chan error, 24)
			for i := 0; i < 24; i++ {
				go func() { done <- s.Close() }()
			}
			for i := 0; i < 24; i++ {
				if e = <-done; e != ErrStorage {
					t.Error("concurrent observer erased close failure", e)
				}
			}
			if s.PacingHealth() == nil {
				t.Fatal("failed close reactivated backend")
			}
			assertRecoveryLedger(t, path, image)
		})
	}
}

// REQ: OP-1, CH-15
func TestActualSessionCloseRetryRetainsFailureRetirementAndDebt(t *testing.T) {
	path, cfg := sessionFixture(t)
	s, e := OpenSession(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Use(func(g *grants.Gate) error {
		if !g.Reserve(false) {
			t.Fatal("fixture reserve")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	image, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.lease.lock.Close(); e != nil {
		t.Fatal("owned descriptor model", e)
	}
	if e = s.Close(context.Background()); e != ErrStorage {
		t.Fatal("session lost actual close fault", e)
	}
	if e = s.Close(context.Background()); e != ErrStorage {
		t.Error("session retry erased cleanup fault", e)
	}
	if e = s.Use(func(*grants.Gate) error { t.Fatal("retired consumer admitted"); return nil }); e != ErrSessionRetired {
		t.Fatal("retirement lost", e)
	}
	assertRecoveryLedger(t, path, image)
}

// REQ: OP-1, CH-15
func TestHealthyConcurrentLeaseCloseRetainsImageAndStableLock(t *testing.T) {
	path, image := recoveryFixture(t)
	s, e := OpenExclusive(path)
	if e != nil {
		t.Fatal(e)
	}
	before, e := os.Stat(path + ".lock")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 24)
	for i := 0; i < 24; i++ {
		go func() { done <- s.Close() }()
	}
	for i := 0; i < 24; i++ {
		if e = <-done; e != nil {
			t.Fatal("healthy close", e)
		}
	}
	after, e := os.Stat(path + ".lock")
	if e != nil || !os.SameFile(before, after) {
		t.Fatal("close replaced/unlinked lock", e)
	}
	assertRecoveryLedger(t, path, image)
	// Healthy complete result permits a new cooperating fixture lease; fault tests
	// above never restart without external recovery determination.
	next, e := OpenExclusive(path)
	if e != nil {
		t.Fatal("healthy lease not released", e)
	}
	if e = next.Close(); e != nil {
		t.Fatal(e)
	}
}

// REQ: OP-1, CH-15
func TestBlockedCloseWaitersJoinImmutableFailureAfterRetirement(t *testing.T) {
	path, image := recoveryFixture(t)
	s, err := OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.lock.Close(); err != nil {
		t.Fatal(err)
	}
	// Model an in-flight operation holding the I/O mutex. All observers must
	// wait for the same final outcome, while retirement is already visible.
	s.mu.Lock()
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- s.Close() }()
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for s.PacingHealth() == nil {
		select {
		case <-deadline.C:
			s.mu.Unlock()
			<-done
			<-done
			t.Fatal("retirement waited for I/O mutex")
		case <-tick.C:
		}
	}
	select {
	case <-done:
		s.mu.Unlock()
		<-done
		t.Fatal("Close finished before drain")
	default:
	}
	s.mu.Unlock()
	for i := 0; i < 2; i++ {
		if err = <-done; err != ErrStorage {
			t.Error("joined waiter erased failure", err)
		}
	}
	assertRecoveryLedger(t, path, image)
}
