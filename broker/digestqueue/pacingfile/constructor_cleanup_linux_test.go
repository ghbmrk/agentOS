//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// REQ: OP-1, CH-15
func TestActualAcquiredLeasePanicUnwindRecordsCleanupFault(t *testing.T) {
	for _, kind := range []string{"lock", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path, cfg := sessionFixture(t)
			lease, err := OpenExclusive(path)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "lock" {
				err = lease.lock.Close()
			} else {
				err = lease.dir.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg.Now = func() time.Time { panic("synthetic constructor canary") }
			fault := false
			var caught any
			func() {
				defer func() { caught = recover() }()
				_ = assembleSession(lease, cfg, nil, &fault)
			}()
			if caught != "synthetic constructor canary" {
				t.Fatal("direct panic semantics changed")
			}
			if !fault {
				t.Fatal("actual unwind close fault discarded")
			}
			if lease.Close() != ErrStorage {
				t.Fatal("backend cleanup outcome erased")
			}
			// Do not open another lease after failed cleanup without external determination.
		})
	}
}

// REQ: OP-1, CH-15
func TestOwnedConstructorCleanupFaultRetainsSlotOnDrain(t *testing.T) {
	p := &Startup{opening: true, done: make(chan struct{})}
	slot := &StartupSlot{current: p}
	p.complete(nil, errConstructorCleanup)
	if p.State() != StartupRecovery {
		t.Fatal("failed constructor became available")
	}
	if err := p.Use(func(_ *grants.Gate) error { t.Fatal("consumer admitted"); return nil }); err != ErrSessionRecovery {
		t.Fatal(err)
	}
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		go func() { results <- slot.Drain(context.Background()) }()
	}
	for i := 0; i < 12; i++ {
		if err := <-results; err != ErrStorage {
			t.Error("uncertain cleanup released admission", err)
		}
	}
	path, cfg := sessionFixture(t)
	if _, err := slot.Start(path, cfg); err != ErrStartupOccupied {
		t.Fatal("competing constructor admitted", err)
	}
}

// REQ: OP-1, CH-15
func TestHealthyAcquiredLeasePanicUnwindPreservesExplicitDrain(t *testing.T) {
	path, cfg := sessionFixture(t)
	lease, err := OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	fault := false
	cfg.Now = func() time.Time { panic("healthy unwind canary") }
	func() {
		defer func() {
			if recover() != "healthy unwind canary" {
				t.Error("panic lost")
			}
		}()
		_ = assembleSession(lease, cfg, &atomic.Bool{}, &fault)
	}()
	if fault || lease.Close() != nil {
		t.Fatal("healthy cleanup held as uncertain")
	}
	p := &Startup{opening: true, done: make(chan struct{})}
	slot := &StartupSlot{current: p}
	p.complete(nil, ErrSessionRecovery)
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Only observed healthy complete cleanup permits this cooperating fixture reopen.
	next, err := OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
}

// REQ: OP-1, CH-15
func TestActualConstructorEntriesHealthyPanicCleanupKeepsStrictSpentDebt(t *testing.T) {
	for _, entry := range []string{"direct", "slot", "predecoded-v1", "reader-v1", "predecoded-v2", "reader-v2"} {
		t.Run(entry, func(t *testing.T) {
			path, owners := protectedFixture(t)
			lease, err := OpenExclusiveProtected(path, owners)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			clock := func() time.Time { return now }
			seed := grants.New(grants.Config{Now: clock, RequestsPerHour: 2, PacingStore: lease, PacingMaxStoreLatency: time.Second})
			if seed.PacingHealth() != nil || !seed.Reserve(false) || !seed.Reserve(false) {
				lease.Close()
				t.Fatal("spent fixture")
			}
			if err = lease.Close(); err != nil {
				t.Fatal(err)
			}
			image, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			panicClock := func() time.Time { panic("synthetic startup cleanup canary") }
			cfg := grants.Config{Now: panicClock, RequestsPerHour: 2, PacingRequireExisting: true, PacingMaxStoreLatency: time.Second}
			var slot StartupSlot
			if entry == "direct" {
				func() {
					defer func() {
						if recover() != "synthetic startup cleanup canary" {
							t.Error("direct panic changed")
						}
					}()
					OpenSession(path, cfg)
				}()
			} else {
				var p *Startup
				if entry == "slot" {
					p, err = slot.Start(path, cfg)
				} else {
					wire := manifestImage(t, path, 2, 1000)
					if entry == "predecoded-v2" || entry == "reader-v2" {
						wire = protectedManifestImage(path, owners)
					}
					cfg = grants.Config{Now: panicClock}
					if entry == "reader-v1" || entry == "reader-v2" {
						p, err = slot.StartManifest(bytes.NewReader(wire), sha256.Sum256(wire), cfg)
					} else {
						settings, e := ReadProvisionedManifest(bytes.NewReader(wire), sha256.Sum256(wire))
						if e != nil {
							t.Fatal(e)
						}
						p, err = settings.Start(&slot, cfg)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if state := waitProtectedManifest(t, p); state != StartupRecovery {
					t.Fatal("panic published consumer", state)
				}
				if err = slot.Drain(context.Background()); err != nil {
					t.Fatal("healthy unwind held", err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(image, after) {
				t.Fatal("panic changed debt", err)
			}
			reopened, err := OpenSession(path, grants.Config{Now: clock, RequestsPerHour: 2, PacingRequireExisting: true, PacingMaxStoreLatency: time.Second})
			if err != nil {
				t.Fatal("healthy explicit reopen", err)
			}
			if err = reopened.Use(func(g *grants.Gate) error {
				if g.PacingHealth() != nil || g.Reserve(false) {
					t.Fatal("debt reset")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err = reopened.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// REQ: OP-1, CH-15
func TestCancelledDrainObserverCannotEraseConstructorCleanupFault(t *testing.T) {
	p := &Startup{opening: true, done: make(chan struct{})}
	slot := &StartupSlot{current: p}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := slot.Drain(ctx); err != context.Canceled {
		t.Fatal("incomplete wait", err)
	}
	p.complete(nil, errConstructorCleanup)
	if err := slot.Drain(context.Background()); err != ErrStorage {
		t.Fatal("cleanup lost after cancellation", err)
	}
	if err := slot.Drain(ctx); err != ErrStorage {
		t.Fatal("cancelled observer erased complete fault", err)
	}
	if slot.current != p {
		t.Fatal("uncertain cleanup freed owner")
	}
}
