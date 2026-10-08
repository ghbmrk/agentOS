//go:build linux

package pacingfile

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-2, CH-15, OP-8
func TestOwnedRecoveryBlocksCompetingWorkButNotStatusOrOwnerStop(t *testing.T) {
	path, cfg := sessionFixture(t)
	var slot StartupSlot
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	go func() {
		done <- slot.recoverDuplicate(path, [32]byte{1}, func(string, [32]byte) error { close(entered); <-release; return nil })
	}()
	<-entered
	if slot.RecoveryState() != RecoveryRunning {
		t.Fatal("no running status")
	}
	if _, e := slot.Start(path+".different", cfg); e != ErrStartupOccupied {
		t.Fatal(e)
	}
	if e := slot.RecoverDuplicate(path+".different", [32]byte{1}); e != ErrStartupOccupied {
		t.Fatal(e)
	}
	if e := slot.Drain(t.Context()); e != ErrStartupOccupied {
		t.Fatal("drain bypassed recovery", e)
	}
	policy := grants.New(grants.Config{})
	eng, e := journal.Open(&journal.MemStore{}, policy, nil, func(s string) string { return s })
	if e != nil {
		t.Fatal(e)
	}
	channel, e := owner.New(owner.Config{Owner: "+15550000999", Engine: eng, Store: &owner.MemStore{}, Now: time.Now, Location: time.UTC})
	if e != nil {
		t.Fatal(e)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- channel.LocalStop(t.Context()) }()
	select {
	case e := <-stopped:
		if e != nil || !eng.Stopped() {
			t.Fatal("actual owner STOP lost", e)
		}
	case <-time.After(time.Second):
		t.Fatal("STOP waited for recovery")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if slot.RecoveryState() != RecoveryIdle {
		t.Fatal("success did not release owner slot")
	}
	startup, e := slot.Start(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	_ = startup
	if e = slot.Drain(t.Context()); e != nil {
		t.Fatal(e)
	}
}

// REQ: CH-15, OP-8
func TestOwnedRecoveryFailureAndPanicRetainAdmission(t *testing.T) {
	for _, panicInstead := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "panic"}[panicInstead], func(t *testing.T) {
			path, cfg := sessionFixture(t)
			var slot StartupSlot
			e := slot.recoverDuplicate(path, [32]byte{1}, func(string, [32]byte) error {
				if panicInstead {
					panic("synthetic-private-panic")
				}
				return errors.New("synthetic-private-storage-detail")
			})
			if e != ErrStorage || slot.RecoveryState() != RecoveryHeld {
				t.Fatal("failed action lost hold", e)
			}
			if _, e = slot.Start(path, cfg); e != ErrStartupOccupied {
				t.Fatal(e)
			}
			if e = slot.Drain(context.Background()); e != ErrStartupOccupied {
				t.Fatal("failed custody drain bypass", e)
			}
			if e = slot.RecoverDuplicate(path, [32]byte{1}); e != ErrStartupOccupied {
				t.Fatal("automatic retry allowed", e)
			}
		})
	}
}

// REQ: CH-15, OP-8
func TestOwnedRecoveryUsesActualDuplicateActionAfterSessionDrain(t *testing.T) {
	path, cfg := sessionFixture(t)
	var slot StartupSlot
	startup, e := slot.Start(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.After(time.Second)
	for startup.State() == StartupOpening {
		select {
		case <-deadline:
			t.Fatal("startup timeout")
		case <-time.After(time.Millisecond):
		}
	}
	if e = startup.Use(func(g *grants.Gate) error {
		if !g.Reserve(false) {
			t.Fatal("first debt")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	image, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path+".tmp", image, 0600); e != nil {
		t.Fatal(e)
	}
	pin := sha256.Sum256(image)
	if e = slot.RecoverDuplicate(path, pin); e != ErrStartupOccupied {
		t.Fatal("live startup allowed cleanup", e)
	}
	if e = slot.Drain(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e = slot.RecoverDuplicate(path, pin); e != nil {
		t.Fatal(e)
	}
	assertRecoveryLedger(t, path, image)
	next, e := slot.Start(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer slot.Drain(context.Background())
	deadline = time.After(time.Second)
	for next.State() == StartupOpening {
		select {
		case <-deadline:
			t.Fatal("reopen timeout")
		case <-time.After(time.Millisecond):
		}
	}
	if e = next.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || !g.Reserve(false) || g.Reserve(false) {
			t.Fatal("debt reset by owned recovery")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

// REQ: CH-15, OP-8
func TestOwnedRecoveryInvalidConfigurationDoesNotOccupyOrInvoke(t *testing.T) {
	var slot StartupSlot
	called := false
	if e := slot.recoverDuplicate("synthetic-unused", [32]byte{}, func(string, [32]byte) error { called = true; return nil }); e != ErrSessionConfig || called || slot.RecoveryState() != RecoveryIdle {
		t.Fatal("zero pin admitted", e)
	}
	if e := slot.recoverDuplicate("synthetic-unused", [32]byte{1}, nil); e != ErrSessionConfig {
		t.Fatal(e)
	}
	var missing *StartupSlot
	if e := missing.RecoverDuplicate("synthetic-unused", [32]byte{1}); e != ErrSessionConfig || missing.RecoveryState() != RecoveryHeld {
		t.Fatal("nil slot accepted", e)
	}
	for state, want := range map[RecoveryState]string{RecoveryIdle: "Notification recovery: no owned action.", RecoveryRunning: "Notification recovery: in progress; notifications held.", RecoveryHeld: "Notification recovery: needs trusted review; notifications held."} {
		if state.Line() != want {
			t.Fatal("unfixed state wording")
		}
	}
}
