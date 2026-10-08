//go:build linux

package pacingfile

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/question"
)

// REQ: CH-15, CH-11, RES-1
func TestStartupSlotKeepsCancelledBlockedConstructorAcrossDifferentPaths(t *testing.T) {
	path, cfg := sessionFixture(t)
	otherPath, otherCfg := sessionFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	cfg.Now = func() time.Time { close(entered); <-release; return time.Now() }
	var slot StartupSlot
	p, err := slot.Start(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		slot.Drain(context.Background())
	})
	<-entered
	var otherCalls atomic.Int32
	otherCfg.Now = func() time.Time { otherCalls.Add(1); return time.Now() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = slot.Drain(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if next, err := slot.Start(otherPath, otherCfg); next != nil || err != ErrStartupOccupied {
			t.Fatal("different-path replacement admitted", err)
		}
	}
	if otherCalls.Load() != 0 || p.State() != StartupRetired {
		t.Fatal("cancelled wait released admission")
	}
	close(release)
	// Constructor completion alone cannot reopen admission: resource owner must
	// observe successful Drain, even when the old handle has completed cleanup.
	<-p.done
	if next, err := slot.Start(otherPath, otherCfg); next != nil || err != ErrStartupOccupied {
		t.Fatal("completion auto-released slot", err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := slot.Start(otherPath, otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	<-next.done
	if next.State() != StartupReady || otherCalls.Load() != 1 {
		t.Fatal("explicit restart failed")
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// REQ: RES-1, CH-15
func TestStartupSlotConcurrentAdmissionLaunchesOneActualConstructor(t *testing.T) {
	path, cfg := sessionFixture(t)
	var calls atomic.Int32
	cfg.Now = func() time.Time { calls.Add(1); return time.Now() }
	var slot StartupSlot
	t.Cleanup(func() { slot.Drain(context.Background()) })
	type result struct {
		p   *Startup
		err error
	}
	results := make(chan result, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p, err := slot.Start(path, cfg); results <- result{p, err} }()
	}
	wg.Wait()
	close(results)
	var winner *Startup
	accepted := 0
	for r := range results {
		if r.err == nil {
			accepted++
			winner = r.p
		} else if r.err != ErrStartupOccupied || r.p != nil {
			t.Fatal("unexpected admission", r.err)
		}
	}
	if accepted != 1 {
		t.Fatal("multiple owners", accepted)
	}
	<-winner.done
	if calls.Load() != 1 || winner.State() != StartupReady {
		t.Fatal("constructor count", calls.Load())
	}
}

// REQ: RES-1, CH-15, CH-11
func TestStartupSlotDrainsActualQuestionBeforeFreshGateAndRetainsDebt(t *testing.T) {
	path, cfg := sessionFixture(t)
	otherPath, otherCfg := sessionFixture(t)
	var slot StartupSlot
	p, err := slot.Start(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	<-p.done
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		slot.Drain(context.Background())
	})
	go func() {
		result <- p.Use(func(g *grants.Gate) error {
			book, err := question.New(question.Config{Reserve: g.Reserve, Now: func(context.Context) (time.Time, error) { return time.Now(), nil }, Send: func(string) error { close(entered); <-release; return nil }})
			if err != nil {
				return err
			}
			_, err = book.Ask(context.Background(), "synthetic-agent", "synthetic-choice", question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
			return err
		})
	}()
	<-entered
	primaryDrain := make(chan error, 1)
	go func() { primaryDrain <- slot.Drain(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for p.State() != StartupRetired {
		if time.Now().After(deadline) {
			t.Fatal("primary drain did not retire")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = slot.Drain(ctx); err != context.Canceled {
		t.Fatal("question scope not held", err)
	}
	if next, err := slot.Start(otherPath, otherCfg); next != nil || err != ErrStartupOccupied {
		t.Fatal("fresh Gate while question send pending", err)
	}
	if lease, err := OpenExclusive(path); err == nil {
		lease.Close()
		t.Fatal("question's actual lease released")
	}
	close(release)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if err = <-primaryDrain; err != nil {
		t.Fatal(err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := slot.Start(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	<-next.done
	if err = next.Use(func(g *grants.Gate) error {
		if !g.Reserve(false) || g.Reserve(false) {
			t.Fatal("spent question debt reset")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// REQ: RES-1, CH-11
func TestStartupSlotKnownCleanupFaultDoesNotAuthorizeReplacement(t *testing.T) {
	path, cfg := sessionFixture(t)
	otherPath, otherCfg := sessionFixture(t)
	var slot StartupSlot
	p, err := slot.Start(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	<-p.done
	// Synthetic private descriptor fault, not hostile-path qualification.
	if err = p.session.lease.lock.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = slot.Drain(context.Background()); err != ErrStorage {
			t.Fatal("known fault lost", err)
		}
	}
	if next, err := slot.Start(otherPath, otherCfg); next != nil || err != ErrStartupOccupied {
		t.Fatal("cleanup fault released admission", err)
	}
}

// REQ: RES-1, CH-11, CH-15
func TestStartupSlotInvalidConfigAndStaleHandlesDoNotAffectNextOwner(t *testing.T) {
	path, cfg := sessionFixture(t)
	var slot StartupSlot
	if p, err := slot.Start(path, grants.Config{}); p != nil || err != ErrSessionConfig {
		t.Fatal(err)
	}
	old, err := slot.Start(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	<-old.done
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := slot.Start(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Drain(context.Background())
	<-next.done
	if err = old.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if old.Use(func(*grants.Gate) error { t.Fatal("old consumer accepted"); return nil }) != ErrSessionRetired || next.State() != StartupReady {
		t.Fatal("old handle affected new owner")
	}
	if p, err := slot.Start(path, cfg); p != nil || err != ErrStartupOccupied {
		t.Fatal("stale close released new slot", err)
	}
	var nilSlot *StartupSlot
	if p, err := nilSlot.Start(path, cfg); p != nil || err != ErrSessionConfig {
		t.Fatal(err)
	}
	if nilSlot.Drain(context.Background()) != ErrSessionConfig || slot.Drain(nil) != ErrSessionConfig {
		t.Fatal("invalid drain accepted")
	}
}
