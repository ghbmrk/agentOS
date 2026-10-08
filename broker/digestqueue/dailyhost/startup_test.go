//go:build linux

package dailyhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/digestqueue/pacingfile"
	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: CH-2, CH-11, CH-15, OP-1, OP-2
func TestIndependentHeldOwnerControlsRemainAvailableDuringGateStartup(t *testing.T) {
	// Construct the actual held transactional owner channel before accounting
	// startup. This is a fixture for an independent existing control service,
	// not daemon wiring or construction of a second live control writer.
	r := setup(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger")
	lease, err := pacingfile.OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := grants.Config{Now: func() time.Time { return r.now }, PacingStore: lease, PacingMaxStoreLatency: time.Second}
	if grants.New(cfg).PacingHealth() != nil {
		t.Fatal("trusted provisioning")
	}
	lease.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	cfg.PacingStore = nil
	cfg.PacingRequireExisting = true
	cfg.Now = func() time.Time { close(entered); <-release; return r.now }
	p, err := pacingfile.StartSession(path, cfg)
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
	if p.State() != pacingfile.StartupOpening || !r.h.Status().Held || r.m.count() != 0 {
		t.Fatal("startup activated notifications")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.h.Channel().LocalStop(t.Context()) }()
	select {
	case err = <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("STOP waited for accounting constructor")
	}
	if !r.e.Stopped() {
		t.Fatal("STOP lost")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = p.Close(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	if p.State() != pacingfile.StartupRetired || !r.h.Status().Held || r.m.count() != 0 {
		t.Fatal("retirement lost independent held status")
	}
	close(release)
	if err = p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !r.e.Stopped() || !r.h.Status().Held || r.m.count() != 0 {
		t.Fatal("late completion resumed or activated")
	}
	if p.Use(func(*grants.Gate) error { t.Fatal("late retired Gate published"); return nil }) != pacingfile.ErrSessionRetired {
		t.Fatal("retirement undone")
	}
	lease, err = pacingfile.OpenExclusive(path)
	if err != nil {
		t.Fatal("late cleanup did not release actual lease", err)
	}
	lease.Close()
}
