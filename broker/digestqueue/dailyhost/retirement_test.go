package dailyhost

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/digestqueue/pacingfile"
	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: CH-15, CH-11, CH-2
func TestProvisionedHostSeesActualLeaseCloseBeforeAnyNewReservation(t *testing.T) {
	r := setup(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger")
	s, err := pacingfile.OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	gc := grants.Config{Now: func() time.Time { return r.now }, PacingStore: s, PacingMaxStoreLatency: time.Second}
	if grants.New(gc).PacingHealth() != nil {
		t.Fatal("fixture provisioning")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = pacingfile.OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	gc.PacingStore = s
	gc.PacingRequireExisting = true
	g := grants.New(gc)
	h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, g))
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Activate(); err != nil {
		t.Fatal(err)
	}
	h.Hold()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if g.PacingHealth() != grants.ErrPacingRecovery || h.Health() != ErrPolicyRecovery || h.Activate() != ErrPolicyRecovery {
		t.Fatal("retired host reactivated")
	}
	if _, err = h.Step(t.Context()); err != ErrPolicyRecovery || h.Status().Code != Recovery || r.m.count() != 0 {
		t.Fatal("retirement did not reach fixed status", err)
	}
	if err = h.Channel().LocalStop(t.Context()); err != nil || !r.e.Stopped() {
		t.Fatal("retired host lost STOP", err)
	}
}
