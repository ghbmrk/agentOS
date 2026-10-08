package grants

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: CH-15, OP-1, OP-2
func TestRequiredPacingStateDoesNotInitializeMissingLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pacing.json")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := Config{Now: func() time.Time { return now }, PacingStore: &change.FileStore{Path: path}, PacingRequireExisting: true}
	g := New(cfg)
	if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) || g.take(false, 1) != 0 {
		t.Fatal("missing ledger treated as provisioning")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("strict startup created state", err)
	}
}

// REQ: CH-15, OP-1, OP-2
func TestProvisionedLedgerDeletionCannotResetRequiredBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pacing.json")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := Config{Now: func() time.Time { return now }, RequestsPerHour: 2, PacingStore: &change.FileStore{Path: path}}
	g := New(cfg)
	if !g.Reserve(false) || !g.Reserve(false) {
		t.Fatal("trusted provisioning failed")
	}
	cfg.PacingRequireExisting = true
	g = New(cfg)
	if g.PacingHealth() != nil || g.Reserve(false) {
		t.Fatal("strict reopen reset prior allowance")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	g = New(cfg)
	if g.PacingHealth() != ErrPacingRecovery || g.Reserve(true) || g.take(false, 10) != 0 {
		t.Fatal("deletion recovered as new allowance")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted ledger recreated", err)
	}
}

type requiredMissingStore struct{ loads, saves int }

func (s *requiredMissingStore) Load() ([]byte, error) { s.loads++; return nil, nil }
func (s *requiredMissingStore) Save([]byte) error     { s.saves++; return nil }

// REQ: CH-15
func TestRequiredPacingStateMissingStoreAndImageRefuseAllReservationKinds(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	s := &requiredMissingStore{}
	for _, store := range []PacingStore{nil, s} {
		g := New(Config{Now: func() time.Time { return now }, PacingStore: store, PacingRequireExisting: true})
		if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) || g.Reserve(true) || g.take(true, 1) != 0 || g.take(false, 1) != 0 {
			t.Fatal("required state bypass")
		}
	}
	if s.loads != 1 || s.saves != 0 {
		t.Fatal("missing required state mutated", s.loads, s.saves)
	}
}

// REQ: CH-15, OP-1, OP-2
func TestRequiredPacingStateEmptyImageRefusalPreservesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pacing.json")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	g := New(Config{PacingStore: &change.FileStore{Path: path}, PacingRequireExisting: true})
	if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) {
		t.Fatal("empty ledger admitted")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != 0 {
		t.Fatal("refusal overwrote evidence", err)
	}
}

// REQ: CH-15
func TestRequiredPacingModeCanOpenExistingEmptyAllowance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pacing.json")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := Config{Now: func() time.Time { return now }, PacingStore: &change.FileStore{Path: path}, RequestsPerHour: 1}
	if err := New(cfg).PacingHealth(); err != nil {
		t.Fatal(err)
	}
	cfg.PacingRequireExisting = true
	g := New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) || g.Reserve(false) {
		t.Fatal("provisioned empty allowance refused or widened")
	}
	// An hour of expiration is a normal accounting event, not provisioning.
	now = now.Add(time.Hour)
	g = New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) {
		t.Fatal("strict mode froze legitimate expiry")
	}
}
