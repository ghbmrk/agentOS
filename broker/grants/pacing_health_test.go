package grants

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

type lifecycleStore struct {
	file         *change.FileStore
	bad          atomic.Bool
	loads, saves atomic.Int32
	after        func()
}

func (s *lifecycleStore) PacingHealth() error {
	if s.bad.Load() {
		return errors.New("synthetic private backend canary")
	}
	return nil
}
func (s *lifecycleStore) Load() ([]byte, error) { s.loads.Add(1); return s.file.Load() }
func (s *lifecycleStore) Save(b []byte) error {
	s.saves.Add(1)
	if err := s.file.Save(b); err != nil {
		return err
	}
	if s.after != nil {
		s.after()
	}
	return nil
}
func lifecycleConfig(s PacingStore) Config {
	return Config{PacingStore: s, RequestsPerHour: 1, Now: func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }}
}

// REQ: CH-15, CH-11
func TestPacingBackendRetirementLatchesWithoutStoreIO(t *testing.T) {
	s := &lifecycleStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "ledger")}}
	g := New(lifecycleConfig(s))
	l, n := s.loads.Load(), s.saves.Load()
	s.bad.Store(true)
	if g.PacingHealth() != ErrPacingRecovery {
		t.Fatal("retired backend invisible")
	}
	s.bad.Store(false)
	if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) {
		t.Fatal("live backend repair cleared Gate quarantine")
	}
	if s.loads.Load() != l || s.saves.Load() != n {
		t.Fatal("health/refusal performed IO")
	}
}

// REQ: CH-15
func TestPacingRetiredBackendStartupDoesNotLoadOrInitialize(t *testing.T) {
	s := &lifecycleStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "ledger")}}
	s.bad.Store(true)
	g := New(lifecycleConfig(s))
	if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) || s.loads.Load() != 0 || s.saves.Load() != 0 {
		t.Fatal("retired startup touched state")
	}
}

// REQ: CH-15
func TestPacingRetirementAtSuccessfulSaveRefusesAndRetainsDebt(t *testing.T) {
	s := &lifecycleStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "ledger")}}
	cfg := lifecycleConfig(s)
	g := New(cfg)
	s.after = func() { s.bad.Store(true) }
	if g.Reserve(false) || g.PacingHealth() != ErrPacingRecovery {
		t.Fatal("retirement after save returned permission")
	}
	next := &lifecycleStore{file: s.file}
	cfg.PacingStore = next
	cfg.PacingRequireExisting = true
	reopened := New(cfg)
	if reopened.PacingHealth() != nil || reopened.Reserve(false) {
		t.Fatal("retirement refunded durable debt")
	}
}

// REQ: CH-15, CH-11
func TestPacingRetirementDuringBlockedStoreHealthDoesNotWait(t *testing.T) {
	s := &lifecycleStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "ledger")}}
	g := New(lifecycleConfig(s))
	entered, release := make(chan struct{}), make(chan struct{})
	s.after = func() { close(entered); <-release }
	result := make(chan bool, 1)
	go func() { result <- g.Reserve(false) }()
	<-entered
	s.bad.Store(true)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	health := make(chan error, 1)
	go func() { health <- g.PacingHealth() }()
	select {
	case err := <-health:
		if err != ErrPacingRecovery {
			t.Fatal("retirement not observed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("health waited for store")
	}
	close(release)
	if <-result {
		t.Fatal("retired blocked store returned permission")
	}
}
