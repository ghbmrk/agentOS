package grants

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/owner"
)

type latencyStore struct {
	file               *change.FileStore
	entered, release   chan struct{}
	block, after, load bool
}

func (s *latencyStore) Load() ([]byte, error) {
	if s.load {
		close(s.entered)
		<-s.release
	}
	return s.file.Load()
}
func (s *latencyStore) Save(b []byte) error {
	if !s.block {
		return s.file.Save(b)
	}
	if s.after {
		if err := s.file.Save(b); err != nil {
			return err
		}
	}
	close(s.entered)
	<-s.release
	if s.after {
		return nil
	}
	return s.file.Save(b)
}
func latencyConfig(s PacingStore) Config {
	return Config{Now: func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }, RequestsPerHour: 1, PacingStore: s, PacingMaxStoreLatency: 200 * time.Millisecond}
}
func latencyExpired(t *testing.T, g *Gate) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			if errors.Is(g.PacingHealth(), ErrPacingRecovery) {
				return
			}
			select {
			case <-deadline.C:
				return
			case <-tick.C:
			}
		}
	}()
	select {
	case <-done:
		if g.PacingHealth() != ErrPacingRecovery {
			t.Fatal("overdue store did not latch recovery")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("health blocked on admission/store mutex")
	}
}

// REQ: CH-15, CH-11
func TestPacingLatencyStalledSaveHealthAndStrictReopen(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-replacement", true: "after-replacement"}[after], func(t *testing.T) {
			s := &latencyStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, entered: make(chan struct{}), release: make(chan struct{}), after: after}
			cfg := latencyConfig(s)
			g := New(cfg)
			if g.PacingHealth() != nil {
				t.Fatal("initial store unhealthy")
			}
			s.block = true
			result := make(chan bool, 1)
			go func() { result <- g.Reserve(false) }()
			<-s.entered
			// The old implementation blocks here even before the latency expires.
			healthy := make(chan error, 1)
			go func() { healthy <- g.PacingHealth() }()
			select {
			case err := <-healthy:
				if err != nil {
					t.Fatal("premature latency fault")
				}
			case <-time.After(100 * time.Millisecond):
				close(s.release)
				<-result
				t.Fatal("health waited for Save")
			}
			latencyExpired(t, g)
			var wg sync.WaitGroup
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if g.PacingHealth() != ErrPacingRecovery {
						t.Error("concurrent health lost recovery")
					}
				}()
			}
			wg.Wait()
			close(s.release)
			if <-result {
				t.Fatal("overdue successful save returned permission")
			}
			if g.Reserve(false) || g.take(false, 1) != 0 || g.PacingHealth() != ErrPacingRecovery {
				t.Fatal("live overdue gate resumed")
			}
			// Both before and after cuts eventually persist debt. Only a fresh strict
			// object may recover, and the failed permission still consumes that debt.
			cfg.PacingStore = s.file
			cfg.PacingRequireExisting = true
			reopened := New(cfg)
			if reopened.PacingHealth() != nil || reopened.Reserve(false) {
				t.Fatal("strict reopen forgot overdue persisted debt")
			}
		})
	}
}

// REQ: CH-15, CH-11
func TestPacingLatencyLoadRefusesLateSuccess(t *testing.T) {
	s := &latencyStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, entered: make(chan struct{}), release: make(chan struct{}), load: true}
	cfg := latencyConfig(s)
	result := make(chan *Gate, 1)
	go func() { result <- New(cfg) }()
	<-s.entered
	timer := time.NewTimer(250 * time.Millisecond)
	<-timer.C
	close(s.release)
	g := <-result
	if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) {
		t.Fatal("late load permitted initialization")
	}
	b, err := s.file.Load()
	if err != nil || b != nil {
		t.Fatal("late load initialized ledger")
	}
}

// REQ: CH-15
func TestPacingLatencyConfigurationRefusal(t *testing.T) {
	for _, cfg := range []Config{{PacingMaxStoreLatency: time.Second}, {PacingMaxStoreLatency: -time.Nanosecond, PacingStore: &change.MemStore{}}, {PacingMaxStoreLatency: 6 * time.Minute, PacingStore: &change.MemStore{}}} {
		g := New(cfg)
		if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) {
			t.Fatal("invalid threshold silently selected volatile/unbounded mode")
		}
	}
}

// REQ: CH-15
func TestPacingLatencyZeroKeepsLegacyStoreSemantics(t *testing.T) {
	s := &change.MemStore{}
	g := New(Config{PacingStore: s})
	if g.PacingHealth() != nil || !g.Reserve(false) {
		t.Fatal("zero threshold changed legacy behavior")
	}
}

// REQ: CH-15, CH-11
func TestPacingLatencyReissueRetainedAndStopDoesNotWait(t *testing.T) {
	s := &latencyStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, entered: make(chan struct{}), release: make(chan struct{})}
	r := newRig(t, func(c *Config) { c.PacingStore = s; c.PacingMaxStoreLatency = 200 * time.Millisecond })
	it := owner.Item{Ref: "synthetic-latency-request", Object: "synthetic", Recipient: "a@example.com", Facts: owner.Facts{Verb: "send"}}
	r.g.mu.Lock()
	r.g.waiting[it.Ref] = &wait{item: it, expires: r.now().Add(time.Hour)}
	r.g.batch = []string{it.Ref}
	r.g.mu.Unlock()
	s.block = true
	done := make(chan struct{})
	go func() { defer close(done); r.g.Flush() }()
	<-s.entered
	t.Cleanup(func() {
		select {
		case <-s.release:
		default:
			close(s.release)
		}
	})
	latencyExpired(t, r.g)
	stop := make(chan error, 1)
	go func() { _, err := r.eng.Stop(t.Context()); stop <- err }()
	select {
	case err := <-stop:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("STOP waited for overdue store")
	}
	close(s.release)
	<-done
	if r.own.count() != 0 || r.g.PacingHealth() != ErrPacingRecovery {
		t.Fatal("overdue reissue reached owner")
	}
	r.g.mu.Lock()
	defer r.g.mu.Unlock()
	if len(r.g.batch) != 1 || r.g.waiting[it.Ref] == nil {
		t.Fatal("overdue reissue lost its waiting identity")
	}
}

// REQ: CH-15
func TestPacingLatencyLateSaveRefusesWithoutHealthObserver(t *testing.T) {
	s := &latencyStore{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, entered: make(chan struct{}), release: make(chan struct{})}
	g := New(latencyConfig(s))
	s.block = true
	result := make(chan bool, 1)
	go func() { result <- g.Reserve(false) }()
	<-s.entered
	timer := time.NewTimer(250 * time.Millisecond)
	<-timer.C
	close(s.release)
	if <-result || g.PacingHealth() != ErrPacingRecovery {
		t.Fatal("late save required a health observer to refuse")
	}
}

// REQ: CH-15, CH-11
func TestPacingLatencyHealthyCompletionClearsDeadline(t *testing.T) {
	g := New(latencyConfig(&change.MemStore{}))
	if g.PacingHealth() != nil || !g.Reserve(false) || g.pacingDeadline.Load() != nil {
		t.Fatal("healthy store completion failed")
	}
	timer := time.NewTimer(250 * time.Millisecond)
	<-timer.C
	if g.PacingHealth() != nil {
		t.Fatal("completed store was later treated as stalled")
	}
}
