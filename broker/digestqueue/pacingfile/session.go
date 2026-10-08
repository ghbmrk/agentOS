package pacingfile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

var (
	ErrSessionConfig  = errors.New("accounting session configuration unavailable")
	ErrSessionRetired = errors.New("accounting session retired")
)

// Session owns one Gate and one cooperating exclusive lease. Do not copy it.
// Use registers scoped consumers, not permission revocation or sandbox custody.
// Gate, bound methods, books, hosts and spawned work must not outlive Use.
// Persistent configuration, provisioning and all writers remain trusted.
type Session struct {
	mu      sync.Mutex
	retired atomic.Bool
	lease   *ExclusiveStore
	gate    *grants.Gate
	active  int
	drained chan struct{}
}

// OpenSession requires strict existing state and a positive bounded observational
// store threshold. No caller-supplied store is permitted. Faulted/missing state
// still returns a session so scoped callers can build held recovery controls.
// Construction is synchronous and can block: independent startup controls are
// still required. This does not provision, activate or start anything.
func OpenSession(path string, cfg grants.Config) (*Session, error) {
	if cfg.PacingStore != nil || !cfg.PacingRequireExisting || cfg.PacingMaxStoreLatency <= 0 || cfg.PacingMaxStoreLatency > 5*time.Minute {
		return nil, ErrSessionConfig
	}
	lease, err := OpenExclusive(path)
	if err != nil {
		return nil, err
	}
	s := &Session{lease: lease, drained: make(chan struct{})}
	cfg.PacingStore = &sessionStore{lease: lease, retired: &s.retired}
	s.gate = grants.New(cfg)
	return s, nil
}

type sessionStore struct {
	lease   *ExclusiveStore
	retired *atomic.Bool
}

func (s *sessionStore) Load() ([]byte, error) { return s.lease.Load() }
func (s *sessionStore) Save(b []byte) error   { return s.lease.Save(b) }
func (s *sessionStore) PacingHealth() error {
	if s.retired.Load() {
		return ErrStorage
	}
	return s.lease.PacingHealth()
}

// Use registers a cooperating user for the entire callback lifetime. The
// callback must drain every derived consumer and handoff before returning,
// including asynchronous Send/runner work. Panic propagates after unregistering.
// A callback must not synchronously await Close on this session: it owns a drain
// registration itself. Retirement refuses new users; faulted Gates remain
// available to existing scopes for held recovery and owner STOP.
func (s *Session) Use(fn func(*grants.Gate) error) error {
	if s == nil || fn == nil {
		return ErrSessionConfig
	}
	s.mu.Lock()
	if s.retired.Load() {
		s.mu.Unlock()
		return ErrSessionRetired
	}
	if s.gate == nil || s.lease == nil || s.drained == nil {
		s.mu.Unlock()
		return ErrSessionConfig
	}
	s.active++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.active--
		if s.retired.Load() && s.active == 0 {
			close(s.drained)
		}
	}()
	return fn(s.gate)
}

// Close retires admission before waiting for every registered user. Cancellation
// while users remain keeps the lease held and session permanently retired; retry
// Close after draining. Once drained, lease Close remains synchronous and may
// block despite ctx. No goroutine detaches I/O or releases custody early. This
// cannot revoke returned permissions or detect consumers escaped from Use.
func (s *Session) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrSessionConfig
	}
	s.mu.Lock()
	if s.lease == nil || s.drained == nil {
		s.mu.Unlock()
		return ErrSessionConfig
	}
	if !s.retired.Swap(true) && s.active == 0 {
		close(s.drained)
	}
	drained := s.drained
	s.mu.Unlock()
	select {
	case <-drained:
		return s.lease.Close()
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-drained:
		return s.lease.Close()
	}
}
