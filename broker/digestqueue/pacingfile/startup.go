package pacingfile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/grants"
)

var (
	ErrSessionOpening  = errors.New("accounting session still opening")
	ErrSessionRecovery = errors.New("accounting session startup needs recovery")
)

type StartupState string

const (
	StartupOpening  StartupState = "opening"
	StartupReady    StartupState = "ready"
	StartupRecovery StartupState = "recovery"
	StartupRetired  StartupState = "retired"
)

// Line is fixed owner operational wording; no constructor errors/paths/codes.
func (s StartupState) Line() string {
	switch s {
	case StartupOpening:
		return "Notification accounting: starting; notifications held."
	case StartupReady:
		return "Notification accounting: available; activation remains explicit."
	case StartupRetired:
		return "Notification accounting: retired; notifications held."
	default:
		return "Notification accounting: needs recovery; notifications held."
	}
}

// Startup owns exactly one constructor attempt and its eventual Session. Do not
// copy it. Retain this handle until Close completes. Independent owner controls
// must already exist and must not wait for this constructor. No retries, timeout
// replacement writer, activation, boot or daemon default is supplied.
type Startup struct {
	mu               sync.Mutex // short publication/retirement state; never constructor/I/O
	session          *Session
	opening, retired bool
	cleanupFault     bool
	retirement       atomic.Bool
	done             chan struct{}
}

// StartSession validates immutable options before launching one owned worker.
// OpenSession (including Gate.New and I/O) remains synchronous inside it and may
// hang indefinitely. Retirement does not detach, interrupt or supersede that
// worker. A late retired result is cleaned before constructor completion is
// published; it is never exposed to Use. Caller must hold resources and this
// handle through shutdown, including after a cancelled Close wait.
func StartSession(path string, cfg grants.Config) (*Startup, error) {
	if !sessionConfigValid(cfg) {
		return nil, ErrSessionConfig
	}
	p := &Startup{opening: true, done: make(chan struct{})}
	go p.open(path, cfg)
	return p, nil
}

func constructSession(path string, cfg grants.Config, retired *atomic.Bool) (s *Session, err error) {
	// OpenSession unwinds its actual lease on panic. Contain only this owned
	// constructor boundary and never disclose the panic or callback error.
	defer func() {
		if recover() != nil {
			s = nil
			err = ErrSessionRecovery
		}
	}()
	return openSession(path, cfg, retired)
}
func (p *Startup) open(path string, cfg grants.Config) {
	s, err := constructSession(path, cfg, &p.retirement)
	p.mu.Lock()
	if p.retired {
		if s != nil {
			_, _ = s.retire()
		}
		p.mu.Unlock()
		cleanupFault := false
		if s != nil {
			cleanupFault = s.Close(context.Background()) != nil
		}
		p.mu.Lock()
		p.cleanupFault = p.cleanupFault || cleanupFault
	}
	if err == nil {
		p.session = s
	}
	p.opening = false
	close(p.done)
	p.mu.Unlock()
}

// State is read-only and independent of constructor/admission I/O. Once ready,
// it observes the owned Gate's cached, I/O-free health. Ready is not activation
// or proof of custody freshness, downstream quiescence or delivery.
func (p *Startup) State() StartupState {
	if p == nil {
		return StartupRecovery
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done == nil {
		return StartupRecovery
	}
	if p.retired {
		return StartupRetired
	}
	if p.opening {
		return StartupOpening
	}
	if p.session == nil || p.session.gate.PacingHealth() != nil {
		return StartupRecovery
	}
	return StartupReady
}

// Use preserves Session's trusted scoped-consumer contract. A completed faulted
// Gate is still exposed for constructing held recovery/STOP controls; constructor
// failure exposes none. It never waits for an incomplete constructor.
func (p *Startup) Use(fn func(*grants.Gate) error) error {
	if p == nil || fn == nil {
		return ErrSessionConfig
	}
	p.mu.Lock()
	if p.done == nil {
		p.mu.Unlock()
		return ErrSessionConfig
	}
	if p.retired {
		p.mu.Unlock()
		return ErrSessionRetired
	}
	if p.opening {
		p.mu.Unlock()
		return ErrSessionOpening
	}
	s := p.session
	p.mu.Unlock()
	if s == nil {
		return ErrSessionRecovery
	}
	return s.Use(fn)
}

// Close retires publication and any already-ready Session before waiting.
// Cancellation retains the owned constructor/lease, with no replacement attempt.
// A blocked constructor, cleanup or final lease Close can still prevent shutdown;
// ctx bounds only incomplete constructor/user waits, never synchronous I/O.
func (p *Startup) Close(ctx context.Context) error {
	if p == nil || ctx == nil {
		return ErrSessionConfig
	}
	p.mu.Lock()
	if p.done == nil {
		p.mu.Unlock()
		return ErrSessionConfig
	}
	p.retired = true
	p.retirement.Store(true)
	if p.session != nil {
		_, _ = p.session.retire()
	}
	done := p.done
	p.mu.Unlock()
	select {
	case <-done:
	default:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	p.mu.Lock()
	s := p.session
	p.mu.Unlock()
	var err error
	if s != nil {
		err = s.Close(ctx)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		p.cleanupFault = true
	}
	if p.cleanupFault {
		return ErrStorage
	}
	return err
}
