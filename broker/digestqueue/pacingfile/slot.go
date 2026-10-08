package pacingfile

import (
	"context"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/grants"
)

var ErrStartupOccupied = errors.New("accounting startup owner occupied")

// StartupSlot admits one owned startup across ledger paths. Its zero value is
// usable; do not copy it. The daemon must consistently reuse one slot for this
// resource: creating another slot or calling StartSession directly bypasses this
// cooperating composition bound. No daemon/global quota is implied.
//
// Use returned handles for State and scoped consumers; retire them through Drain
// while owned. Do not concurrently call their Close outside this slot. Retain the
// slot/handle until drain completes, including after cancellation or cleanup fault.
type StartupSlot struct {
	mu       sync.Mutex // state only: never waits for constructor/user/I/O work
	current  *Startup
	draining *slotDrain
	recovery RecoveryState
}

type slotDrain struct {
	done chan struct{}
	err  error // immutable after done closes
}

// Start rejects occupied admission before launching another constructor, even
// for a different path or an already completed/failed/retired handle. Admission
// is released only by successful explicit Drain. Invalid configuration does not
// occupy an empty slot. Nothing activates or retries automatically.
func (s *StartupSlot) Start(path string, cfg grants.Config) (*Startup, error) {
	if s == nil {
		return nil, ErrSessionConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil || s.recovery != RecoveryIdle {
		return nil, ErrStartupOccupied
	}
	p, err := StartSession(path, cfg)
	if err != nil {
		return nil, err
	}
	s.current = p
	return p, nil
}

// Drain retires the current startup and releases admission only on successful
// complete Close. Constructor/user waits, synchronous cleanup and known faults
// retain occupancy. One caller owns each drain attempt; concurrent callers join
// its result or cancel their own wait without another Close operation. A joined
// caller sees the initiating attempt's error (including its context cancellation)
// and may explicitly retry later. No extra worker is started for draining.
//
// A completed old drain cannot clear a newly started handle. Context never
// interrupts synchronous I/O or guarantees shutdown. Do not await Drain inside
// an owned Use scope: that scope is itself part of the drain.
func (s *StartupSlot) Drain(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrSessionConfig
	}
	s.mu.Lock()
	if s.recovery != RecoveryIdle {
		s.mu.Unlock()
		return ErrStartupOccupied
	}
	if s.current == nil {
		s.mu.Unlock()
		return nil
	}
	if a := s.draining; a != nil {
		s.mu.Unlock()
		select {
		case <-a.done:
			return a.err
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.done:
			return a.err
		}
	}
	p := s.current
	a := &slotDrain{done: make(chan struct{})}
	s.draining = a
	s.mu.Unlock()
	err := p.Close(ctx)
	s.mu.Lock()
	if err == nil && s.current == p {
		s.current = nil
	}
	a.err = err
	s.draining = nil
	close(a.done)
	s.mu.Unlock()
	return err
}
