package pacingfile

// RecoveryState observes only this slot's explicit recovery action, not its
// current startup state, filesystem freshness or authority. The zero state means
// no owned recovery; startup admission may still be occupied by a Startup.
type RecoveryState uint8

const (
	RecoveryIdle RecoveryState = iota
	RecoveryRunning
	RecoveryHeld
)

func (r RecoveryState) Line() string {
	switch r {
	case RecoveryIdle:
		return "Notification recovery: no owned action."
	case RecoveryRunning:
		return "Notification recovery: in progress; notifications held."
	default:
		return "Notification recovery: needs trusted review; notifications held."
	}
}

// RecoveryState never waits for action I/O. Nil/unknown is held, not permission
// to start. No pin, path, backend detail or panic is disclosed in fixed wording.
func (s *StartupSlot) RecoveryState() RecoveryState {
	if s == nil {
		return RecoveryHeld
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovery
}

// RecoverDuplicate admits D54's explicit trusted action through the SAME slot
// used for Start. The existing startup must have completely drained. No consumer,
// recovery, new startup or Drain may bypass admitted/failed recovery occupancy.
// Success only releases admission for a future explicit Start; nothing activates.
//
// Failure/panic is a fixed latched hold with no retry/reset API. Caller owns this
// synchronous invocation; it may hang forever. State/owner controls remain separate.
// Another slot, direct DiscardDuplicateTemporary/StartSession, process restart or
// escaped work bypasses this cooperating in-memory bound. Trusted persistent
// operator/config/custody/all-user quiescence remains external qualification.
func (s *StartupSlot) RecoverDuplicate(path string, expected [32]byte) error {
	return s.recoverDuplicate(path, expected, DiscardDuplicateTemporary)
}

// The operation hook is private, solely for deterministic blocked/fault models.
// Production admits only the actual duplicate-byte/pin action, never a callback.
func (s *StartupSlot) recoverDuplicate(path string, expected [32]byte, operation func(string, [32]byte) error) (err error) {
	if s == nil || expected == ([32]byte{}) || operation == nil {
		return ErrSessionConfig
	}
	s.mu.Lock()
	if s.current != nil || s.draining != nil || s.recovery != RecoveryIdle {
		s.mu.Unlock()
		return ErrStartupOccupied
	}
	s.recovery = RecoveryRunning
	s.mu.Unlock()
	err = ErrStorage // also the fixed panic result; no raw backend detail escapes
	defer func() {
		if recover() != nil {
			err = ErrStorage
		}
		s.mu.Lock()
		if err == nil {
			s.recovery = RecoveryIdle
		} else {
			s.recovery = RecoveryHeld
		}
		s.mu.Unlock()
	}()
	if operation(path, expected) != nil {
		return ErrStorage
	}
	return nil
}
