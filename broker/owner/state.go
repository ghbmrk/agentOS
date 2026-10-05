package owner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the owner channel's durable state. It survives restarts so that a
// reboot cannot reopen a used grid cell, replay a used code-generator step,
// forget recent wrong codes, or drop a lockout (CH-18).
type State struct {
	// UnlockedUntil ends the current session unlock (CH-3, CH-14).
	UnlockedUntil time.Time `json:"unlocked_until"`
	// Locks counts session locks. Anything signed in under an earlier
	// count, such as a local UI device, is signed out.
	Locks uint64 `json:"locks"`
	// LastStep is the newest code-generator time step accepted; older and
	// equal steps are refused, so each generator code works once.
	LastStep int64 `json:"last_step"`
	// GridUsed lists spent grid cells.
	GridUsed []string `json:"grid_used,omitempty"`
	// Wrong holds the times of wrong codes of any kind in the last 24 h.
	Wrong []time.Time `json:"wrong,omitempty"`
	// LowLocked: texted codes are off until a code-generator unlock.
	LowLocked bool `json:"low_locked"`
	// ClearedAt is the last code-generator unlock. Only wrong codes after
	// it count toward WrongToLock and WrongToChallenge.
	ClearedAt time.Time `json:"cleared_at"`
	// Challenged is challenge mode (O4): codes count only inside a reply
	// carrying the texted challenge. BoundStart and BoundUsed are the
	// fixed 24-hour window of counted challenge attempts.
	Challenged bool      `json:"challenged"`
	BoundStart time.Time `json:"bound_start"`
	BoundUsed  int       `json:"bound_used"`
	// LocalStart and LocalUsed are the fixed 24-hour window of local UI
	// sign-in attempts (LocalBound).
	LocalStart time.Time `json:"local_start"`
	LocalUsed  int       `json:"local_used"`
	// LocalSignIns lists local sign-ins not yet texted to the owner, and
	// LocalAlertAt is the last such text (SignInAlertEvery).
	LocalSignIns []time.Time `json:"local_sign_ins,omitempty"`
	LocalAlertAt time.Time   `json:"local_alert_at"`
	// Pending lists open requests and Queued the auto-replies waiting out
	// their undo window, by reference only (never codes or reply text), so
	// a restart can report what it dropped (OP-4, CH-13).
	Pending []PendingRef `json:"pending,omitempty"`
	Queued  []QueuedRef  `json:"queued,omitempty"`
	// Retired holds IDs closed in the last RetireFor, which are not reused.
	Retired map[string]time.Time `json:"retired,omitempty"`
}

// PendingRef is an open request as a restart sees it. Asked, Expires,
// and Sums (ItemSum of each item, in Refs order) let the caller re-issue
// an item that has not expired and has not changed (Config.Reissue). A
// record without them, from an older build, is cancelled.
type PendingRef struct {
	ID      string    `json:"id"`
	Refs    []string  `json:"refs"`
	Asked   time.Time `json:"asked,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
	Sums    []string  `json:"sums,omitempty"`
}

// QueuedRef is a queued auto-reply as a restart sees it.
type QueuedRef struct {
	ID  string `json:"id"`
	Ref string `json:"ref"`
}

// Store persists State.
type Store interface {
	Load() (State, error)
	Save(State) error
}

// MemStore keeps State in memory (tests, simulator runs).
type MemStore struct {
	mu sync.Mutex
	s  State
}

func (m *MemStore) Load() (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyState(m.s), nil
}
func (m *MemStore) Save(s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.s = copyState(s)
	return nil
}

func copyState(s State) State {
	s.GridUsed = append([]string(nil), s.GridUsed...)
	s.Wrong = append([]time.Time(nil), s.Wrong...)
	s.LocalSignIns = append([]time.Time(nil), s.LocalSignIns...)
	s.Pending = append([]PendingRef(nil), s.Pending...)
	s.Queued = append([]QueuedRef(nil), s.Queued...)
	r := make(map[string]time.Time, len(s.Retired))
	for k, v := range s.Retired {
		r[k] = v
	}
	s.Retired = r
	return s
}

// FileStore keeps State in one JSON file, replaced atomically.
type FileStore struct{ Path string }

func (f FileStore) Load() (State, error) {
	var s State
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func (f FileStore) Save(s State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".owner-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(f.Path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
