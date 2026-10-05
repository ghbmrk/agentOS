package journal

import "fmt"

// RecSleep journals the agent machine going to sleep or waking (PE7).
const RecSleep RecordType = "sleep"

// The events a SleepNote records.
const (
	SleepAsleep = "asleep"       // stopped with its memory saved, while the box learns
	SleepFailed = "sleep_failed" // a sleep that did not happen; the agent runs on
	SleepAwake  = "awake"        // running again
)

// SleepNote is one sleep or wake of an agent machine (PE7 condition 12).
// Every field is an identifier-like code (the sleeper's fixed causes and
// vm's cold reasons), never free text, so it is kept as written.
type SleepNote struct {
	Machine string `json:"machine"`
	Event   string `json:"event"`
	// Cause is why it woke; Cold, for a wake without its memory, why.
	Cause string `json:"cause,omitempty"`
	Cold  string `json:"cold,omitempty"`
}

func (n SleepNote) valid() bool {
	switch n.Event {
	case SleepAsleep, SleepFailed, SleepAwake:
	default:
		return false
	}
	return n.Machine != "" && token(n.Machine) == n.Machine && token(n.Cause) == n.Cause && token(n.Cold) == n.Cold
}

// RecordSleep journals a sleep or wake. It is audit only: it changes no
// intent, and STOP does not hold it.
func (e *Engine) RecordSleep(n SleepNote) error {
	if !n.valid() {
		return fmt.Errorf("%w: sleep note needs a machine, a known event and code-like fields", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	return e.commit(Record{Type: RecSleep, Sleep: &n})
}
