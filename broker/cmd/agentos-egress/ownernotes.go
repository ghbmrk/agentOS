package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/modelroute"
)

// ownerNotes keeps the vault process's notices for the owner until
// agentosd takes them over the verify socket and texts them in its own
// wording (egress K6). Only a notice's kind and count are kept, never its
// text (L3 on #142). It has its own lock: the custody notifies with its
// lock held.
type ownerNotes struct {
	mu      sync.Mutex
	notes   []modelroute.OwnerNote
	dropped int
}

func newOwnerNotes() *ownerNotes { return &ownerNotes{} }

// add queues the notice s if it has a kind; past MaxOwnerNotes the
// oldest is dropped and counted.
func (q *ownerNotes) add(s string) {
	n, ok := classifyNote(s)
	if q == nil || !ok {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.notes) == modelroute.MaxOwnerNotes {
		q.notes = append(q.notes[:0], q.notes[1:]...)
		if q.dropped < modelroute.MaxNoteCount {
			q.dropped++
		}
	}
	q.notes = append(q.notes, n)
}

// take hands over the queued notices, oldest first, and the count of
// those dropped, and clears both.
func (q *ownerNotes) take() ([]modelroute.OwnerNote, int) {
	if q == nil {
		return nil, 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	notes, dropped := q.notes, q.dropped
	q.notes, q.dropped = nil, 0
	return notes, dropped
}

// Notices whose wording carries a count or a name, matched by shape.
const (
	wrongPassNote   = "wrong vault passphrase tried on the box's Wi-Fi"
	wrongPassMore   = " (%d more since the last notice)"
	wrongPassQuiet  = "%d more wrong vault passphrases were tried on the box's Wi-Fi since the last notice"
	restartedPrefix = "The box unlock was started over "
	trustedPrefix   = "this PC is now a trusted host"
)

// ownerNoteKinds maps the notices with fixed wording to their kind.
var ownerNoteKinds = map[string]modelroute.OwnerNoteKind{
	"vault passphrase accepted; waiting for a code-generator code": modelroute.NoteUnlockPending,
	"wrong code for a vault unlock":                                modelroute.NoteWrongCode,
	"too many wrong codes for a vault unlock; key discarded":       modelroute.NoteCodeLockout,
	"vault unlock expired without a code; key discarded":           modelroute.NoteUnlockExpired,
	"vault unlocked":                                        modelroute.NoteUnlocked,
	"vault unlocked on this trusted host":                   modelroute.NoteUnlockedTrusted,
	"vault unlocked on this trusted host with its boot PIN": modelroute.NoteUnlockedTrusted,
	"wrong boot PIN on this trusted host":                   modelroute.NoteWrongBootPIN,
	"this PC's TPM locked out after wrong boot PINs":        modelroute.NoteBootPINLockout,
	noteTPMSilent:    modelroute.NoteChipSilent,
	noteCounterReset: modelroute.NoteCounterReset,
	noteRolledBack:   modelroute.NoteRolledBack,
	"This PC started the box in a way it hasn't before. If you didn't change anything, the drive may have been tampered with. Unlock only if you're sure.": modelroute.NoteChangedBoot,
	"a trusted host was removed": modelroute.NoteTrustedRemoved,
	noteSIPReplaced:              modelroute.NoteLineReplaced,
	noteSMSReplaced:              modelroute.NoteLineReplaced,
	noteSIPRemoved:               modelroute.NoteLineRemoved,
	noteSMSRemoved:               modelroute.NoteLineRemoved,
	noteSMSMissed:                modelroute.NoteTextsMissed,
}

// classifyNote says which owner notice s is. A notice it does not know
// stays in the log only.
func classifyNote(s string) (modelroute.OwnerNote, bool) {
	if k, ok := ownerNoteKinds[s]; ok {
		return modelroute.OwnerNote{Kind: k}, true
	}
	switch {
	case s == wrongPassNote:
		return modelroute.OwnerNote{Kind: modelroute.NoteWrongPassphrase, N: 1}, true
	case strings.HasPrefix(s, wrongPassNote):
		if n, ok := count(strings.TrimPrefix(s, wrongPassNote), wrongPassMore); ok {
			return modelroute.OwnerNote{Kind: modelroute.NoteWrongPassphrase, N: min(n+1, modelroute.MaxNoteCount)}, true
		}
	case strings.HasPrefix(s, restartedPrefix):
		return modelroute.OwnerNote{Kind: modelroute.NoteUnlockRestarted}, true
	case strings.HasPrefix(s, trustedPrefix+":"), strings.HasPrefix(s, trustedPrefix+", "):
		return modelroute.OwnerNote{Kind: modelroute.NoteTrustedAdded}, true
	default:
		if n, ok := count(s, wrongPassQuiet); ok {
			return modelroute.OwnerNote{Kind: modelroute.NoteWrongPassphrase, N: n}, true
		}
	}
	return modelroute.OwnerNote{}, false
}

// count reads the one %d of format back out of s, which must be exactly
// format with a positive count in it.
func count(s, format string) (int, bool) {
	var n int
	if _, err := fmt.Sscanf(s, format, &n); err != nil || n < 1 || fmt.Sprintf(format, n) != s {
		return 0, false
	}
	return min(n, modelroute.MaxNoteCount), true
}
