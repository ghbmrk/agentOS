package modelroute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// OwnerNoteKind is one of the vault process's notices for the owner
// (egress K6). The set is closed: the vault process says which notice,
// never its text, and agentosd words it (L3 on #142: agentosd never shows
// text the vault process supplied).
type OwnerNoteKind string

const (
	NoteWrongPassphrase OwnerNoteKind = "wrong_passphrase" // N: how many
	NoteUnlockPending   OwnerNoteKind = "unlock_pending"
	NoteUnlockRestarted OwnerNoteKind = "unlock_restarted"
	NoteWrongCode       OwnerNoteKind = "wrong_code"
	NoteCodeLockout     OwnerNoteKind = "code_lockout"
	NoteUnlockExpired   OwnerNoteKind = "unlock_expired"
	NoteUnlocked        OwnerNoteKind = "unlocked"
	NoteUnlockedTrusted OwnerNoteKind = "unlocked_trusted"
	NoteWrongBootPIN    OwnerNoteKind = "wrong_boot_pin"
	NoteBootPINLockout  OwnerNoteKind = "boot_pin_lockout"
	NoteChipSilent      OwnerNoteKind = "chip_silent"
	NoteCounterReset    OwnerNoteKind = "counter_reset"
	NoteRolledBack      OwnerNoteKind = "rolled_back"
	NoteChangedBoot     OwnerNoteKind = "changed_boot"
	NoteTrustedAdded    OwnerNoteKind = "trusted_added"
	NoteTrustedRemoved  OwnerNoteKind = "trusted_removed"
	NoteLineReplaced    OwnerNoteKind = "line_replaced"
	NoteLineRemoved     OwnerNoteKind = "line_removed"
	NoteTextsMissed     OwnerNoteKind = "texts_missed"
)

// OwnerNoteKinds is every kind, in no particular order.
var OwnerNoteKinds = []OwnerNoteKind{
	NoteWrongPassphrase, NoteUnlockPending, NoteUnlockRestarted, NoteWrongCode,
	NoteCodeLockout, NoteUnlockExpired, NoteUnlocked, NoteUnlockedTrusted,
	NoteWrongBootPIN, NoteBootPINLockout, NoteChipSilent, NoteCounterReset,
	NoteRolledBack, NoteChangedBoot, NoteTrustedAdded, NoteTrustedRemoved,
	NoteLineReplaced, NoteLineRemoved, NoteTextsMissed,
}

// Known reports whether k is one of OwnerNoteKinds.
func (k OwnerNoteKind) Known() bool {
	for _, x := range OwnerNoteKinds {
		if k == x {
			return true
		}
	}
	return false
}

// OwnerNote is one notice: its kind and, for NoteWrongPassphrase, a count.
type OwnerNote struct {
	Kind OwnerNoteKind `json:"kind"`
	N    int           `json:"n,omitempty"`
}

const (
	// MaxOwnerNotes bounds the notices the vault process keeps for
	// agentosd, and the ones agentosd takes in one answer.
	MaxOwnerNotes = 32
	// MaxNoteCount bounds a notice's count.
	MaxNoteCount = 9999
)

// OwnerNotesReply is the verify socket's answer to POST /owner-notes.
type OwnerNotesReply struct {
	Notes   []OwnerNote `json:"notes"`
	Dropped int         `json:"dropped,omitempty"`
}

// OwnerNotes takes the vault process's notices for the owner, oldest
// first; each is given once. It works while the vault is locked, when
// most of them happen. Notices of an unknown kind or with an out-of-range
// count, and those past MaxOwnerNotes, are skipped and counted in dropped
// with the ones the vault process itself dropped.
func (v *Verifier) OwnerNotes(ctx context.Context) ([]OwnerNote, int, error) {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/owner-notes"} // over the Unix socket
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := v.c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("owner notes: vault process answered %s", resp.Status)
	}
	var out OwnerNotesReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&out); err != nil {
		return nil, 0, err
	}
	if out.Dropped < 0 || out.Dropped > MaxNoteCount {
		return nil, 0, fmt.Errorf("owner notes: dropped count %d", out.Dropped)
	}
	notes, dropped := make([]OwnerNote, 0, len(out.Notes)), out.Dropped
	for _, n := range out.Notes {
		if !n.Kind.Known() || n.N < 0 || n.N > MaxNoteCount || len(notes) == MaxOwnerNotes {
			dropped++
			continue
		}
		notes = append(notes, n)
	}
	return notes, dropped, nil
}
