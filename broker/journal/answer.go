package journal

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// RecAnswer journals the owner's answer on a pending intent before the
// broker acts on it (OP-12, SM-AJ-1), so a restart rebuilds the answer
// rather than asking again or losing it (OP-11, SM-AJ-2, SM-AJ-3). It
// changes no state: the authorize or denied record that follows does.
const RecAnswer RecordType = "owner_answer"

// AnswerNote is what the gate needs to rebuild one answer. It holds no
// approval code, no item text and no parameters (Invariant C): the item
// is kept only as its digest, which an erase blanks (CAP-3).
type AnswerNote struct {
	// Approved is the owner's verdict; Confirm marks a confirmation on the
	// local page that carries no verdict (CH-3).
	Approved bool `json:"approved,omitempty"`
	Confirm  bool `json:"confirm,omitempty"`
	// Why is the owner's reason or the broker's code for it ("owner",
	// "expired", "undo window passed"): fixed broker text, never typed by
	// the owner.
	Why string `json:"why,omitempty"`
	// Request is the owner request the answer closed (an auto-reply's ID
	// for a release).
	Request string `json:"request,omitempty"`
	// Sum is owner.ItemSum of the item the owner was asked.
	Sum string `json:"sum,omitempty"`
	// Local: the item also needs the local page; Confirmed: the page
	// confirmed it with this answer.
	Local     bool `json:"local,omitempty"`
	Confirmed bool `json:"confirmed,omitempty"`
	// Asked, Implicit and Late are the gate's decision marks (the answer
	// closed a waiting request; an auto-reply released unanswered; one
	// released late).
	Asked    bool `json:"asked,omitempty"`
	Implicit bool `json:"implicit,omitempty"`
	Late     bool `json:"late,omitempty"`
	// Hold marks an answer on a held effect (REV-3), which the owner
	// channel's boot settles; the gate does not rebuild it.
	Hold bool `json:"hold,omitempty"`
	// Tries is how many attempts the intent had when the owner answered:
	// the approval covers the next one only (GR8).
	Tries int `json:"tries,omitempty"`
	// Went and Unclear are the intent IDs of repeats the approved line
	// showed (grants decision.covers).
	Went    []string `json:"went,omitempty"`
	Unclear []string `json:"unclear,omitempty"`
}

// maxAnswerText bounds Why and each repeat ID.
const maxAnswerText = 256

func (n AnswerNote) valid() bool {
	if n.Confirm && (n.Approved || n.Why != "" || n.Sum != "") {
		return false
	}
	if !plain(n.Why) || token(n.Request) != n.Request || n.Tries < 0 {
		return false
	}
	if n.Sum != "" && !hex64(n.Sum) {
		return false
	}
	for _, ids := range [][]string{n.Went, n.Unclear} {
		for _, id := range ids {
			if id == "" || !plain(id) {
				return false
			}
		}
	}
	return true
}

// plain is short printable text on one line.
func plain(s string) bool {
	if len(s) > maxAnswerText || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
	}
	return true
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// RecordAnswer journals the owner's answer on pending intent id. It
// fails, and the caller must not act on the answer, when the note is
// malformed, the intent is not pending, or the journal cannot take it.
func (e *Engine) RecordAnswer(id string, n AnswerNote) error {
	if !n.valid() {
		return fmt.Errorf("%w: answer note needs code-like fields and a digest", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	return e.commit(Record{Type: RecAnswer, ID: id, Answer: &n})
}
