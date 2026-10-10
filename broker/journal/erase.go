package journal

import (
	"fmt"
	"sort"
	"time"
)

// Erasure (CAP-3: deletion requests propagate). When the owner deletes a
// source, the broker erases the intents built by machines that had read it:
// their parameters, preconditions and executor evidence leave the journal,
// in memory and on disk. What stays is the audit trail OP-5 needs: who
// asked, the account, action, recipients, executor, decisions and results.
//
// Only a finished intent is erased. One still pending is denied first, and
// one authorized but not yet run fails its recheck first, so nothing runs
// on erased parameters. One in flight or with an unknown outcome is
// returned as held, to be erased once it settles.

// ErasedReason is the decision recorded on an intent stopped by an erase.
const ErasedReason = "a source it was built from was deleted"

// Since lists the intents submitted with origin at or after since, oldest
// first.
func (e *Engine) Since(origin string, since time.Time) []string {
	return e.Between(origin, since, time.Time{})
}

// Between lists the intents submitted with origin at or after from and,
// unless until is zero, before until, oldest first.
func (e *Engine) Between(origin string, from, until time.Time) []string {
	var out []string
	e.each(func(en *entry) {
		if en.between(origin, from, until) {
			out = append(out, en.intent.ID)
		}
	})
	return out
}

// StatusBetween is Between with each intent's status, read in one pass.
func (e *Engine) StatusBetween(origin string, from, until time.Time) []Status {
	var out []Status
	e.each(func(en *entry) {
		if en.between(origin, from, until) {
			out = append(out, en.status())
		}
	})
	return out
}

func (en *entry) between(origin string, from, until time.Time) bool {
	return en.intent.Origin == origin && !en.submitted.Before(from) && (until.IsZero() || en.submitted.Before(until))
}

// Erase removes the content of the given intents (see above) and rewrites
// the journal so no copy remains in the live file. It returns the intents
// erased now and those held because they are in flight or unresolved.
// Unknown and already erased IDs are skipped.
func (e *Engine) Erase(ids []string) (erased, held []string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return nil, nil, e.broken
	}
	// Evicted denials come back for the erase, and stay until it is done.
	if err := e.rehydrate(ids); err != nil {
		return nil, nil, err
	}
	e.pinned = true
	defer func() { e.pinned = false; e.trim() }()
	for _, id := range ids {
		en := e.intents[id]
		if en == nil || en.erased {
			continue
		}
		switch en.state {
		case Pending:
			if err := e.commit(Record{Type: RecDenied, ID: id, Reason: ErasedReason}); err != nil {
				return erased, held, err
			}
		case Authorized, NotApplied:
			if err := e.commit(Record{Type: RecRecheckFailed, ID: id, Reason: ErasedReason}); err != nil {
				return erased, held, err
			}
		case InFlight, OutcomeUnknown:
			held = append(held, id)
			continue
		}
		if err := e.commit(Record{Type: RecErased, ID: id, FP: en.fp, EFP: en.efp}); err != nil {
			return erased, held, err
		}
		erased = append(erased, id)
	}
	if len(erased) == 0 {
		return nil, held, nil
	}
	return erased, held, e.rewriteErased()
}

// unerased reports whether a record still carries content of an intent
// the journal records as erased.
func unerased(recs []Record) bool {
	erased := erasedIDs(recs)
	for _, r := range recs {
		if erased[r.ID] && carries(r) {
			return true
		}
	}
	return false
}

func erasedIDs(recs []Record) map[string]bool {
	out := map[string]bool{}
	for _, r := range recs {
		if r.Type == RecErased {
			out[r.ID] = true
		}
	}
	return out
}

func carries(r Record) bool {
	switch r.Type {
	case RecSubmitted:
		return r.Intent != nil && (r.Intent.Params != nil || r.Intent.Preconditions != nil)
	case RecObserved, RecCancel:
		return r.Evidence != ""
	}
	return false
}

// rewriteErased rewrites the journal with erased intents' content removed
// from every record. Records keep their sequence numbers and times, and
// replaying the result gives the same state. A failed rewrite breaks the
// engine, as a failed append does. Caller holds mu (or is Open).
func (e *Engine) rewriteErased() error {
	recs, err := e.readJournal()
	if err != nil {
		return err
	}
	erased := erasedIDs(recs)
	var buf []byte
	for _, r := range recs {
		if erased[r.ID] && carries(r) {
			if r.Intent != nil {
				in := *r.Intent
				in.Params, in.Preconditions = nil, nil
				r.Intent = &in
			}
			if r.Type == RecObserved || r.Type == RecCancel {
				r.Evidence = ""
			}
		}
		line, err := encodeRecord(r)
		if err != nil {
			return err
		}
		buf = append(buf, line...)
	}
	if err := e.store.Rewrite(buf); err != nil {
		e.broken = fmt.Errorf("%w: erase rewrite: %v", ErrBroken, err)
		return e.broken
	}
	return nil
}

// Erased lists erased intents, sorted (for reports and tests).
func (e *Engine) Erased() []string {
	var out []string
	e.each(func(en *entry) {
		if en.erased {
			out = append(out, en.intent.ID)
		}
	})
	sort.Strings(out)
	return out
}
