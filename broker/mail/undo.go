package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// UndoWindow is how long a digest's UNDO stays valid (ADP-2).
const UndoWindow = 7 * 24 * time.Hour

// ParseChange reads an organize effect's journaled evidence.
func ParseChange(evidence string) (Change, error) {
	var c Change
	if err := json.Unmarshal([]byte(evidence), &c); err != nil || c.Record == "" || c.From == "" {
		return Change{}, errors.New("mail: evidence is not an organize change")
	}
	if _, ok := byName[c.Op]; !ok {
		return Change{}, ErrOp
	}
	return c, nil
}

// UndoReport is what an UNDO did.
type UndoReport struct {
	Restored, Skipped int
}

// Text is the owner's reply to an UNDO, e.g. "Restored 47; 3 skipped
// (changed since)".
func (r UndoReport) Text() string {
	if r.Skipped == 0 {
		return fmt.Sprintf("Restored %d.", r.Restored)
	}
	return fmt.Sprintf("Restored %d; %d skipped (changed since).", r.Restored, r.Skipped)
}

// Undo restores organized items (ADP-2's UNDO). Each item is restored
// only if its current state still matches what the agent set: still in the
// folder the effect moved it to, with the flags it added and without the
// ones it removed. Anything else, including an item no longer found, is
// skipped, so an undo never overrides a change made since. Trash and spam
// moves are not organize effects and are skipped, as is evidence from a
// reconciliation, which holds no prior state. The check and the restore
// are separate IMAP commands (no CONDSTORE), so a change landing between
// them is overwritten (ASSUMPTIONS M9); each restore acts only under the
// UID validity the check read, so a mailbox rebuilt between them never
// has its reused UID restored (SR3-5).
func (a *Adapter) Undo(ctx context.Context, changes []Change) UndoReport {
	var r UndoReport
	for _, c := range changes {
		if a.undoOne(ctx, c) {
			r.Restored++
		} else {
			r.Skipped++
		}
	}
	return r
}

func (a *Adapter) undoOne(ctx context.Context, c Change) bool {
	if o, ok := byName[c.Op]; !ok || o.Inverse == "" || c.Reconciled {
		return false
	}
	at := c.From
	if c.To != "" {
		at = c.To
	}
	ms, err := a.cfg.Store.Find(ctx, at, c.Record)
	if err != nil || len(ms) != 1 {
		return false
	}
	m := ms[0]
	// A flag change names the message it found; under another UID
	// validity the folder was rebuilt since, and a same-ID message there
	// is not shown to be the one the agent changed (SR3-5).
	if c.To == "" && c.Validity != 0 && m.Ref() != (Ref{Folder: c.From, Validity: c.Validity, UID: c.UID}) {
		return false
	}
	for _, f := range c.Added {
		if !has(m.Flags, f) {
			return false
		}
	}
	for _, f := range c.Removed {
		if has(m.Flags, f) {
			return false
		}
	}
	if len(c.Added)+len(c.Removed) > 0 {
		if a.cfg.Store.SetFlags(ctx, m.Ref(), c.Removed, c.Added) != nil {
			return false
		}
	}
	if c.To != "" && c.To != c.From {
		if a.cfg.Store.Move(ctx, m.Ref(), c.From) != nil {
			return false
		}
	}
	return true
}

// Digest is the daily digest's organize line (ADP-2): counts by action,
// the senders most affected (by domain, clipped, so the line fits a text),
// guard hits, and the UNDO that restores them.
type Digest struct {
	ByAction   map[string]int
	TopSenders []string
	GuardHits  int
	Total      int
}

// Summarize counts a day's organize changes.
func Summarize(changes []Change) Digest {
	d := Digest{ByAction: map[string]int{}}
	senders := map[string]int{}
	for _, c := range changes {
		if o, ok := byName[c.Op]; !ok || o.Inverse == "" {
			continue
		}
		d.Total++
		d.ByAction[describe(c.Op)]++
		if dom := domainOf(c.Sender); dom != "" {
			senders[clip(dom, 24)]++
		}
		if c.Alert {
			d.GuardHits++
		}
	}
	for s := range senders {
		d.TopSenders = append(d.TopSenders, s)
	}
	sort.Slice(d.TopSenders, func(i, j int) bool {
		x, y := d.TopSenders[i], d.TopSenders[j]
		return senders[x] > senders[y] || senders[x] == senders[y] && x < y
	})
	if len(d.TopSenders) > 3 {
		d.TopSenders = d.TopSenders[:3]
	}
	return d
}

// Line renders the digest line in fixed wording, with the undo ID and the
// day it lapses.
func (d Digest) Line(undoID string, until time.Time) string {
	if d.Total == 0 {
		return ""
	}
	var acts []string
	for k, n := range d.ByAction {
		acts = append(acts, fmt.Sprintf("%d %s", n, k))
	}
	sort.Strings(acts)
	s := fmt.Sprintf("Mail organized: %d (%s).", d.Total, strings.Join(acts, ", "))
	if len(d.TopSenders) > 0 {
		s += " Most from " + strings.Join(d.TopSenders, ", ") + "."
	}
	if d.GuardHits > 0 {
		s += fmt.Sprintf(" %d security alerts labelled but left in the inbox.", d.GuardHits)
	}
	return s + fmt.Sprintf(" UNDO %s until %s. MORE %s lists them.", undoID, until.Format("Mon Jan 2"), undoID)
}
