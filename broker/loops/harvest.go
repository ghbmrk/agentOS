package loops

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// Owner actions Harvest turns into OP-7 verdicts and held-out cases
// (change ASSUMPTIONS C14 (a)).
type Action string

const (
	// Approved: the owner said YES to the item as the agent made it.
	Approved Action = "approved"
	// Edited: the owner changed the item before it went out; the edit is
	// the reference.
	Edited Action = "edited"
	// Denied: the owner said NO.
	Denied Action = "denied"
	// Undone: the owner undid the effect (UNDO).
	Undone Action = "undone"
)

// Outcome is one owner action on an item an agent made.
type Outcome struct {
	// Intent is the journal intent the owner acted on.
	Intent string
	Action Action
	// Input is the owner's task message the item answered; Output is the
	// item as the agent made it; Correction is the owner's edit (Edited).
	Input, Output, Correction []byte
	// Public marks a task whose every input was labelled public (REV-5).
	Public bool
}

// Harvester records owner outcomes. The owner channel calls it after the
// owner's action is authenticated (CH-10); nothing else may, since a
// verdict with the owner source is evidence the suite trusts (CHG-1,
// CAP-3).
type Harvester struct {
	J interface {
		RecordQuality(id string, q journal.Quality) (journal.Status, error)
	}
	Pipeline interface {
		AddTaskCase(change.Case) error
		Dev(change.Class) []change.Case
	}
	Store change.Store
	// Source is the owner's verdict source (change.Config.OwnerSource).
	// Default "owner".
	Source string
	// Wake, if set, is told about new evidence (the scheduler's Wake).
	Wake func()

	mu     sync.Mutex
	loaded bool
	added  map[string]string // case ID -> task key of its intent
}

var ErrAction = errors.New("loops: unknown owner action")

// Harvest records the owner's verdict on the intent (OP-7) and adds the
// task case it makes (CHG-1). The case is one ClassTask case per intent:
// evidence for every change to how tasks are done. An approved item is
// good and its output is the reference; an edit is wrong with the edit as
// the reference; NO and UNDO are wrong, and a candidate must not
// reproduce the rejected output.
func (h *Harvester) Harvest(o Outcome) error {
	c := change.Case{ID: o.Intent, Class: change.ClassTask, Input: o.Input, Task: o.Intent, Public: o.Public}
	q := journal.Quality{Source: h.source(), Note: "owner " + string(o.Action)}
	switch o.Action {
	case Approved:
		q.Verdict, c.Outcome, c.Expect = journal.VerdictGood, change.Accepted, o.Output
	case Edited:
		if len(o.Correction) == 0 {
			return fmt.Errorf("%w: an edit needs the owner's correction", ErrAction)
		}
		q.Verdict, c.Outcome, c.Expect = journal.VerdictWrong, change.Corrected, o.Correction
	case Denied, Undone:
		q.Verdict, c.Outcome, c.Expect = journal.VerdictWrong, change.Rejected, o.Output
	default:
		return ErrAction
	}
	if o.Intent == "" || len(o.Input) == 0 {
		return errors.New("loops: an outcome needs its intent and the owner's task message")
	}
	st, err := h.J.RecordQuality(o.Intent, q)
	if err != nil {
		return err
	}
	taskKey := TaskKey(st.Intent)
	// The journal's REV-5 label is authoritative: the caller's mark can
	// only narrow it, since Public decides what may be shared (CHG-5).
	c.Public = o.Public && st.Intent.Label == "public"
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.loadLocked(); err != nil {
		return err
	}
	if err := h.Pipeline.AddTaskCase(c); err != nil {
		if errors.Is(err, change.ErrDuplicate) {
			// A later action on the same item (UNDO after YES) is
			// recorded in the journal; the suite keeps the first.
			return nil
		}
		return err
	}
	h.added[c.ID] = taskKey
	b, _ := json.Marshal(h.added)
	if err := h.Store.Save(b); err != nil {
		return err
	}
	if h.Wake != nil {
		h.Wake()
	}
	return nil
}

func (h *Harvester) source() string {
	if h.Source == "" {
		return "owner"
	}
	return h.Source
}

func (h *Harvester) loadLocked() error {
	if h.loaded {
		return nil
	}
	b, err := h.Store.Load()
	if err != nil {
		return err
	}
	h.added = map[string]string{}
	if b != nil {
		if err := json.Unmarshal(b, &h.added); err != nil {
			return err
		}
	}
	h.loaded = true
	return nil
}

// Evidence is what Loop 1 may know about the harvested cases: which tasks
// are held out, so it never mines them, and how many there are.
type Evidence struct {
	HeldOut int
	// heldTasks are the task keys whose case is held out.
	heldTasks map[string]bool
	// Dev are the dev-split task cases, the only ones a builder may see.
	Dev []change.Case
}

// Held reports whether a task (its goal key) has a held-out case.
func (e Evidence) Held(task string) bool { return e.heldTasks[task] }

// Evidence splits the harvested cases into dev and held out (CHG-1).
func (h *Harvester) Evidence() (Evidence, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.loadLocked(); err != nil {
		return Evidence{}, err
	}
	dev := h.Pipeline.Dev(change.ClassTask)
	inDev := map[string]bool{}
	for _, c := range dev {
		inDev[c.ID] = true
	}
	ev := Evidence{heldTasks: map[string]bool{}, Dev: dev}
	ids := make([]string, 0, len(h.added))
	for id := range h.added {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !inDev[id] {
			ev.HeldOut++
			ev.heldTasks[h.added[id]] = true
		}
	}
	return ev, nil
}
