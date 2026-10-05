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
	st     harvested
}

// harvested is what the harvester persists. Tasks is written before a case
// goes to the pipeline and Added after, so a crash between the two leaves a
// task excluded from mining but not counted as evidence (fail safe, CHG-1).
type harvested struct {
	Tasks map[string]string `json:"tasks"` // case ID -> task key of its intent
	Added map[string]bool   `json:"added"` // cases the pipeline holds
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
	if h.st.Added[c.ID] {
		// A later action on the same item (UNDO after YES) is recorded in
		// the journal; the suite keeps the first.
		return nil
	}
	if _, ok := h.st.Tasks[c.ID]; !ok {
		h.st.Tasks[c.ID] = taskKey
		if err := h.saveLocked(); err != nil {
			delete(h.st.Tasks, c.ID)
			return err
		}
	}
	// A failure from here on is retryable: calling Harvest again records
	// the verdict again (the same verdict) and adds the case.
	if err := h.Pipeline.AddTaskCase(c); err != nil && !errors.Is(err, change.ErrDuplicate) {
		return err
	}
	h.st.Added[c.ID] = true
	if err := h.saveLocked(); err != nil {
		delete(h.st.Added, c.ID)
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
	h.st = harvested{}
	if b != nil {
		if err := json.Unmarshal(b, &h.st); err != nil {
			return err
		}
	}
	if h.st.Tasks == nil {
		h.st.Tasks = map[string]string{}
	}
	if h.st.Added == nil {
		h.st.Added = map[string]bool{}
	}
	h.loaded = true
	return nil
}

func (h *Harvester) saveLocked() error {
	b, err := json.Marshal(h.st)
	if err != nil {
		return err
	}
	return h.Store.Save(b)
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
	ids := make([]string, 0, len(h.st.Tasks))
	for id := range h.st.Tasks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if inDev[id] {
			continue
		}
		// A task whose case may be held out is never mined, even if the
		// pipeline may not have it; only cases it holds count.
		ev.heldTasks[h.st.Tasks[id]] = true
		if h.st.Added[id] {
			ev.HeldOut++
		}
	}
	return ev, nil
}
