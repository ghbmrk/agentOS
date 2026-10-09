package loops

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

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
	// Implicit: the owner let an auto-reply go unanswered through its
	// undo window, on time (grants GR20, owner Queued.Late). A weaker
	// good: recorded under its own source, never the owner's, capped,
	// and counted at half weight (PK2; security B1, potency C3 on #90).
	Implicit Action = "accepted-implicitly"
)

// MaxImplicitPerDay caps the implicit acceptances a guest lineage may turn
// into cases each day, so one burst of replies an injected guest wrote
// cannot flood the suite (security B1(c) on #90).
const MaxImplicitPerDay = 5

// MaxImplicitBoxPerDay caps them across every lineage, so a guest that
// renews its lineage (a recreated machine) cannot reset its cap (L3
// MUST-2 on #109).
const MaxImplicitBoxPerDay = 10

// boxKey is the box-wide count in harvested.Daily; origin keys start
// "origin:".
const boxKey = "*"

// ErrImplicitCap is Harvest's refusal of an implicit acceptance over its
// lineage's daily cap.
var ErrImplicitCap = errors.New("loops: daily cap on implicit acceptances reached")

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
		Get(id string) (journal.Status, error)
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
	// Now is the clock for the daily implicit cap. Default time.Now.
	Now func() time.Time

	mu     sync.Mutex
	loaded bool
	st     harvested
	// erased is Loop 1's ForgetIntents, set by NewLearn, so the reach
	// that erases intents drops candidates built from them too (security
	// F1 on #153).
	erased atomic.Pointer[func([]string)]
}

// harvested is what the harvester persists. Tasks is written before a case
// goes to the pipeline and Added after, so a crash between the two leaves a
// task excluded from mining but not counted as evidence (fail safe, CHG-1).
type harvested struct {
	Tasks map[string]string `json:"tasks"` // case ID -> task key of its intent
	Added map[string]bool   `json:"added"` // cases the pipeline holds
	// Origins is the origin task key of each case's intent (TaskKey with
	// no goal). A held-out case holds it too: the same guest's intents
	// with no goal land there and may be the held-out task's own work
	// (guest G14, #55 review B2).
	Origins map[string]string `json:"origins,omitempty"`
	// Implicit are the cases from implicit acceptances; Daily counts
	// each lineage's (origin task key's) on its last day.
	Implicit map[string]bool     `json:"implicit,omitempty"`
	Daily    map[string]dayCount `json:"daily,omitempty"`
	// Forgotten are intents recall's deletion reach erased (ForgetIntents):
	// never harvested again.
	Forgotten map[string]bool `json:"forgotten,omitempty"`
}

type dayCount struct {
	Day string `json:"day"`
	N   int    `json:"n"`
}

var ErrAction = errors.New("loops: unknown owner action")

// ErrForgotten is Harvest's refusal of an intent recall's deletion reach
// erased (ForgetIntents).
var ErrForgotten = errors.New("loops: the intent was erased by a deletion")

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
	case Implicit:
		q.Source = h.source() + "-implicit"
		q.Verdict, c.Outcome, c.Expect, c.Implicit = journal.VerdictGood, change.Accepted, o.Output, true
	default:
		return ErrAction
	}
	if o.Intent == "" || len(o.Input) == 0 {
		return errors.New("loops: an outcome needs its intent and the owner's task message")
	}
	// An erased intent is refused before its verdict is recorded.
	if err := h.refuseForgotten(o.Intent); err != nil {
		return err
	}
	// An implicit case takes its slot under the cap before the verdict is
	// recorded, under one lock, so concurrent harvests cannot overshoot it
	// (L3 MUST-1 on #109); kept says the slot is now this case's.
	var lineage, day string
	reserved, kept := false, false
	if c.Implicit {
		st, err := h.J.Get(o.Intent)
		if err != nil {
			return err
		}
		lineage, day = originKey(st.Intent), h.now().UTC().Format("2006-01-02")
		if reserved, err = h.reserve(c.ID, lineage, day); err != nil {
			return err
		}
		defer func() {
			if reserved && !kept {
				h.mu.Lock()
				h.releaseLocked(lineage, day)
				h.mu.Unlock()
			}
		}()
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
	if h.st.Forgotten[c.ID] {
		return ErrForgotten
	}
	if h.st.Added[c.ID] {
		// A later action on the same item (UNDO after YES) is recorded in
		// the journal; the suite keeps the first.
		return nil
	}
	if _, ok := h.st.Tasks[c.ID]; !ok {
		h.st.Tasks[c.ID] = taskKey
		h.st.Origins[c.ID] = originKey(st.Intent)
		if c.Implicit {
			h.st.Implicit[c.ID] = true
		}
		if err := h.saveLocked(); err != nil {
			delete(h.st.Tasks, c.ID)
			delete(h.st.Origins, c.ID)
			delete(h.st.Implicit, c.ID)
			return err
		}
		kept = true
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

func (h *Harvester) refuseForgotten(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.loadLocked(); err != nil {
		return err
	}
	if h.st.Forgotten[id] {
		return ErrForgotten
	}
	return nil
}

// reserve takes a slot under the lineage's and the box's daily caps for
// case id, unless the case is already counted (a retry), and reports
// whether it took one. Counts from earlier days are dropped.
func (h *Harvester) reserve(id, lineage, day string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.loadLocked(); err != nil {
		return false, err
	}
	if _, ok := h.st.Tasks[id]; ok {
		return false, nil
	}
	for k, n := range h.st.Daily {
		if n.Day != day {
			delete(h.st.Daily, k)
		}
	}
	if h.st.Daily[lineage].N >= MaxImplicitPerDay || h.st.Daily[boxKey].N >= MaxImplicitBoxPerDay {
		return false, ErrImplicitCap
	}
	for _, k := range []string{lineage, boxKey} {
		h.st.Daily[k] = dayCount{Day: day, N: h.st.Daily[k].N + 1}
	}
	return true, nil
}

// releaseLocked gives back a slot reserve took for a case that was not
// kept.
func (h *Harvester) releaseLocked(lineage, day string) {
	for _, k := range []string{lineage, boxKey} {
		if n := h.st.Daily[k]; n.Day == day && n.N > 0 {
			h.st.Daily[k] = dayCount{Day: day, N: n.N - 1}
		}
	}
}

func (h *Harvester) now() time.Time {
	if h.Now == nil {
		return time.Now()
	}
	return h.Now()
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
	if h.st.Origins == nil {
		h.st.Origins = map[string]string{}
	}
	if h.st.Implicit == nil {
		h.st.Implicit = map[string]bool{}
	}
	if h.st.Daily == nil {
		h.st.Daily = map[string]dayCount{}
	}
	if h.st.Forgotten == nil {
		h.st.Forgotten = map[string]bool{}
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

// ForgetCases drops the harvester's records of cases the pipeline forgot
// with their task (W3-tasks part 1, CAP-3; the IDs change.ForgetGoal
// returns), so the held-out evidence no longer counts them and the saved
// state no longer names them. Only the broker's handling of an
// authenticated owner forget calls it: dropping a record un-holds its task
// for mining (change TestOnlyTheDaemonForgets).
func (h *Harvester) ForgetCases(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.loadLocked(); err != nil {
		return err
	}
	for _, id := range ids {
		delete(h.st.Tasks, id)
		delete(h.st.Added, id)
		delete(h.st.Origins, id)
		delete(h.st.Implicit, id)
	}
	return h.saveLocked()
}

// ForgetIntents marks intents recall's deletion reach erases (CAP-3,
// change C19), before the journal erases them: Harvest refuses each from
// then on, so an intent still in flight cannot settle into a case that
// may hold the deleted record, and a case already harvested stops
// counting as evidence. Its task stays held (Tasks, Origins), so Loop 1
// never mines it either. Idempotent. Only the broker's deletion reach
// calls it (security F1 on #59).
func (h *Harvester) ForgetIntents(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	err := h.forgetIntents(ids)
	// After the marks, on every call whatever they did: Loop 1 drops a
	// candidate it kept from these intents before them, and keeps none
	// after them (erasedAny; security F1 on #153).
	if f := h.erased.Load(); f != nil {
		(*f)(ids)
	}
	return err
}

func (h *Harvester) forgetIntents(ids []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.loadLocked(); err != nil {
		return err
	}
	changed := false
	for _, id := range ids {
		if id == "" || (h.st.Forgotten[id] && !h.st.Added[id]) {
			continue
		}
		h.st.Forgotten[id] = true
		delete(h.st.Added, id)
		changed = true
	}
	if !changed {
		return nil
	}
	return h.saveLocked()
}

// erasedAny reports whether ForgetIntents marked any of ids; true when the
// state cannot be read, so nothing is kept on a guess.
func (h *Harvester) erasedAny(ids []string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.loadLocked(); err != nil {
		return true
	}
	for _, id := range ids {
		if h.st.Forgotten[id] {
			return true
		}
	}
	return false
}

// Evidence is what Loop 1 may know about the harvested cases: which tasks
// are held out, so it never mines them, and how many there are.
type Evidence struct {
	// HeldOut is the held-out evidence: explicit owner cases count one,
	// implicit ones half (potency C3 on #90), rounded down. Explicit is
	// the explicit cases alone.
	HeldOut, Explicit int
	// heldTasks are the task keys whose case is held out.
	heldTasks map[string]bool
	// heldIntents are the intents held-out cases were recorded on (a
	// case's ID is its intent's).
	heldIntents map[string]bool
	// Dev are the dev-split explicit task cases, the only ones a builder
	// may see.
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
	ev := Evidence{heldTasks: map[string]bool{}, heldIntents: map[string]bool{}}
	for _, c := range dev {
		// A builder never sees an implicit case, not even its ID: it has
		// no content to learn from (change C17).
		if !c.Implicit {
			ev.Dev = append(ev.Dev, c)
		}
	}
	implicit := 0
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
		ev.heldIntents[id] = true
		if o := h.st.Origins[id]; o != "" {
			ev.heldTasks[o] = true
		}
		if h.st.Added[id] {
			if h.st.Implicit[id] {
				implicit++
			} else {
				ev.Explicit++
			}
		}
	}
	ev.HeldOut = ev.Explicit + implicit/2
	return ev, nil
}
