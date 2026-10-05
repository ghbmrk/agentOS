package main

import (
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/loops"
)

// Task texts are kept for harvesting (W3, potency PW3 on #90): a case's
// input is the owner's task message the agent's item answered (loops L6),
// and the journal holds only its goal ID. Only the owner's task chat to
// the agent machine is kept, never a replay's; at most maxTasks, none
// past keepTasks, in the learn directory, which only the broker reads.
const (
	maxTasks  = 512
	keepTasks = 30 * 24 * time.Hour
	// maxVerdicts bounds the owner verdicts waiting to be harvested; more
	// are dropped, with a fixed log line.
	maxVerdicts = 256
)

type taskText struct {
	Text   string    `json:"text"`
	Public bool      `json:"public,omitempty"`
	At     time.Time `json:"at"`
}

type taskTexts struct {
	store change.Store
	now   func() time.Time
	logf  func(string, ...any)

	mu sync.Mutex
	st map[string]taskText
}

func openTaskTexts(store change.Store, now func() time.Time, logf func(string, ...any)) (*taskTexts, error) {
	t := &taskTexts{store: store, now: now, logf: logf, st: map[string]taskText{}}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &t.st); err != nil {
			return nil, errors.New("task texts: corrupt state")
		}
		if t.st == nil {
			t.st = map[string]taskText{}
		}
	}
	// Expired texts go at start too, not only on the next task (security
	// A3 on PW3).
	t.mu.Lock()
	n := len(t.st)
	t.pruneLocked(now())
	if len(t.st) != n {
		t.saveLocked()
	}
	t.mu.Unlock()
	return t, nil
}

// put keeps the task text for goal. A failed save is logged: harvesting
// then skips that task, and the owner's message is delivered regardless.
func (t *taskTexts) put(goal, text string, public bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.st[goal] = taskText{Text: text, Public: public, At: now}
	t.pruneLocked(now)
	t.saveLocked()
}

func (t *taskTexts) saveLocked() {
	b, err := json.Marshal(t.st)
	if err == nil {
		err = t.store.Save(b)
	}
	if err != nil {
		t.logf("learning: task texts not saved: %v", err)
	}
}

func (t *taskTexts) pruneLocked(now time.Time) {
	goals := make([]string, 0, len(t.st))
	for g, x := range t.st {
		if now.Sub(x.At) > keepTasks {
			delete(t.st, g)
			continue
		}
		goals = append(goals, g)
	}
	if len(goals) <= maxTasks {
		return
	}
	sort.Slice(goals, func(i, j int) bool { return t.st[goals[i]].At.After(t.st[goals[j]].At) })
	for _, g := range goals[maxTasks:] {
		delete(t.st, g)
	}
}

func (t *taskTexts) get(goal string) (taskText, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	x, ok := t.st[goal]
	if !ok || t.now().Sub(x.At) > keepTasks {
		return taskText{}, false
	}
	return x, true
}

// harvester is loops.Harvester as harvestOutcome uses it.
type harvester interface {
	Harvest(loops.Outcome) error
}

// harvestOutcome records the owner's final verdict on an agent's effect
// (grants.Config.Outcome) as a Loop 1 case. Implicit acceptance waits for
// a verdict strength the pipeline does not have yet (potency PK2). With no
// task text kept for its goal, there is no case input, so nothing is
// recorded. Only a fixed class is logged, never the item or the task.
func harvestOutcome(h harvester, tasks *taskTexts, o grants.OwnerOutcome, logf func(string, ...any)) {
	var a loops.Action
	switch o.Verdict {
	case grants.OwnerAccepted:
		a = loops.Approved
	case grants.OwnerDeclined:
		a = loops.Denied
	case grants.OwnerUndone:
		a = loops.Undone
	case grants.OwnerAcceptedImplicitly:
		a = loops.Implicit
	default:
		return
	}
	task, ok := tasks.get(o.Intent.GoalID)
	if !ok {
		logf("learning: owner verdict not harvested: no task text for its goal")
		return
	}
	out, err := json.Marshal(o.Intent.Params)
	if err != nil {
		return
	}
	switch err := h.Harvest(loops.Outcome{Intent: o.Intent.ID, Action: a, Input: []byte(task.Text), Output: out, Public: task.Public}); {
	case errors.Is(err, loops.ErrImplicitCap):
		logf("learning: owner verdict not harvested: daily cap on implicit acceptances")
	case err != nil:
		logf("learning: owner verdict not harvested: refused") // the error may quote the case
	}
}
