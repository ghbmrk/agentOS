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
	// Via is the channel the task came in on: viaSMS for the owner's
	// texts. Only an SMS task's text is ever texted back (FORGET's list,
	// security C2 on W3-forget); empty, from before this was kept, is
	// treated as not SMS.
	Via string `json:"via,omitempty"`
}

// viaSMS marks a task the owner texted.
const viaSMS = "sms"

type taskTexts struct {
	store change.Store
	now   func() time.Time
	logf  func(string, ...any)

	mu sync.Mutex
	// dirty: the last save failed, so memory may hold less than the
	// file (security R1 on #123).
	dirty bool
	st    map[string]taskText
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
func (t *taskTexts) put(goal, text string, public bool, via string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.st[goal] = taskText{Text: text, Public: public, At: now, Via: via}
	t.pruneLocked(now)
	t.saveLocked()
}

func (t *taskTexts) saveLocked() error {
	b, err := json.Marshal(t.st)
	if err == nil {
		err = t.store.Save(b)
	}
	if err != nil {
		t.logf("learning: task texts not saved: %v", err)
	}
	t.dirty = err != nil
	return err
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

// forget deletes goal's task text (W3-tasks, CAP-3) and reports whether
// one was kept. A failed save is logged and returned (security F1 on #123).
func (t *taskTexts) forget(goal string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.st[goal]; !ok {
		if t.dirty {
			// An earlier save failed: the entry left memory but may
			// still be on disk (security R1 on #123).
			return false, t.saveLocked()
		}
		return false, nil
	}
	delete(t.st, goal)
	return true, t.saveLocked()
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

// recentTask is one kept task, for FORGET's list.
type recentTask struct {
	Goal string
	taskText
}

// recent lists up to n kept tasks, newest first.
func (t *taskTexts) recent(n int) []recentTask {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var out []recentTask
	for g, x := range t.st {
		if now.Sub(x.At) <= keepTasks {
			out = append(out, recentTask{g, x})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].Goal < out[j].Goal
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// harvester is loops.Harvester as harvestOutcome uses it.
type harvester interface {
	Harvest(loops.Outcome) error
}

// harvestOutcome records the owner's final verdict on an agent's effect
// (grants.Config.Outcome) as a Loop 1 case. An implicit acceptance is a
// weaker, capped good verdict under its own source (loops L6). With no
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
