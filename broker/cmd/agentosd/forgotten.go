package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// maxForgotten bounds the goals kept in the tombstone; past it the oldest
// go. The journal keeps intents without a sweep, so the tombstone has no
// age limit.
const maxForgotten = 65536

// forgotten is the tombstone of the goals the owner forgot (W3-tasks part
// 1; security F1 on #123). The journal still holds a forgotten goal's
// intents, so learning skips them: Loop 1's mining and the compiler read
// the journal through it (skip), and no text, values or case is kept for
// the goal again. It holds goal IDs and when they were forgotten, never
// content.
type forgotten struct {
	store change.Store
	now   func() time.Time

	mu sync.Mutex
	st map[string]time.Time
}

func openForgotten(store change.Store, now func() time.Time) (*forgotten, error) {
	f := &forgotten{store: store, now: now, st: map[string]time.Time{}}
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if b != nil {
		if err := json.Unmarshal(b, &f.st); err != nil {
			return nil, fmt.Errorf("learning: forgotten goals: %v", err)
		}
	}
	return f, nil
}

// has reports whether goal was forgotten. A nil tombstone forgets nothing.
func (f *forgotten) has(goal string) bool {
	if f == nil || goal == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.st[goal]
	return ok
}

// goals lists the tombstoned goals, oldest first.
func (f *forgotten) goals() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.st))
	for g := range f.st {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if !f.st[out[i]].Equal(f.st[out[j]]) {
			return f.st[out[i]].Before(f.st[out[j]])
		}
		return out[i] < out[j]
	})
	return out
}

// add tombstones goal and saves. On a failed save the goal stays
// tombstoned in memory, and the next add saves it again.
func (f *forgotten) add(goal string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st[goal] = f.now()
	if len(f.st) > maxForgotten {
		goals := make([]string, 0, len(f.st))
		for g := range f.st {
			goals = append(goals, g)
		}
		sort.Slice(goals, func(i, j int) bool { return f.st[goals[i]].Before(f.st[goals[j]]) })
		for _, g := range goals[:len(goals)-maxForgotten] {
			delete(f.st, g)
		}
	}
	b, err := json.Marshal(f.st)
	if err != nil {
		return err
	}
	return f.store.Save(b)
}

// List is the journal without the forgotten goals' intents.
func (r lateReader) List() []journal.Status {
	e := r.e.Load()
	if e == nil {
		return nil
	}
	sts := e.List()
	out := sts[:0:0]
	for _, s := range sts {
		if !r.gone.has(s.Intent.GoalID) {
			out = append(out, s)
		}
	}
	return out
}

// Trail is the journal's records without the forgotten goals' intents:
// a record naming one only by ID goes with the intent's own record.
func (r lateReader) Trail() []journal.Record {
	e := r.e.Load()
	if e == nil {
		return nil
	}
	rs := e.Trail()
	dropped := map[string]bool{}
	for _, x := range rs {
		if x.Intent != nil && r.gone.has(x.Intent.GoalID) {
			dropped[x.Intent.ID] = true
		}
	}
	out := rs[:0:0]
	for _, x := range rs {
		if dropped[x.ID] || x.Intent != nil && dropped[x.Intent.ID] {
			continue
		}
		out = append(out, x)
	}
	return out
}
