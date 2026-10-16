package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// A domain lifecycle (device actuation, DEV-5; credential hand-off, CRED-11)
// is a set of intent kinds submitted to the Engine, never a store of its own
// (OP-11). Lifecycle is its declaration: the effect is an intent whose
// Action starts with Kind; the inverse is a second intent (UNDO submits it);
// the prior state and bounds ride in Params as non-secret scalars, which
// survive scrubbing; the daily count is read from records; and any state
// such as "stopped" is a record that replay rebuilds. Nothing here writes a
// file or keeps a counter.
type Lifecycle struct {
	// Kind is the action prefix, ending in ".": "actuate.lamp." covers
	// "actuate.lamp.set". No kind may contain another.
	Kind string
	// Inverse is the action that undoes an effect, under Kind, or
	// Irreversible (a hand-off cannot be taken back).
	Inverse string
	// Target is the param key holding the value an effect sets, and Prior
	// the key holding the value it replaced. A reversible lifecycle needs
	// both; an irreversible one names neither.
	Target string
	Prior  string
	// Bounds are the further param keys every intent of the kind must
	// carry as scalars: the owner-confirmed bounds for an actuation, the
	// source, destination, size and content hash for a hand-off.
	Bounds []string
	// DailyCap is the default number of effects a day per account, for
	// the owner to change (DEV-5: 50).
	DailyCap int
}

// Irreversible is the Inverse of a lifecycle whose effects cannot be undone.
const Irreversible = "irreversible"

// ParamUndoes is the param of an inverse intent naming the effect it undoes.
const ParamUndoes = "undoes"

// MaxScalarBytes bounds a string scalar in a lifecycle param. A longer value
// belongs in a content store, named by its hash (OP-11).
const MaxScalarBytes = 256

var (
	// ErrLifecycle reports an incomplete or conflicting declaration, or an
	// intent its lifecycle does not admit.
	ErrLifecycle = errors.New("journal: lifecycle")
	// ErrNoUndo reports that an effect has no undo now: it is unknown,
	// irreversible, did not certainly happen, or the device has changed
	// since (DEV-5).
	ErrNoUndo = errors.New("journal: no undo")
)

var lifecycles struct {
	sync.RWMutex
	byKind map[string]Lifecycle
}

// Register declares a lifecycle. It refuses an incomplete declaration and a
// kind that equals, contains or lies inside one already registered.
func Register(l Lifecycle) error {
	if err := l.valid(); err != nil {
		return err
	}
	lifecycles.Lock()
	defer lifecycles.Unlock()
	for k := range lifecycles.byKind {
		if strings.HasPrefix(l.Kind, k) || strings.HasPrefix(k, l.Kind) {
			return fmt.Errorf("%w: kind %q overlaps registered kind %q", ErrLifecycle, l.Kind, k)
		}
	}
	if lifecycles.byKind == nil {
		lifecycles.byKind = map[string]Lifecycle{}
	}
	l.Bounds = append([]string(nil), l.Bounds...)
	lifecycles.byKind[l.Kind] = l
	return nil
}

// LifecycleOf returns the registered lifecycle an action belongs to.
func LifecycleOf(action string) (Lifecycle, bool) {
	lifecycles.RLock()
	defer lifecycles.RUnlock()
	for k, l := range lifecycles.byKind {
		if strings.HasPrefix(action, k) {
			return l, true
		}
	}
	return Lifecycle{}, false
}

func (l Lifecycle) valid() error {
	bad := func(why string) error { return fmt.Errorf("%w: %q: %s", ErrLifecycle, l.Kind, why) }
	switch {
	case l.Kind == "" || !strings.HasSuffix(l.Kind, "."):
		return bad(`kind must be a non-empty prefix ending in "."`)
	case l.Inverse == "":
		return bad("no inverse: name one, or Irreversible")
	case l.DailyCap <= 0:
		return bad("no daily cap")
	case len(l.Bounds) == 0:
		return bad("no bound params")
	}
	if l.Inverse == Irreversible {
		if l.Target != "" || l.Prior != "" {
			return bad("an irreversible lifecycle keeps no target or prior state")
		}
	} else {
		switch {
		case !strings.HasPrefix(l.Inverse, l.Kind) || l.Inverse == l.Kind:
			return bad("inverse must be an action under the kind")
		case l.Target == "" || l.Prior == "":
			return bad("a reversible lifecycle needs its target and prior-state params")
		case l.Target == l.Prior || l.Target == ParamUndoes || l.Prior == ParamUndoes:
			return bad("target, prior and undoes params must differ")
		}
	}
	seen := map[string]bool{l.Target: l.Target != "", l.Prior: l.Prior != "", ParamUndoes: true}
	for _, b := range l.Bounds {
		if b == "" || seen[b] {
			return bad(fmt.Sprintf("bound param %q is empty or repeated", b))
		}
		seen[b] = true
	}
	return nil
}

// Check reports whether an intent of this lifecycle carries what UNDO, the
// cap and the journal need. Callers run it before Submit; an actuation
// submitted without its prior state could never be undone. The daily cap is
// checked separately, against DailyCount.
func (l Lifecycle) Check(in Intent) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: intent %q (%s): %s", ErrLifecycle, in.ID, in.Action, why)
	}
	if !strings.HasPrefix(in.Action, l.Kind) {
		return bad("action is not of kind " + l.Kind)
	}
	if in.Account == "" {
		return bad("no account")
	}
	keys := append([]string(nil), l.Bounds...)
	if l.Inverse != Irreversible {
		keys = append(keys, l.Target, l.Prior)
	}
	if in.Action == l.Inverse {
		if s, ok := in.Params[ParamUndoes].(string); !ok || s == "" {
			return bad("an inverse must name the effect it undoes")
		}
	}
	for _, k := range keys {
		if !scalar(in.Params[k]) {
			return bad(fmt.Sprintf("param %q must be a number, bool or string of at most %d bytes", k, MaxScalarBytes))
		}
	}
	return nil
}

// scalar reports whether v survives the journal's scrub unchanged in kind:
// strings are redacted but stay strings, numbers and bools are kept.
func scalar(v any) bool {
	switch t := v.(type) {
	case string:
		return len(t) <= MaxScalarBytes
	case bool, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return true
	}
	return false
}

// effect is what records say about one intent.
type effect struct {
	intent    *Intent
	firstSent time.Time
	sent      map[int]bool
	result    map[int]Result // latest observation per attempt
	erased    bool
}

// effects folds records into per-intent facts. It reads records only.
func effects(records []Record) map[string]*effect {
	m := map[string]*effect{}
	get := func(id string) *effect {
		e := m[id]
		if e == nil {
			e = &effect{sent: map[int]bool{}, result: map[int]Result{}}
			m[id] = e
		}
		return e
	}
	for _, r := range records {
		switch r.Type {
		case RecSubmitted:
			if e := get(r.ID); e.intent == nil && r.Intent != nil {
				in := *r.Intent
				e.intent = &in
			}
		case RecDispatched:
			e := get(r.ID)
			if !e.sent[r.Attempt] && (e.firstSent.IsZero() || r.At.Before(e.firstSent)) {
				e.firstSent = r.At
			}
			e.sent[r.Attempt] = true
		case RecObserved:
			get(r.ID).result[r.Attempt] = r.Result
		case RecErased:
			get(r.ID).erased = true
		}
	}
	return m
}

// mayHaveApplied: some dispatched attempt is not known to have failed.
func (e *effect) mayHaveApplied() bool {
	for a := range e.sent {
		if e.result[a] != ResultNotApplied {
			return true
		}
	}
	return false
}

func (e *effect) succeeded() bool {
	for a := range e.sent {
		if e.result[a] == ResultSucceeded {
			return true
		}
	}
	return false
}

// DailyCount is the number of effects of this lifecycle on account whose
// first dispatch fell on day's calendar date in day's location. It is a pure
// function of records, so replay after a restart gives the same count. An
// effect counts once it is dispatched, unless every attempt is known not to
// have applied; an outcome still unknown counts, since it may have landed.
// An undo does not count, since it only restores; any other intent of the
// inverse action does, so a forged "restore" cannot actuate past the cap.
func (l Lifecycle) DailyCount(records []Record, account string, day time.Time) int {
	y, mo, d := day.Date()
	from := time.Date(y, mo, d, 0, 0, 0, 0, day.Location())
	to := from.AddDate(0, 0, 1)
	all := effects(records)
	n := 0
	for _, e := range all {
		in := e.intent
		if in == nil || in.Account != account || !strings.HasPrefix(in.Action, l.Kind) || l.isUndo(all, in) {
			continue
		}
		if e.firstSent.IsZero() || e.firstSent.Before(from) || !e.firstSent.Before(to) {
			continue
		}
		if e.mayHaveApplied() {
			n++
		}
	}
	return n
}

// isUndo reports whether in is the plan UndoPlan builds: the inverse, with
// the undo's ID, of a succeeded effect of this lifecycle on the same account,
// setting the target back to that effect's prior value.
func (l Lifecycle) isUndo(all map[string]*effect, in *Intent) bool {
	if l.Inverse == Irreversible || in.Action != l.Inverse {
		return false
	}
	id, _ := in.Params[ParamUndoes].(string)
	orig := all[id]
	if id == "" || in.ID != UndoID(id) || orig == nil || orig.intent == nil || !orig.succeeded() {
		return false
	}
	o := orig.intent
	return o.Account == in.Account && strings.HasPrefix(o.Action, l.Kind) && o.Action != l.Inverse &&
		sameValue(in.Params[l.Target], o.Params[l.Prior])
}

// UndoID is the intent ID of the undo of an effect, so that repeating UNDO
// resubmits one intent (OP-1).
func UndoID(effectID string) string { return "undo:" + effectID }

// UndoPlan returns the inverse intent that undoes effectID, built from the
// records alone. There is a plan only while current, the device's state now,
// still holds the value the effect set (DEV-5): a device someone has changed
// since is not restored. The effect must be of a registered reversible
// lifecycle, have succeeded, and keep its params. The caller sets Origin to
// the authenticated source of the UNDO, checks the plan, and submits it.
func UndoPlan(records []Record, effectID string, current map[string]any) (Intent, error) {
	no := func(why string) (Intent, error) { return Intent{}, fmt.Errorf("%w: %q: %s", ErrNoUndo, effectID, why) }
	e := effects(records)[effectID]
	if e == nil || e.intent == nil {
		return no("no such effect in the journal")
	}
	if e.erased {
		return no("its params were erased")
	}
	in := *e.intent
	l, ok := LifecycleOf(in.Action)
	switch {
	case !ok:
		return no("action " + in.Action + " has no lifecycle")
	case l.Inverse == Irreversible:
		return no("irreversible")
	case in.Action == l.Inverse:
		return no("an undo is not undone")
	}
	if err := l.Check(in); err != nil {
		return no(err.Error())
	}
	if !e.succeeded() {
		return no("not known to have happened")
	}
	now, ok := current[l.Target]
	if !ok || !sameValue(now, in.Params[l.Target]) {
		return no("the device's state is no longer what the agent set")
	}
	params := make(map[string]any, len(in.Params)+1)
	for k, v := range in.Params {
		params[k] = v
	}
	params[l.Target], params[l.Prior] = in.Params[l.Prior], in.Params[l.Target]
	params[ParamUndoes] = effectID
	return Intent{
		ID:       UndoID(effectID),
		GoalID:   in.GoalID,
		Account:  in.Account,
		Action:   l.Inverse,
		Params:   params,
		Executor: in.Executor,
	}, nil
}

// sameValue compares two scalars as the journal stores them, so a number
// read back as float64 equals the int an adapter reports.
func sameValue(a, b any) bool {
	if !scalar(a) || !scalar(b) {
		return false
	}
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}
