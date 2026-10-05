package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/compile"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// Task values are kept for the skill compiler (BOARD W3-values; security
// on 3b, arbitrator, UX-S3-2): the journal stores no free text, so the
// values of the guest's intents are recorded here, from the gate as the
// guest wrote them, only while learning is on. A secret-shaped value
// (owner.Disclose's formats, CH-19) or one the journal's redactor would
// change is kept as the vault's placeholder, so its run never compiles.
// A goal's values are kept only once the owner said YES to it; an implicit
// acceptance keeps a keyed hash per value, enough to see that a value
// varies and nothing of what it was ("count, not content"); any other
// verdict drops them, and so do 30 days without one. At most maxValueGoals
// goals, maxValueSteps intents each, in the learn directory (0600), which
// only the broker reads. Only the compiler reads them (security V3).
const (
	maxValueGoals = 512
	maxValueSteps = 32
	keepValues    = 30 * 24 * time.Hour
	// maxObserved bounds intents waiting to be recorded; more are dropped
	// with a fixed log line, so the gate never waits (security V1).
	maxObserved = 256
	// redactedValue is the vault's placeholder (vault.Placeholder), which
	// compile's Redacted check reads as no value.
	redactedValue = vaultPlaceholder
)

type valueStep struct {
	Params     map[string]any `json:"params,omitempty"`
	Recipients []string       `json:"recipients,omitempty"`
}

type valueGoal struct {
	At    time.Time            `json:"at"`
	Label string               `json:"label,omitempty"`
	Steps map[string]valueStep `json:"steps"` // intent ID -> its values
	// Good: the owner said YES to the goal. Hashed: an implicit
	// acceptance, so its values are keyed hashes.
	Good   bool `json:"good,omitempty"`
	Hashed bool `json:"hashed,omitempty"`
}

type taskValues struct {
	store change.Store
	key   []byte
	now   func() time.Time
	logf  func(string, ...any)
	// redact is the journal's redactor, once one keeps values (P2-4):
	// a value it would change is a secret. Nil: none.
	redact journal.Redactor

	mu sync.Mutex
	st map[string]*valueGoal // goal ID -> its values
}

// openTaskValues loads the record and its hash key, made on first use.
func openTaskValues(store change.Store, keyPath string, now func() time.Time, logf func(string, ...any)) (*taskValues, error) {
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err == nil {
			err = os.WriteFile(keyPath, key, 0o600)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("task values: bad key")
	}
	v := &taskValues{store: store, key: key, now: now, logf: logf, st: map[string]*valueGoal{}}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &v.st); err != nil {
			return nil, errors.New("task values: corrupt state")
		}
		if v.st == nil {
			v.st = map[string]*valueGoal{}
		}
	}
	v.mu.Lock()
	if v.pruneLocked(now()) {
		v.saveLocked()
	}
	v.mu.Unlock()
	return v, nil
}

// observe records the values of an intent the gate authorized.
func (v *taskValues) observe(in journal.Intent) {
	if in.GoalID == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	g := v.st[in.GoalID]
	switch {
	case g == nil:
		g = &valueGoal{Steps: map[string]valueStep{}}
		v.st[in.GoalID] = g
	case g.Hashed || len(g.Steps) >= maxValueSteps:
		return
	}
	if _, ok := g.Steps[in.ID]; ok {
		return
	}
	g.At, g.Label = v.now(), in.Label
	step := valueStep{Recipients: make([]string, len(in.Recipients))}
	for i, r := range in.Recipients {
		step.Recipients[i] = v.scrub(r)
	}
	if in.Params != nil {
		step.Params = v.scrubValue(in.Params).(map[string]any)
	}
	g.Steps[in.ID] = step
	v.pruneLocked(v.now())
	v.saveLocked()
}

// verdict applies the owner's verdict on an effect to its goal's values.
func (v *taskValues) verdict(o grants.OwnerOutcome) {
	goal := o.Intent.GoalID
	if goal == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	g := v.st[goal]
	if g == nil {
		return
	}
	switch o.Verdict {
	case grants.OwnerAccepted:
		if g.Hashed {
			// Its values are gone; an explicit YES cannot bring them back.
			return
		}
		g.Good = true
	case grants.OwnerAcceptedImplicitly:
		if g.Good || g.Hashed {
			return
		}
		g.Hashed = true
		for id, s := range g.Steps {
			g.Steps[id] = v.hashStep(s)
		}
	default:
		delete(v.st, goal)
	}
	v.saveLocked()
}

// scrub is one leaf: secret-shaped, or changed by the journal's
// redactor, is the placeholder as a whole (security V2).
func (v *taskValues) scrub(s string) string {
	if owner.SecretShaped(s) || (v.redact != nil && v.redact(s) != s) {
		return redactedValue
	}
	return s
}

func (v *taskValues) scrubValue(x any) any { return v.scrubIn("", x) }

// scrubIn scrubs x found under key: a leaf is read with its key, so
// "code": 123456 is a code as "code 123456" is, and a number is read as
// its decimal text (security F1 on #119).
func (v *taskValues) scrubIn(key string, x any) any {
	switch t := x.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, c := range t {
			if sk := v.scrub(k); sk != k {
				out[sk] = redactedValue
				continue
			}
			out[k] = v.scrubIn(k, c)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, c := range t {
			out[i] = v.scrubIn(key, c)
		}
		return out
	}
	text, ok := leafText(x)
	if !ok {
		return x
	}
	if v.scrub(text) != text || longDigits(text) || key != "" && v.scrub(key+" "+text) != key+" "+text {
		return redactedValue
	}
	return x
}

// leafText is a string or number leaf as text; numbers without an
// exponent, so 4111111111111111 reads as its digits.
func leafText(x any) (string, bool) {
	switch t := x.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	}
	return "", false
}

// minSecretDigits: a run of this many digits, spaces, dots or dashes
// between them allowed, reads as a card or account number and is not
// kept. It fails closed: a long order number is dropped too, so a skill
// built on one does not compile.
const minSecretDigits = 12

func longDigits(s string) bool {
	n := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			if n++; n >= minSecretDigits {
				return true
			}
		case r == ' ' || r == '-' || r == '.':
		default:
			n = 0
		}
	}
	return false
}

// hashStep keeps a keyed hash of each string value: equal values hash
// equal, so variation shows, and the value cannot be read back. Keys stay,
// since they are the step's shape.
func (v *taskValues) hashStep(s valueStep) valueStep {
	out := valueStep{Recipients: make([]string, len(s.Recipients))}
	for i, r := range s.Recipients {
		out.Recipients[i] = v.hash(r)
	}
	if s.Params != nil {
		out.Params = v.hashValue(s.Params).(map[string]any)
	}
	return out
}

func (v *taskValues) hashValue(x any) any {
	switch t := x.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, c := range t {
			out[k] = v.hashValue(c)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, c := range t {
			out[i] = v.hashValue(c)
		}
		return out
	}
	if text, ok := leafText(x); ok { // numbers too: count, not content (security R1 on #119)
		return v.hash(text)
	}
	return x
}

func (v *taskValues) hash(s string) string {
	if s == redactedValue {
		return s
	}
	m := hmac.New(sha256.New, v.key)
	m.Write([]byte(s))
	return "h" + hex.EncodeToString(m.Sum(nil)[:16])
}

// values returns intent id's recorded values, if its goal's are kept: a
// goal with no verdict yet is not read.
func (v *taskValues) values(goal, id string) (valueStep, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	g := v.st[goal]
	if g == nil || !(g.Good || g.Hashed) || v.now().Sub(g.At) > keepValues {
		return valueStep{}, false
	}
	s, ok := g.Steps[id]
	return s, ok
}

func (v *taskValues) saveLocked() {
	b, err := json.Marshal(v.st)
	if err == nil {
		err = v.store.Save(b)
	}
	if err != nil {
		v.logf("learning: task values not saved: %v", err)
	}
}

// pruneLocked drops goals past keepValues and the oldest past
// maxValueGoals, and reports whether it dropped any.
func (v *taskValues) pruneLocked(now time.Time) bool {
	n := len(v.st)
	goals := make([]string, 0, n)
	for id, g := range v.st {
		if now.Sub(g.At) > keepValues {
			delete(v.st, id)
			continue
		}
		goals = append(goals, id)
	}
	if len(goals) > maxValueGoals {
		sort.Slice(goals, func(i, j int) bool { return v.st[goals[i]].At.After(v.st[goals[j]].At) })
		for _, id := range goals[maxValueGoals:] {
			delete(v.st, id)
		}
	}
	return len(v.st) != n
}

// valuedJournal is the journal as the compiler reads it: each intent whose
// goal's values are kept carries them in place of the journal's redaction
// marks. It is handed to the compiler only (security V3).
type valuedJournal struct {
	j      compile.Journal
	values *taskValues
}

func (vj valuedJournal) with(in journal.Intent) journal.Intent {
	s, ok := vj.values.values(in.GoalID, in.ID)
	if !ok {
		return in
	}
	in.Params, in.Recipients = s.Params, s.Recipients
	return in
}

func (vj valuedJournal) List() []journal.Status {
	sts := vj.j.List()
	out := make([]journal.Status, len(sts))
	for i, s := range sts {
		s.Intent = vj.with(s.Intent)
		out[i] = s
	}
	return out
}

func (vj valuedJournal) Trail() []journal.Record {
	rs := vj.j.Trail()
	out := make([]journal.Record, len(rs))
	for i, r := range rs {
		if r.Intent != nil {
			in := vj.with(*r.Intent)
			r.Intent = &in
		}
		out[i] = r
	}
	return out
}
