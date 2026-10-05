package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/compile"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
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
	key, err := readValuesKey(keyPath)
	if err != nil {
		return nil, err
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
		for id, g := range v.st {
			if g == nil || g.Steps == nil || len(g.Steps) > maxValueSteps {
				delete(v.st, id)
				logf("task values: a malformed goal was dropped")
			}
		}
	}
	v.mu.Lock()
	if v.pruneLocked(now()) {
		v.saveLocked()
	}
	v.mu.Unlock()
	return v, nil
}

// The credential shapes recall's scrubber removes (CRED-1), restated here
// since agentosd's control path may not import recall (ARC-2): an auth
// scheme with its token, a URL query or fragment param REV-5 names as a
// credential, and a long random-looking token (L3 MUST-2 on #119).
var (
	authScheme = regexp.MustCompile(`(?i)\b(bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{8,}`)
	tokenParam = regexp.MustCompile(`(?i)(?:^|[?&#;\s])[^=&#;\s]*(token|code|key|sig|auth|session|pass|secret|otp)[^=&#;\s]*=[^&#;\s]+`)
	emailShape = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
)

func credentialShaped(s string) bool {
	if authScheme.MatchString(s) || tokenParam.MatchString(s) {
		return true
	}
	for _, tok := range strings.Fields(s) {
		if t := strings.Trim(tok, "\"'()[]{}<>.,;:!?"); !strings.Contains(t, "://") && randomLooking(t) {
			return true
		}
	}
	return false
}

// randomLooking is recall's test: at least 16 characters mixing letters
// and digits with high per-character entropy, or at least 20 of very high
// entropy; addresses are kept.
func randomLooking(t string) bool {
	if len(t) < 16 || emailShape.MatchString(t) {
		return false
	}
	h := entropy(t)
	if strings.ContainsAny(t, "0123456789") && strings.IndexFunc(t, unicode.IsLetter) >= 0 && h >= 3.0 {
		return true
	}
	return len(t) >= 20 && h >= 3.5
}

func entropy(t string) float64 {
	n := map[rune]float64{}
	for _, r := range t {
		n[r]++
	}
	total := float64(len([]rune(t)))
	h := 0.0
	for _, c := range n {
		p := c / total
		h -= p * math.Log2(p)
	}
	return h
}

// readValuesKey reads the hash key, made on first use: written to a
// temporary file and renamed, so a crash never leaves a short key, and
// refused when others can read it.
func readValuesKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		tmp := path + ".tmp"
		if err = os.WriteFile(tmp, key, 0o600); err == nil {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("task values: key file is readable by others")
	}
	if len(key) != 32 {
		return nil, errors.New("task values: bad key")
	}
	return key, nil
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

// forget deletes goal's values with its task text (W3-values (d), CAP-3)
// and reports whether any were kept.
func (v *taskValues) forget(goal string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.st[goal] == nil {
		return false
	}
	delete(v.st, goal)
	v.saveLocked()
	return true
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

// scrub is one leaf: secret-shaped, holding credential material, or
// changed by the journal's redactor, is the placeholder as a whole
// (security V2).
func (v *taskValues) scrub(s string) string {
	if owner.SecretShaped(s) || credentialShaped(s) || (v.redact != nil && v.redact(s) != s) {
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

// schemaKey is a map key shaped like a field name; any other key is data
// and is hashed in an implicit run (L3 on #119).
var schemaKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)

func (v *taskValues) hashValue(x any) any {
	switch t := x.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, c := range t {
			if !schemaKey.MatchString(k) { // a key that is data, such as an address
				k = v.hash(k)
			}
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
	if !ok {
		return valueStep{}, false
	}
	// A copy, so nothing the compiler does reaches the record (security R1
	// on #119), as observe copies what it records (V1).
	out := valueStep{Recipients: append([]string(nil), s.Recipients...)}
	if s.Params != nil {
		out.Params = copyValue(s.Params).(map[string]any)
	}
	return out, true
}

func copyValue(x any) any {
	switch t := x.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, c := range t {
			out[k] = copyValue(c)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, c := range t {
			out[i] = copyValue(c)
		}
		return out
	}
	return x
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

// skillBuilder is Loop 1's builder for repeated trajectories: the
// compiler, reading kept values in place of the journal's marks. Loop 1
// mines its evidence from the plain journal, so the builder maps each
// brief's evidence through the values itself, on a copy: the values never
// enter Loop 1's brief (security V3; L3 MUST-1 on #119).
func skillBuilder(j compile.Journal, values *taskValues, cases compile.Cases) (loops.BySignal, error) {
	var b loops.Builder
	if values == nil {
		comp, err := compile.New(compile.Config{Journal: j, Cases: cases, Redacted: journalRedacted})
		if err != nil {
			return nil, err
		}
		b = compile.LoopBuilder{C: comp}
	} else {
		vj := valuedJournal{j, values}
		comp, err := compile.New(compile.Config{Journal: vj, Cases: cases, Redacted: journalRedacted})
		if err != nil {
			return nil, err
		}
		b = valuedBuilder{compile.LoopBuilder{C: comp}, vj}
	}
	return loops.BySignal{loops.SignalRepeat: b}, nil
}

type valuedBuilder struct {
	b  compile.LoopBuilder
	vj valuedJournal
}

func (vb valuedBuilder) valued(br loops.Brief) loops.Brief {
	ev := make([]journal.Status, len(br.Hypothesis.Evidence))
	for i, s := range br.Hypothesis.Evidence {
		s.Intent = vb.vj.with(s.Intent)
		ev[i] = s
	}
	br.Hypothesis.Evidence = ev
	return br
}

func (vb valuedBuilder) Build(ctx context.Context, br loops.Brief) (change.Candidate, error) {
	return vb.b.Build(ctx, vb.valued(br))
}

func (vb valuedBuilder) Ready(br loops.Brief) bool { return vb.b.Ready(vb.valued(br)) }

var _ loops.Readier = valuedBuilder{}
