package compile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Journal is the part of the intent engine the compiler reads.
type Journal interface {
	Trail() []journal.Record
	List() []journal.Status
}

// Step is one recorded effect.
type Step struct {
	Account    string
	Action     string
	Params     map[string]any
	Recipients []string
}

// Trajectory is one task's effects in submission order, with when the
// first was submitted and the last observed.
type Trajectory struct {
	Goal    string
	Intents []string
	Steps   []Step
	Start   time.Time
	End     time.Time
	// Succeeded: every effect succeeded. Good: the owner judged the task
	// good and nobody judged any of it wrong. Public: every intent came
	// from a public machine (REV-5).
	Succeeded bool
	Good      bool
	Public    bool
	// Redacted: some value is the journal's redaction of a secret, which
	// a skill must never replay as a literal.
	Redacted bool
}

// Span is how long the task's effects took, first submit to last outcome.
func (t Trajectory) Span() time.Duration { return t.End.Sub(t.Start) }

// trajectories groups the journal's external intents by goal (group),
// skipping intents with none. Broker-state intents are never steps.
func trajectories(j Journal, group func(journal.Intent) string, ownerSource string, redacted func(string) bool) map[string]*Trajectory {
	sts := map[string]journal.Status{}
	for _, s := range j.List() {
		sts[s.Intent.ID] = s
	}
	byGoal := map[string]*Trajectory{}
	goalOf := map[string]string{}
	for _, r := range j.Trail() {
		switch r.Type {
		case journal.RecSubmitted:
			if r.Intent == nil || r.Intent.Account == journal.BrokerAccount {
				continue
			}
			g := group(*r.Intent)
			if g == "" {
				continue
			}
			t := byGoal[g]
			if t == nil {
				t = &Trajectory{Goal: g, Start: r.At, End: r.At, Succeeded: true, Public: true}
				byGoal[g] = t
			}
			goalOf[r.ID] = g
			t.Intents = append(t.Intents, r.ID)
		case journal.RecObserved, journal.RecDenied, journal.RecRecheckFailed:
			if t := byGoal[goalOf[r.ID]]; t != nil && r.At.After(t.End) {
				t.End = r.At
			}
		}
	}
	for _, t := range byGoal {
		owner, wrong := false, false
		for _, id := range t.Intents {
			s, ok := sts[id]
			if !ok {
				t.Succeeded = false
				continue
			}
			in := s.Intent
			t.Steps = append(t.Steps, Step{Account: in.Account, Action: in.Action, Params: in.Params, Recipients: in.Recipients})
			if s.State != journal.Succeeded {
				t.Succeeded = false
			}
			if in.Label != "public" {
				t.Public = false
			}
			switch s.Quality.Verdict {
			case journal.VerdictWrong:
				wrong = true
			case journal.VerdictGood:
				owner = owner || s.Quality.Source == ownerSource
			}
			if redacted != nil && anyString(in.Params, in.Recipients, redacted) {
				t.Redacted = true
			}
		}
		t.Good = owner && !wrong
	}
	return byGoal
}

func anyString(params map[string]any, recips []string, f func(string) bool) bool {
	for _, r := range recips {
		if f(r) {
			return true
		}
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case string:
			return f(x)
		case map[string]any:
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	return walk(map[string]any(params))
}

// leaf is one value in a step: its path ("p" + JSON-pointer-like keys, or
// "r<i>" for a recipient), its JSON kind, and its canonical encoding.
type leaf struct {
	step int
	path []string // param keys from the top; nil for a recipient
	rcpt int      // recipient index when path is nil
	kind byte     // s n b j z (string, number, bool, list/object, null)
	val  []byte   // canonical JSON
	raw  any
}

func (l leaf) key() string {
	if l.path == nil {
		return fmt.Sprintf("%d/r/%d", l.step, l.rcpt)
	}
	return fmt.Sprintf("%d/p/%s", l.step, strings.Join(escape(l.path), "/"))
}

func escape(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = strings.NewReplacer("~", "~0", "/", "~1").Replace(p)
	}
	return out
}

// leaves flattens a trajectory's values. Objects are walked into; lists
// and empty objects are leaves.
func leaves(t *Trajectory) []leaf {
	var out []leaf
	for i, st := range t.Steps {
		var walk func(path []string, v any)
		walk = func(path []string, v any) {
			if m, ok := v.(map[string]any); ok && len(m) > 0 && len(path) < 8 {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					walk(append(append([]string(nil), path...), k), m[k])
				}
				return
			}
			out = append(out, newLeaf(i, path, 0, v))
		}
		keys := make([]string, 0, len(st.Params))
		for k := range st.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk([]string{k}, st.Params[k])
		}
		for r, v := range st.Recipients {
			out = append(out, newLeaf(i, nil, r, v))
		}
	}
	return out
}

func newLeaf(step int, path []string, rcpt int, v any) leaf {
	b := canonical(v)
	var kind byte
	switch v.(type) {
	case string:
		kind = 's'
	case bool:
		kind = 'b'
	case nil:
		kind = 'z'
	case map[string]any, []any:
		kind = 'j'
	default:
		kind = 'n' // json.Number or a float
	}
	return leaf{step: step, path: path, rcpt: rcpt, kind: kind, val: b, raw: v}
}

func canonical(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// Shape is what makes two trajectories the same task: the accounts and
// actions in order, and every value's position and kind. Values are not
// part of it.
func Shape(t *Trajectory) string {
	h := sha256.New()
	for i, st := range t.Steps {
		fmt.Fprintf(h, "step %d %q %q %d\n", i, st.Account, st.Action, len(st.Recipients))
	}
	for _, l := range leaves(t) {
		fmt.Fprintf(h, "%s %c\n", l.key(), l.kind)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
