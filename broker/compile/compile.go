package compile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/skill"
)

// Cases is the part of the change pipeline the compiler uses: the dev
// split, the only cases a builder may see (CHG-1).
type Cases interface {
	Dev(class change.Class) []change.Case
}

// Config configures New.
type Config struct {
	Journal Journal
	Cases   Cases
	// OwnerSource is the verdict source that marks the owner's own
	// judgment (OP-7). Default "owner".
	OwnerSource string
	// MinRuns is how many same-shape trajectories compile into a skill.
	// Default 3.
	MinRuns int
	// MinSteps is the fewest effects worth a procedure or skill: one effect
	// is already one effect_request. Default 2.
	MinSteps int
	// Group names an intent's task. Default its goal ID; intents with none
	// are in no trajectory.
	Group func(journal.Intent) string
	// Redacted reports a value the journal's redactor produced (a secret
	// replaced by a marker). A trajectory holding one is never compiled.
	// Nil: none detected.
	Redacted func(string) bool
}

// Compiler builds procedure and skill candidates from the journal.
type Compiler struct{ cfg Config }

// Origin names the compiler in a candidate (journal audit only).
const Origin = "compile"

// New returns a compiler.
func New(cfg Config) (*Compiler, error) {
	if cfg.Journal == nil || cfg.Cases == nil {
		return nil, fmt.Errorf("compile: Journal and Cases are required")
	}
	if cfg.OwnerSource == "" {
		cfg.OwnerSource = "owner"
	}
	if cfg.MinRuns < 2 {
		cfg.MinRuns = 3
	}
	if cfg.MinSteps < 1 {
		cfg.MinSteps = 2
	}
	if cfg.Group == nil {
		cfg.Group = func(in journal.Intent) string { return in.GoalID }
	}
	return &Compiler{cfg: cfg}, nil
}

// CaseClass is the class the harvester should file a task's case under:
// ClassSkill when the task's trajectory has at least MinSteps effects (a
// skill or procedure could do it), "" otherwise. Skill candidates are
// evaluated on held-out cases of this class (change C5).
func (c *Compiler) CaseClass(intentID string) change.Class {
	for _, t := range trajectories(c.cfg.Journal, c.cfg.Group, c.cfg.OwnerSource, c.cfg.Redacted) {
		for _, id := range t.Intents {
			if id == intentID {
				if len(t.Steps) >= c.cfg.MinSteps {
					return change.ClassSkill
				}
				return ""
			}
		}
	}
	return ""
}

// usable returns the successful trajectories the builder may see: those
// of tasks behind a dev case, grouped by shape.
func (c *Compiler) usable() map[string][]*Trajectory {
	all := trajectories(c.cfg.Journal, c.cfg.Group, c.cfg.OwnerSource, c.cfg.Redacted)
	goalOf := map[string]string{}
	for g, t := range all {
		for _, id := range t.Intents {
			goalOf[id] = g
		}
	}
	dev := map[string]bool{}
	for _, cl := range []change.Class{change.ClassSkill, change.ClassProcedure} {
		for _, cs := range c.cfg.Cases.Dev(cl) {
			if g, ok := goalOf[cs.Task]; ok {
				dev[g] = true
			}
		}
	}
	out := map[string][]*Trajectory{}
	for g, t := range all {
		if !dev[g] || !t.Succeeded || !t.Good || t.Redacted || !structured(t) || len(t.Steps) < c.cfg.MinSteps || len(t.Steps) > skill.MaxSteps {
			continue
		}
		sh := Shape(t)
		out[sh] = append(out[sh], t)
	}
	for _, ts := range out {
		sort.Slice(ts, func(i, j int) bool { return ts[i].Goal < ts[j].Goal })
	}
	return out
}

// Candidates returns one change-pipeline candidate per shape whose skill
// or procedure is missing from active (the active tree's skills and
// procedures) or differs from it in anything but its run count. A shape
// with MinRuns trajectories gets a skill, which also deletes that shape's
// procedure; one with fewer gets a procedure. Public is set only when
// every source intent came from a public machine (CHG-5, REV-5).
func (c *Compiler) Candidates(active change.Tree) []change.Candidate {
	var out []change.Candidate
	groups := c.usable()
	shapes := make([]string, 0, len(groups))
	for sh := range groups {
		shapes = append(shapes, sh)
	}
	sort.Strings(shapes)
	for _, sh := range shapes {
		ts := groups[sh]
		var sk *skill.Skill
		if len(ts) >= c.cfg.MinRuns {
			sk = Compile(sh, ts)
		} else {
			if _, has := active[skill.SkillsNS+"/k"+sh+".json"]; has {
				continue // a skill already covers it
			}
			sk = Procedure(sh, ts)
		}
		if sk == nil || sk.Validate() != nil || same(active[sk.Path()], sk) {
			continue
		}
		cand := change.Candidate{
			Source: change.Local, Origin: Origin,
			Files:  map[string][]byte{sk.Path(): sk.Encode()},
			Public: true,
		}
		for _, t := range ts {
			cand.Public = cand.Public && t.Public
		}
		if sk.Kind == skill.KindSkill {
			if _, has := active[skill.ProceduresNS+"/p"+sh+".json"]; has {
				cand.Delete = []string{skill.ProceduresNS + "/p" + sh + ".json"}
			}
		}
		out = append(out, cand)
	}
	return out
}

// same reports whether file b holds sk apart from its run count, so more
// runs alone never make a new candidate.
func same(b []byte, sk *skill.Skill) bool {
	if b == nil {
		return false
	}
	old, err := skill.Decode(b)
	if err != nil {
		return false
	}
	old.Runs = sk.Runs
	return bytes.Equal(old.Encode(), sk.Encode())
}

// Compile builds a skill from same-shape trajectories: a value equal in
// every run is a literal; any other is an input. Inputs whose values are
// equal run for run share one slot. Nil if they are not the same shape.
func Compile(shape string, ts []*Trajectory) *skill.Skill {
	return build(skill.KindSkill, "k"+shape, ts, false)
}

// Procedure records same-shape trajectories, too few to compile, with
// every value an input (no literal carries a recorded value), so it
// replays the steps on new inputs.
func Procedure(shape string, ts []*Trajectory) *skill.Skill {
	return build(skill.KindProcedure, "p"+shape, ts, true)
}

func build(kind skill.Kind, id string, ts []*Trajectory, allSlots bool) *skill.Skill {
	per := make([][]leaf, len(ts))
	for i, t := range ts {
		per[i] = leaves(t)
		if len(per[i]) != len(per[0]) {
			return nil
		}
	}
	sk := &skill.Skill{Version: skill.Version, Kind: kind, ID: id, Runs: len(ts)}
	for _, st := range ts[0].Steps {
		sk.Steps = append(sk.Steps, skill.Step{Account: st.Account, Action: st.Action})
	}
	slotOf := map[string]string{} // value vector -> slot name
	names := map[string]bool{"run_id": true}
	for li, l0 := range per[0] {
		vals := make([][]byte, len(ts))
		constant := true
		for ti := range ts {
			l := per[ti][li]
			if l.key() != l0.key() || l.kind != l0.kind {
				return nil
			}
			vals[ti] = l.val
			constant = constant && bytes.Equal(l.val, l0.val)
		}
		var node skill.Node
		if constant && !allSlots {
			node = skill.Node{Lit: json.RawMessage(l0.val)}
		} else {
			vec := string(bytes.Join(vals, []byte{0}))
			name, ok := slotOf[vec]
			if !ok {
				sl := slotFor(l0, per, li, names)
				if sl == nil {
					return nil
				}
				name = sl.Name
				slotOf[vec] = name
				names[name] = true
				sk.Slots = append(sk.Slots, *sl)
			}
			node = skill.Node{Slot: name}
		}
		place(&sk.Steps[l0.step], l0, node)
	}
	return sk
}

var nonName = regexp.MustCompile(`[^a-z0-9_]+`)

// slotFor names and types an input from its leaf's values in every run.
// A kind that cannot be an input (null) makes no skill.
func slotFor(l0 leaf, per [][]leaf, li int, taken map[string]bool) *skill.Slot {
	base := "recipient"
	if l0.path != nil {
		base = strings.Trim(nonName.ReplaceAllString(strings.ToLower(l0.path[len(l0.path)-1]), "_"), "_")
	}
	if base == "" || base[0] < 'a' || base[0] > 'z' {
		base = "v" + base
	}
	if len(base) > 24 {
		base = base[:24]
	}
	name := base
	for n := 2; taken[name]; n++ {
		name = fmt.Sprintf("%s_%d", base, n)
	}
	sl := &skill.Slot{Name: name, Max: 1}
	longest := 0
	email := true
	for _, ls := range per {
		l := ls[li]
		if len(l.val) > longest {
			longest = len(l.val)
		}
		if s, ok := l.raw.(string); ok {
			email = email && emailRE.MatchString(s)
		}
	}
	bound := min(skill.MaxValue, max(64, 2*longest))
	if l0.path == nil {
		bound = min(bound, 320) // a recipient: the guest plane's own bound
	}
	switch l0.kind {
	case 's':
		sl.Type, sl.Max = skill.Text, bound
		if email {
			sl.Type = skill.Email
		}
	case 'n':
		sl.Type = skill.Number
	case 'b':
		sl.Type = skill.Bool
	case 'j':
		sl.Type, sl.Max = skill.JSON, bound
	default:
		return nil
	}
	return sl
}

var emailRE = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

// place puts node at the leaf's position in step st.
func place(st *skill.Step, l leaf, node skill.Node) {
	if l.path == nil {
		for len(st.Recipients) <= l.rcpt {
			st.Recipients = append(st.Recipients, skill.Node{})
		}
		st.Recipients[l.rcpt] = node
		return
	}
	if st.Params == nil {
		st.Params = map[string]skill.Node{}
	}
	m := st.Params
	for _, k := range l.path[:len(l.path)-1] {
		n := m[k]
		if n.Obj == nil {
			n.Obj = map[string]skill.Node{}
			m[k] = n
		}
		m = n.Obj
	}
	m[l.path[len(l.path)-1]] = node
}

// ErrNoSkill: the evidence holds no shape with MinRuns successful,
// owner-accepted trajectories.
var ErrNoSkill = errors.New("compile: no repeated trajectory to compile")

// BuildSkill compiles a skill from the journal statuses Loop 1 hands over
// with a repeat hypothesis (its brief's evidence, which never holds a
// held-out task, CHG-1). It reads nothing else. The candidate writes only
// under skills/; Loop 1 sets its source, origin, and public mark.
func (c *Compiler) BuildSkill(evidence []journal.Status) (change.Candidate, error) {
	all := trajectories(evidenceJournal(evidence), c.cfg.Group, c.cfg.OwnerSource, c.cfg.Redacted)
	groups := map[string][]*Trajectory{}
	for _, t := range all {
		if !t.Succeeded || !t.Good || t.Redacted || !structured(t) || len(t.Steps) < c.cfg.MinSteps || len(t.Steps) > skill.MaxSteps {
			continue
		}
		sh := Shape(t)
		groups[sh] = append(groups[sh], t)
	}
	best := ""
	for sh, ts := range groups {
		if len(ts) >= c.cfg.MinRuns && (best == "" || len(ts) > len(groups[best]) || (len(ts) == len(groups[best]) && sh < best)) {
			best = sh
		}
	}
	if best == "" {
		return change.Candidate{}, ErrNoSkill
	}
	ts := groups[best]
	sort.Slice(ts, func(i, j int) bool { return ts[i].Goal < ts[j].Goal })
	sk := Compile(best, ts)
	if sk == nil || sk.Validate() != nil {
		return change.Candidate{}, ErrNoSkill
	}
	return change.Candidate{Source: change.Local, Origin: Origin, Files: map[string][]byte{sk.Path(): sk.Encode()}}, nil
}

// evidenceJournal presents statuses, in the order given, as a journal with
// no timestamps.
type evidenceJournal []journal.Status

func (e evidenceJournal) List() []journal.Status { return e }

func (e evidenceJournal) Trail() []journal.Record {
	out := make([]journal.Record, 0, len(e))
	for i := range e {
		in := e[i].Intent
		out = append(out, journal.Record{Type: journal.RecSubmitted, ID: in.ID, Intent: &in})
	}
	return out
}
