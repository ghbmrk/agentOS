package change

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/route"
)

// idLetters avoids I and O, as the owner channel's IDs do.
const idLetters = "ABCDEFGHJKLMNPQRSTUVWXYZ"

// shortLocked allocates an owner-facing ID not used by an active adoption
// or by any of the last 200 adoptions.
func (p *Pipeline) shortLocked() (string, error) {
	recent := map[string]bool{}
	for i, a := range p.st.Adoptions {
		if a.Reverted == "" || i >= len(p.st.Adoptions)-200 {
			recent[a.Short] = true
		}
	}
	taken := func(id string) bool { return recent[id] }
	if p.cfg.ShortID != nil {
		id, err := p.cfg.ShortID(taken)
		if err != nil {
			return "", err
		}
		if taken(id) || !shortOK(id) {
			return "", fmt.Errorf("change: owner ID %q is in use or malformed", id)
		}
		return id, nil
	}
	n := len(idLetters) * 98
	for i := 0; i < n; i++ {
		k := (len(p.st.Adoptions) + i) % n
		id := fmt.Sprintf("%c%d", idLetters[k%len(idLetters)], 2+k/len(idLetters))
		if !taken(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("change: no free owner ID")
}

func shortOK(id string) bool {
	if len(id) < 2 || len(id) > 3 || !strings.ContainsRune(idLetters, rune(id[0])) {
		return false
	}
	for _, c := range id[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// safe keeps owner-facing names to a fixed alphabet and length, so no
// candidate-chosen path can carry a sentence into a text (CH-12).
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-", r) {
			b.WriteRune(r)
		}
		if b.Len() >= 40 {
			break
		}
	}
	return b.String()
}

// what says in plain words what an adoption changed, from fields the
// broker knows: classes, owner-configured task class names, machine names,
// provider names, and the signed release version. Never from candidate
// text.
func (p *Pipeline) what(a *Adoption) string {
	has := map[Class]bool{}
	for _, c := range a.Classes {
		has[c] = true
	}
	switch {
	case has[ClassGuestImage] || has[ClassHostImage]:
		v := safe(strings.TrimPrefix(a.Origin, "update:"))
		if a.Staged {
			return "Staged update " + v + "; it starts at the next restart"
		}
		return "Installed update " + v
	case has[ClassConfig]:
		return "Changed a setting"
	case has[ClassRouting]:
		var classes []string
		for _, e := range a.Edits {
			if e.Path == RoutingPath {
				if line := p.primaryChange(e.Before, e.After); line != "" {
					return line
				}
				for c := range routingClasses(e.Before) {
					classes = append(classes, safe(c))
				}
			}
		}
		sort.Strings(classes)
		if len(classes) > 3 {
			classes = append(classes[:3], "other")
		}
		return "Changed which AI handles " + strings.Join(classes, ", ") + " tasks"
	case has[ClassContext]:
		var ms []string
		for _, e := range a.Edits {
			if classOf(e.Path) == ClassContext {
				ms = append(ms, safe(strings.TrimSuffix(strings.TrimPrefix(e.Path, "context/"), ".json")))
			}
		}
		return "Changed what " + strings.Join(ms, ", ") + " looks at first"
	case has[ClassSkill]:
		return "Learned a new way to do a task"
	}
	return "Improved how a task is done"
}

// primaryChange names, per task class, a change of first route provider or
// a dropped local fallback (arbitrator R1); "" when there is none.
func (p *Pipeline) primaryChange(before, after []byte) string {
	var b, n route.Rule
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &n) != nil {
		return ""
	}
	local := func(rs []route.Route) bool {
		for _, r := range rs {
			if p.cfg.LocalProvider != nil && p.cfg.LocalProvider(r.Provider) {
				return true
			}
		}
		return false
	}
	classes := make([]string, 0, len(n))
	for c := range n {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	var parts []string
	for _, c := range classes {
		old, now := b[c], n[c]
		if len(old) == 0 || len(now) == 0 {
			continue
		}
		var s string
		if old[0].Provider != now[0].Provider {
			s = fmt.Sprintf("%s tasks now go first to %s instead of %s", safe(c), safe(now[0].Provider), safe(old[0].Provider))
		}
		if local(old) && !local(now) {
			if s == "" {
				s = safe(c) + " tasks"
			}
			s += " no longer fall back to the local model"
		}
		if s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "Changed AI routing: " + strings.Join(parts, "; ")
}

func routingClasses(b []byte) map[string]bool {
	var r map[string]any
	_ = decodeStrict(b, &r)
	out := map[string]bool{}
	for k := range r {
		out[k] = true
	}
	return out
}

// Digest returns one fixed-template line per adoption or revert not yet
// listed, and marks them listed. No line carries a candidate's own text.
func (p *Pipeline) Digest() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, a := range p.st.Adoptions {
		if !a.Listed {
			line := p.what(a) + "."
			line += testedText(a.Score)
			switch a.Basis {
			case BasisOwner:
				line += " You approved it."
			case BasisSecurity:
				line += " Security update, under your standing policy."
			}
			switch {
			case a.Reverted != "":
			case p.undoableLocked(a):
				line += fmt.Sprintf(" UNDO %s / MORE %s", a.Short, a.Short)
			default:
				line += fmt.Sprintf(" MORE %s", a.Short)
			}
			out = append(out, line)
			a.Listed = true
		}
		if a.Reverted != "" && !a.RevertSeen {
			why := map[string]string{
				WhyOwner:      " as you asked.",
				WhyRegression: ": it did worse on newer tasks.",
				WhySecurity:   ": it failed a security check.",
				WhyFallback:   ": the update did not start cleanly, so the box kept the previous one.",
			}[a.Reverted]
			out = append(out, "Undid "+a.Short+why)
			a.RevertSeen = true
		}
	}
	seen := map[string]bool{}
	for _, d := range p.st.Declined {
		if !seen[d.Version] {
			seen[d.Version] = true
			out = append(out, "You declined security update "+safe(d.Version)+"; the box is still on the previous version until a newer update is installed.")
		}
	}
	for _, a := range p.st.Adoptions {
		if a.Concern != "" && !a.ConcernSeen && a.Reverted == "" {
			s := a.ConcernScore
			line := p.what(&Adoption{Classes: a.Classes, Origin: a.Origin}) + " now"
			if a.Concern == WhySecurity {
				line += " fails a newer security check"
			} else {
				line += fmt.Sprintf(" does worse on %d of %d newer tasks", max(s.Regressions, s.BaselinePassed-s.Passed), s.HeldOut)
			}
			if p.undoableLocked(a) {
				line += ". Reply UNDO " + a.Short + " to go back to the previous version, or nothing to keep it."
			} else {
				line += ". It is the only version on the box, so it stays until a newer update is installed."
			}
			out = append(out, line)
			a.ConcernSeen = true
		}
	}
	if p.st.Outages >= OutageAlert && !p.st.OutageSeen {
		out = append(out, fmt.Sprintf("The box could not re-test its learned changes the last %d times it tried; they stay as they are until it can.", p.st.Outages))
		p.st.OutageSeen = true
	}
	if len(out) > 0 {
		_ = p.saveLocked()
	}
	return out
}

// Ask is the one plain line the owner gets for a proposal that waits on
// them, sent through CH-15 coalescing by the wiring. For a security
// release it says what it fixes, how many past tasks did worse with one
// example, and asks to approve or decline (arbitrator R2).
func (p *Pipeline) Ask(id string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr := p.props[id]
	if pr == nil {
		return "", fmt.Errorf("change: no open proposal %s", id)
	}
	s := pr.report.Score
	if pr.security {
		line := "Security update " + safe(strings.TrimPrefix(pr.cand.Origin, "update:")) + " fixes a security issue."
		if s.Regressions > 0 {
			line += fmt.Sprintf(" It did worse on %d of %d past tasks", s.Regressions, s.HeldOut)
			if c := s.example; c != nil {
				line += ", for example a " + string(c.Class) + " task"
				if !c.At.IsZero() {
					line += " from " + c.At.Format("Jan 2")
				}
			}
			line += "."
		}
		return line + " Approve or decline?", nil
	}
	a := &Adoption{Classes: pr.classes, Edits: pr.edits, Origin: pr.cand.Origin, Staged: true}
	return p.what(a) + "." + testedText(s) + " Approve or decline?", nil
}

// Line gives what the owner is asked to approve for a change intent that
// Check sends to the owner (C8, CH-12): a verb, a short object of at most
// 40 characters (the owner channel's field cap), and whether the owner can
// reverse it later by UNDO or LEARN OFF. The grants gate renders it as a
// high-tier approval item. Every word is broker text built from
// broker-known fields, never a candidate's Claim.
func (p *Pipeline) Line(in journal.Intent) (verb, object string, undoable bool, err error) {
	l, err := p.line(in)
	return l.Verb, l.Object, l.Undoable, err
}

// ownerLine is Line's result.
type ownerLine struct {
	Verb, Object string
	Undoable     bool
}

func (p *Pipeline) line(in journal.Intent) (ownerLine, error) {
	parts := parseID(in.ID)
	if parts == nil {
		return ownerLine{}, errors.New("change: malformed change intent")
	}
	switch in.Action {
	case ActionPolicy:
		if len(parts) == 5 && parts[3] == "sharing" {
			return ownerLine{Verb: "turn on", Object: "sharing learned changes", Undoable: true}, nil
		}
		return ownerLine{Verb: "turn on", Object: "learning without asking", Undoable: true}, nil
	case ActionSuite:
		return ownerLine{Verb: "remove", Object: "a past task from the tests"}, nil
	case ActionAdopt:
	default:
		return ownerLine{}, errors.New("change: no owner line for this action")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pr := p.props[parts[1]]
	if pr == nil || in.ID != adoptID(parts[1]) {
		return ownerLine{}, fmt.Errorf("change: no open proposal %s", parts[1])
	}
	s := pr.report.Score
	a := &Adoption{Classes: pr.classes, Edits: pr.edits}
	undoable := true
	if prev, _, err := undoTree(pr.next, a); err != nil || emptiedSlot(a, prev) != "" {
		undoable = false // the first image a box installs is replaced, never undone
	}
	if images := slices.ContainsFunc(pr.classes, func(c Class) bool { return c == ClassGuestImage || c == ClassHostImage }); images {
		v := safe(strings.TrimPrefix(pr.cand.Origin, "update:"))
		if len(v) > 12 {
			v = v[:12]
		}
		obj := "update " + v
		if pr.security {
			obj = "security update " + v
		}
		if s.Regressions > 0 {
			obj += fmt.Sprintf(", %d/%d tasks worse", s.Regressions, s.HeldOut)
		}
		return ownerLine{Verb: "install", Object: obj, Undoable: undoable}, nil
	}
	has := map[Class]bool{}
	for _, c := range pr.classes {
		has[c] = true
	}
	obj := "a learned procedure"
	switch {
	case has[ClassConfig]:
		obj = "a setting change"
	case has[ClassRouting]:
		obj = "an AI routing change"
	case has[ClassContext]:
		obj = "a context change"
	case has[ClassSkill] && pr.cand.Source == Shared:
		obj = "a shared skill"
	case pr.cand.Source == Shared:
		obj = "a shared procedure"
	case has[ClassSkill]:
		obj = "a learned skill"
	}
	switch {
	case s.HeldOut == 0 && s.NotEvaluated > 0:
		obj += ", not testable here"
	case s.HeldOut == 0:
		obj += ", not tested yet"
	default:
		obj += fmt.Sprintf(", tested on %d tasks", s.HeldOut)
	}
	return ownerLine{Verb: "adopt", Object: obj, Undoable: undoable}, nil
}

func testedText(s Score) string {
	switch {
	case s.HeldOut == 0 && s.NotEvaluated > 0:
		return " Not tested on this box."
	case s.HeldOut == 0:
		return " No past tasks to test it on yet."
	case s.NotEvaluated > 0:
		return fmt.Sprintf(" Tested on %d of your past tasks, none worse; %d could not be tested on this box.", s.HeldOut, s.NotEvaluated)
	}
	return fmt.Sprintf(" Tested on %d of your past tasks, none worse.", s.HeldOut)
}

// More answers MORE <id>: the files an adoption changed and its counts.
// The diff itself stays on the local page.
func (p *Pipeline) More(ref string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.adoptionLocked(ref)
	if a == nil {
		return nil, fmt.Errorf("change: no adoption %s", ref)
	}
	var files []string
	for i, e := range a.Edits {
		if i == 10 {
			files = append(files, fmt.Sprintf("and %d more", len(a.Edits)-10))
			break
		}
		how := "changed"
		switch {
		case e.Before == nil:
			how = "new"
		case e.After == nil:
			how = "removed"
		}
		files = append(files, safe(e.Path)+" ("+how+")")
	}
	s := a.Score
	return []string{
		a.Short + " changed: " + strings.Join(files, ", "),
		fmt.Sprintf("Past tasks: %d tested, %d passed (%d before). Security checks: %d of %d passed.",
			s.HeldOut, s.Passed, s.BaselinePassed, s.SecurityPassed, s.Security),
	}, nil
}
