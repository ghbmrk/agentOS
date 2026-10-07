package change

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/routerule"
)

// idLetters avoids I and O, as the owner channel's IDs do.
const idLetters = "ABCDEFGHJKLMNPQRSTUVWXYZ"

// shortLocked allocates an owner-facing ID not used by an active adoption
// or by any of the last 200 adoptions.
func (p *Pipeline) shortLocked() (string, error) {
	recent := p.recentShortsLocked()
	taken := func(id string) bool { return recent[id] }
	if p.cfg.ShortID != nil {
		id, err := p.cfg.ShortID(taken)
		if err != nil {
			return "", err
		}
		if id != "" {
			if taken(id) || !shortOK(id) {
				return "", fmt.Errorf("change: owner ID %q is in use or malformed", id)
			}
			return id, nil
		}
		// "": the allocator has nothing to give yet (the owner channel
		// is not up); the pipeline's own sequence stands in.
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

// recentShortsLocked is every owner-facing ID the pipeline still answers
// to: active adoptions and the last 200. Caller holds mu.
func (p *Pipeline) recentShortsLocked() map[string]bool {
	recent := map[string]bool{}
	for i, a := range p.st.Adoptions {
		if a.Reverted == "" || i >= len(p.st.Adoptions)-200 {
			recent[a.Short] = true
		}
	}
	return recent
}

// refreshShortsLocked publishes recentShortsLocked for ShortInUse. Caller
// holds mu.
func (p *Pipeline) refreshShortsLocked() {
	m := p.recentShortsLocked()
	p.shorts.Store(&m)
}

// ShortInUse reports whether the pipeline still answers to owner-facing ID
// id (an UNDO or MORE in a digest line). It takes no lock, so the owner
// channel may call it while allocating its own request IDs under its lock
// (Config.ShortID runs the other way, under the pipeline's lock), and its
// requests never take an ID an adoption uses (C11).
func (p *Pipeline) ShortInUse(id string) bool {
	m := p.shorts.Load()
	return id != "" && m != nil && (*m)[id]
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
	var b, n routerule.Rule
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &n) != nil {
		return ""
	}
	local := func(rs []routerule.Route) bool {
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
				WhyForgotten:  ": it was learned from a task you asked the box to forget.",
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
	for i := range p.st.Notices {
		if n := &p.st.Notices[i]; !n.Seen {
			out = append(out, n.Line)
			n.Seen = true
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

// MaxNotices bounds the notice keys the pipeline keeps.
const MaxNotices = 32

// Notice queues one broker line for the digest under key, once: a key
// already kept, listed or not, adds nothing, across restarts. Callers pass
// fixed broker wording only, never candidate or agent text (CH-12). It is
// for what is not urgent, which CH-15 holds for the digest (UX-108-1). The
// oldest kept keys go first once there are more than MaxNotices, listed
// ones before any still waiting.
func (p *Pipeline) Notice(key, line string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, n := range p.st.Notices {
		if n.Key == key {
			return nil
		}
	}
	prev := p.st.Notices
	ns := append(append([]notice(nil), prev...), notice{Key: key, Line: line})
	for len(ns) > MaxNotices {
		drop := 0
		for i, n := range ns {
			if n.Seen {
				drop = i
				break
			}
		}
		ns = append(ns[:drop], ns[drop+1:]...)
	}
	p.st.Notices = ns
	if err := p.saveLocked(); err != nil {
		p.st.Notices = prev
		return err
	}
	return nil
}

// Superseded records that the owner's own configuration now stands in for
// namespace ns's adopted state, which its target could no longer take (the
// owner changed the configuration it reorders; W3-route-a, L3 MUST-1 on
// #110). If ns's active files still equal was, they are dropped, since the
// empty tree stands for the owner's configuration, and every active
// adoption that edited ns is marked undone with WhySettings, with no line
// of its own: the caller's Notice tells the owner. The target is not
// called; it already runs the owner's configuration. A stale was changes
// nothing. It reports whether the active tree changed. It is only for a
// namespace whose empty tree means the owner's own configuration, today
// routing alone (security R3 on #110). This records what
// runs rather than changing it, so it is no intent (CHG-2): later
// evaluations then compare against what the owner actually has.
func (p *Pipeline) Superseded(ns string, was Tree) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.st.Active.under(ns)
	if len(cur) == 0 || cur.Hash() != was.Hash() {
		return false, nil
	}
	prevActive, prevAdoptions := p.st.Active, p.st.Adoptions
	next := Tree{}
	for path, b := range p.st.Active {
		if namespace(path) != ns {
			next[path] = b
		}
	}
	adoptions := make([]*Adoption, len(p.st.Adoptions))
	for i, a := range p.st.Adoptions {
		adoptions[i] = a
		if a.Reverted != "" {
			continue
		}
		for _, e := range a.Edits {
			if namespace(e.Path) == ns {
				c := *a
				c.Reverted, c.RevertSeen = WhySettings, true
				adoptions[i] = &c
				break
			}
		}
	}
	p.st.Active, p.st.Adoptions = next, adoptions
	if err := p.saveLocked(); err != nil {
		p.st.Active, p.st.Adoptions = prevActive, prevAdoptions
		return false, err
	}
	return true, nil
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

// Line gives the item the owner is asked to approve for a change intent
// that Check sends to the owner (C8, CH-12): a verb, a short object (the
// owner channel caps it at 40 characters), the test result as a separate
// detail so the cap never cuts it, and how the owner can reverse it later.
// Every word is broker text built from broker-known fields, never a
// candidate's Claim. Kind sets the tier (arbitrator ruling on #48): a local
// learned skill or procedure tested on past tasks that UNDO can reverse is
// an ordinary low-tier item, answered with the request's texted code;
// everything else (images, settings, routing, context, shared packages,
// untested changes, policy and suites) is GrantChange, so always high tier.
// The grants gate sets Ref and keeps it recipient-free.
func (p *Pipeline) Line(in journal.Intent) (owner.Item, error) {
	parts := parseID(in.ID)
	if parts == nil {
		return owner.Item{}, errors.New("change: malformed change intent")
	}
	high := func(verb, obj, detail, undo string) owner.Item {
		return owner.Item{Object: obj, Detail: detail, UndoBy: undo,
			Facts: owner.Facts{Kind: owner.GrantChange, Verb: verb, NoRecipient: true}}
	}
	switch in.Action {
	case ActionPolicy:
		if len(parts) == 5 && parts[3] == "sharing" {
			return high("turn on", "sharing learned changes", "", "can be undone later"), nil
		}
		return high("turn on", "learning without asking", "", "LEARN OFF any time"), nil
	case ActionSuite:
		p.mu.Lock()
		c, ok := p.st.Cases[parts[len(parts)-1]]
		p.mu.Unlock()
		obj := "a past task from the tests"
		switch {
		case ok && c.Security:
			// Removing a security fixture weakens LOOP-10; say so.
			obj = "a security check from the tests"
		case ok && !c.At.IsZero():
			obj = "the " + c.At.Format("Jan 2") + " " + string(c.Class) + " task from the tests"
		}
		return high("remove", obj, "", ""), nil
	case ActionAdopt:
	default:
		return owner.Item{}, errors.New("change: no owner line for this action")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pr := p.props[parts[1]]
	if pr == nil || in.ID != adoptID(parts[1]) {
		return owner.Item{}, fmt.Errorf("change: no open proposal %s", parts[1])
	}
	s := pr.report.Score
	a := &Adoption{Classes: pr.classes, Edits: pr.edits}
	undo := "can be undone later"
	if prev, _, err := undoTree(pr.next, a); err != nil || emptiedSlot(a, prev) != "" {
		undo = "" // the first image a box installs is replaced, never undone
	}
	tested := ""
	switch {
	case s.HeldOut == 0 && s.NotEvaluated > 0:
		tested = "not testable on this box"
	case s.HeldOut == 0:
		tested = "not tested on past tasks yet"
	case s.Regressions > 0:
		tested = fmt.Sprintf("worse on %d of %d past tasks", s.Regressions, s.HeldOut)
	default:
		tested = fmt.Sprintf("tested on %d past tasks, none worse", s.HeldOut)
	}
	if slices.ContainsFunc(pr.classes, func(c Class) bool { return c == ClassGuestImage || c == ClassHostImage }) {
		v := safe(strings.TrimPrefix(pr.cand.Origin, "update:"))
		if len(v) > 20 {
			v = v[:20]
		}
		obj := "update " + v
		if pr.security {
			obj = "security update " + v
		}
		return high("install", obj, tested, undo), nil
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
		for _, e := range pr.edits {
			if e.Path != RoutingPath {
				continue
			}
			var names []string
			for c := range routingClasses(e.After) {
				names = append(names, safe(c))
			}
			sort.Strings(names)
			if len(names) > 0 && len(strings.Join(names, ", ")) <= 20 {
				obj = "AI routing for " + strings.Join(names, ", ") + " tasks"
			}
		}
	case has[ClassContext]:
		obj = "a context change"
	case has[ClassSkill] && pr.cand.Source == Shared:
		obj = "a shared skill"
	case pr.cand.Source == Shared:
		obj = "a shared procedure"
	case has[ClassSkill]:
		obj = "a learned skill"
	}
	learned := pr.cand.Source == Local && !has[ClassConfig] && !has[ClassRouting] && !has[ClassContext]
	if learned && s.HeldOut > 0 && undo != "" {
		return owner.Item{Object: obj, Detail: tested, UndoBy: undo,
			Facts: owner.Facts{Kind: owner.Ordinary, Verb: "adopt", NoRecipient: true}}, nil
	}
	return high("adopt", obj, tested, undo), nil
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
		case cleared(e):
			how = "forgotten"
		case e.After == nil:
			// Before it, as a delete can hold nothing either side once a
			// forget took its Before back past a forgotten file (C23).
			how = "removed"
		case e.Before == nil:
			how = "new"
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
