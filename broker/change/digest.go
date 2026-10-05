package change

import (
	"fmt"
	"sort"
	"strings"
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
	if len(id) < 2 || len(id) > 3 || id[0] < 'A' || id[0] > 'Z' {
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
// and the signed release version. Never from candidate text.
func (a *Adoption) what() string {
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
			line := a.what() + "."
			if a.Score.HeldOut > 0 {
				line += fmt.Sprintf(" Tested on %d of your past tasks, none worse.", a.Score.HeldOut)
			} else {
				line += " No past tasks to test it on yet."
			}
			switch a.Basis {
			case BasisOwner:
				line += " You approved it."
			case BasisSecurity:
				line += " Security update, under your standing policy."
			}
			if a.Reverted == "" {
				line += fmt.Sprintf(" UNDO %s / MORE %s", a.Short, a.Short)
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
	if len(out) > 0 {
		_ = p.saveLocked()
	}
	return out
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
