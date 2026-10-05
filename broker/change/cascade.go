package change

import (
	"bytes"
	"errors"
	"slices"
)

// learnedClass are the classes a candidate learned from owner tasks may
// change, Loop 1's (C23); Propose rejects one with Goals elsewhere.
var learnedClass = map[Class]bool{ClassSkill: true, ClassProcedure: true, ClassContext: true}

// ErrForgotten: the candidate was built from a task the owner forgot
// (C23). It is never adopted.
var ErrForgotten = errors.New("change: built from a forgotten task")

// goneLocked reports whether any of goals was forgotten since start.
func (p *Pipeline) goneLocked(goals []string) bool {
	for _, g := range goals {
		if p.gone[g] {
			return true
		}
	}
	return false
}

// forgetAdoptionsLocked removes from the active tree and from history the
// files of every adoption learned from goal (security C1 on #120, C23),
// newest first, and drops proposals built from it. An active one is
// undone, as if never adopted: each file it wrote goes back to what it was
// before, unless a later adoption still active edited it since, and then
// that adoption's UNDO goes back to the same earlier file instead, if it
// built on this one's. Every such
// adoption's own file contents are cleared, active or undone, so neither
// the tree nor the saved state keeps them. It returns the tree to make
// active, the history to keep, the edits whose namespaces changed, and
// whether anything did. It changes p.st only through the copies it
// returns: the caller activates, then commits.
func (p *Pipeline) forgetAdoptionsLocked(goal string) (Tree, []*Adoption, []Edit, bool) {
	for id, pr := range p.props {
		if slices.Contains(pr.cand.Goals, goal) {
			delete(p.props, id)
		}
	}
	if !slices.ContainsFunc(p.st.Adoptions, func(a *Adoption) bool { return slices.Contains(a.Goals, goal) }) {
		return p.st.Active, p.st.Adoptions, nil, false // the common case on a replay at start
	}
	next := p.st.Active.clone()
	ads := make([]*Adoption, len(p.st.Adoptions))
	for i, a := range p.st.Adoptions {
		c := *a
		c.Edits = slices.Clone(a.Edits)
		ads[i] = &c
	}
	var touched []Edit
	changed := false
	for i := len(ads) - 1; i >= 0; i-- {
		a := ads[i]
		if !slices.Contains(a.Goals, goal) {
			continue
		}
		for k, e := range a.Edits {
			if cleared(e) {
				continue // cleared by an earlier forget
			}
			// The file's successors, by succession and not by bytes alone
			// (L3 MUST-1 on #160): an undone later adoption kept the file
			// in its history, so its UNDO-side copy goes back past it too;
			// the first later one still active built on it, if its Before
			// is this file, and owns the path from then on.
			superseded := false
			for _, b := range ads[i+1:] {
				j := slices.IndexFunc(b.Edits, func(f Edit) bool { return f.Path == e.Path && !cleared(f) })
				if j < 0 {
					continue
				}
				if f := b.Edits[j]; (f.Before != nil) == (e.After != nil) && bytes.Equal(f.Before, e.After) {
					b.Edits[j].Before = bytes.Clone(e.Before)
				}
				if b.Reverted == "" {
					superseded = true
					break
				}
			}
			cur, ok := next[e.Path]
			if a.Reverted == "" && !superseded && ok == (e.After != nil) && bytes.Equal(cur, e.After) {
				if e.Before == nil {
					delete(next, e.Path)
				} else {
					next[e.Path] = bytes.Clone(e.Before)
				}
				touched = append(touched, Edit{Path: e.Path})
			}
			a.Edits[k] = Edit{Path: e.Path}
			changed = true
		}
		if a.Reverted == "" {
			a.Reverted = WhyForgotten
			changed = true
		}
	}
	return next, ads, touched, changed
}

// cleared reports whether a forget cleared e: no edit writes nothing over
// nothing.
func cleared(e Edit) bool { return e.Before == nil && e.After == nil }
