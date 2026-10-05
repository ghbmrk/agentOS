package change

import (
	"bytes"
	"errors"
	"slices"
)

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
// before, unless a later adoption changed it since, and then that later
// adoption's UNDO goes back to the same earlier file instead. Every such
// adoption's own file contents are cleared, active or undone, so neither
// the tree nor the saved state keeps them. It returns the tree to make
// active, the history to keep, the edits whose namespaces changed, and
// whether anything did. It changes p.st only through the copies it
// returns: the caller activates, then commits.
func (p *Pipeline) forgetAdoptionsLocked(goal string) (Tree, []*Adoption, []Edit, bool) {
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
			if e.Before == nil && e.After == nil {
				continue // cleared by an earlier forget
			}
			cur, ok := next[e.Path]
			if a.Reverted == "" && ok == (e.After != nil) && bytes.Equal(cur, e.After) {
				if e.Before == nil {
					delete(next, e.Path)
				} else {
					next[e.Path] = bytes.Clone(e.Before)
				}
				touched = append(touched, Edit{Path: e.Path})
			}
			// Later adoptions built on this file go back past it.
			for _, b := range ads[i+1:] {
				for j, f := range b.Edits {
					if f.Path == e.Path && (f.Before != nil) == (e.After != nil) && bytes.Equal(f.Before, e.After) {
						b.Edits[j].Before = bytes.Clone(e.Before)
					}
				}
			}
			a.Edits[k] = Edit{Path: e.Path}
			changed = true
		}
		if a.Reverted == "" {
			a.Reverted = WhyForgotten
			changed = true
		}
	}
	for id, pr := range p.props {
		if slices.Contains(pr.cand.Goals, goal) {
			delete(p.props, id)
		}
	}
	return next, ads, touched, changed
}
