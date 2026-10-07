package grants

import (
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/reversible"
)

// sweptHold names, in the owner's fixed RV7 lines, an effect whose hold
// a restart ended: the owner channel's hold ID did not survive it.
const sweptHold = "An action you approved before the restart"

// Sweep settles the staged copies a restart left behind (RV11; L3 F2 on
// #76). Call it at start, after Attach and before the owner channel's
// Boot, so Boot's own cancels wait for it instead of racing it.
//
// It finds each stage that succeeded and has no inverse yet. Its copy is
// removed when its effect has not succeeded and will not send it: denied,
// not applied (unless the adapter reported the copy gone, or edited and so
// left for the owner), or pending with no hold of its own on (a cancelled
// hold is asked again, and the next hold stages afresh). That covers a
// stage in flight at a crash that the journal later finds succeeded, which
// the restart's cancel could not unstage. A released effect still waiting
// to be dispatched (authorized, or in flight) keeps its latest copy, and
// is handed to endHeld, so it is settled when it ends: a release STOP held
// over a restart. An inverse that is not applied leaves the copy, and the
// owner is told in the fixed RV7 line. The removals run in the
// background; Wait waits for them.
func (g *Gate) Sweep() {
	g.mu.Lock()
	eng := g.eng
	g.mu.Unlock()
	if eng == nil || len(g.forms) == 0 {
		return
	}
	for _, st := range eng.List() {
		p, n, ok := reversible.Parent(st.Intent)
		sid := st.Intent.ID
		if !ok || sid != reversible.StageID(p, n) || st.State != journal.Succeeded || len(st.Attempts) == 0 {
			continue
		}
		if _, err := eng.Get(reversible.InverseID(p, n)); err == nil {
			continue
		}
		ps, err := eng.Get(p)
		if err != nil {
			continue
		}
		f, ok := g.forms[ps.Intent.Executor][ps.Intent.Action]
		if !ok || f.Stage == "" {
			continue
		}
		g.mu.Lock()
		w := g.waiting[p]
		live := w != nil && w.held && w.attempt == n
		_, busy := g.staging[sid]
		g.mu.Unlock()
		if live || busy {
			continue
		}
		ev := lastEvidence(ps)
		switch {
		case ps.State == journal.Authorized || ps.State == journal.InFlight:
			if last, _ := g.lastStage(p); last == n {
				g.mu.Lock()
				if _, ok := g.after[p]; !ok {
					g.after[p] = afterRef{hold: sweptHold, n: n}
				}
				g.mu.Unlock()
			}
		case ps.State == journal.NotApplied && (ev == reversible.EvidenceGone || ev == reversible.EvidenceEdited):
		case ps.State == journal.Denied || ps.State == journal.NotApplied || ps.State == journal.Pending:
			// The staging mark makes a cancel's unstage of the same copy
			// wait for this one, then find its inverse and stop.
			done := make(chan struct{})
			g.mu.Lock()
			g.staging[sid] = done
			g.mu.Unlock()
			g.wg.Add(1)
			go func(parent journal.Intent, stage journal.Status) {
				defer g.wg.Done()
				defer close(done)
				g.sweepOne(parent, f, n, stage)
			}(ps.Intent, st)
		}
	}
}

// sweepOne runs the inverse of parent's n-th stage.
func (g *Gate) sweepOne(parent journal.Intent, f reversible.Form, n int, stage journal.Status) {
	in := reversible.Inverse(parent, f, n, lastEvidence(stage))
	if _, err := g.eng.Get(in.ID); err == nil {
		return
	}
	g.mu.Lock()
	g.derived[in.ID] = true
	own := g.own
	g.mu.Unlock()
	if st := g.runDerived(in); st.State != journal.Succeeded && own != nil {
		_ = own.Inform(sweptHold + " did not run, but its draft or staged copy could not be removed, so it was left as is.")
	}
}
