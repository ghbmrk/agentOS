package change

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// GoalVerdict is the verdict a goal's latest quality record carried, empty
// while it has none.
type GoalVerdict struct {
	Goal    string          `json:"goal"`
	Verdict journal.Verdict `json:"verdict,omitempty"`
}

// QualityRetry is how long the quality trigger waits after a pass left an
// adoption due, so an evaluator outage or a failing revert is not retried
// on every scheduler pass.
const QualityRetry = time.Hour

// goalVerdicts reads each goal's latest verdict from the journal. A goal
// the journal cannot read is recorded with no verdict, so the first one
// it reads differs.
func (p *Pipeline) goalVerdicts(goals []string) []GoalVerdict {
	if len(goals) == 0 || p.j == nil {
		return nil
	}
	out := make([]GoalVerdict, 0, len(goals))
	for _, g := range goals {
		v := GoalVerdict{Goal: g}
		if st, err := p.j.Get(g); err == nil {
			v.Verdict = st.Quality.Verdict
		}
		out = append(out, v)
	}
	return out
}

// qualityDue is an active adoption a goal-quality revision reaches, with
// the verdicts it is re-evaluated on.
type qualityDue struct {
	id  string
	now []GoalVerdict
}

// qualityStale lists, newest first, the active adoptions some goal of
// which now has a latest verdict other than the one remembered for it
// (OP-7: the revision is the order of a goal's quality records, and the
// journal keeps the latest). A goal with no remembered verdict, as on an
// adoption from before verdicts were kept, differs once. A goal the
// journal cannot read is left out: it changed nothing it can tell.
func (p *Pipeline) qualityStale() []qualityDue {
	type ref struct {
		id    string
		goals []string
		seen  []GoalVerdict
	}
	p.mu.Lock()
	j := p.j
	var refs []ref
	for i := len(p.st.Adoptions) - 1; i >= 0; i-- {
		if a := p.st.Adoptions[i]; a.Reverted == "" && len(a.Goals) > 0 {
			refs = append(refs, ref{a.ID, slices.Clone(a.Goals), a.GoalVerdicts})
		}
	}
	p.mu.Unlock()
	if j == nil {
		return nil
	}
	// The journal is read without p.mu: a goal shared by several
	// adoptions is read once.
	latest := map[string]*journal.Verdict{}
	read := func(g string) *journal.Verdict {
		if v, ok := latest[g]; ok {
			return v
		}
		var v *journal.Verdict
		if st, err := j.Get(g); err == nil {
			v = &st.Quality.Verdict
		}
		latest[g] = v
		return v
	}
	var out []qualityDue
	for _, r := range refs {
		changed := false
		now := make([]GoalVerdict, 0, len(r.goals))
		for _, g := range r.goals {
			v := read(g)
			i := slices.IndexFunc(r.seen, func(s GoalVerdict) bool { return s.Goal == g })
			if v == nil {
				if i >= 0 {
					now = append(now, r.seen[i])
				}
				continue
			}
			now = append(now, GoalVerdict{Goal: g, Verdict: *v})
			changed = changed || i < 0 || r.seen[i].Verdict != *v
		}
		if changed {
			out = append(out, qualityDue{r.id, now})
		}
	}
	return out
}

// QualityDue reports whether a goal-quality revision reached an active
// adoption that RecheckQuality has not re-evaluated on it yet. It is true
// at boot for a revision recorded while the broker was down (SM-AQ-4).
func (p *Pipeline) QualityDue() bool {
	p.mu.Lock()
	wait := p.cfg.Now().Before(p.qualityRetry)
	p.mu.Unlock()
	return !wait && len(p.qualityStale()) > 0
}

// RecheckQuality re-evaluates, newest first, exactly the active adoptions
// a goal-quality revision reached (OP-7, SM-AQ-1), on Recheck's
// per-adoption path: one that no longer qualifies is reverted, why
// regression or security, and a protected one raises Concern instead
// (SM-AQ-2). A restated verdict reaches none (SM-AQ-3). Each adoption
// re-evaluated, kept or put to the owner remembers the verdicts it was
// evaluated on, so it is not due again until one changes. It returns the
// reverted IDs.
func (p *Pipeline) RecheckQuality(ctx context.Context) ([]string, error) {
	var out []string
	var errs []error
	retry := false
	defer func() {
		if retry {
			p.mu.Lock()
			p.qualityRetry = p.cfg.Now().Add(QualityRetry)
			p.mu.Unlock()
		}
	}()
	for _, d := range p.qualityStale() {
		if p.awaitsCase(d) {
			// Nothing is remembered: the case's revision makes it due
			// again at once, the retry wait otherwise.
			retry = true
			continue
		}
		switch res, err := p.recheckOne(ctx, d.id); res {
		case recheckInterrupted, recheckStopped:
			// Nothing is remembered: the next pass re-evaluates it.
			return out, errors.Join(append(errs, err)...)
		case recheckReverted:
			out = append(out, d.id)
		case recheckKept, recheckConcern, recheckSkipped:
			p.rememberVerdicts(d.id, d.now)
		case recheckOutage, recheckHandover:
			retry = true
		case recheckFailed:
			retry = true
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

// awaitsCase reports whether due adoption d is held because the case of
// one of its goals, a task case whose Task is the goal, still carries the
// outcome of the verdict before the revision: Harvest records the verdict
// first and revises the case after, and scoring on the case in between
// would settle the adoption on the stale outcome (OP-7, QCR-3). It is held
// one retry wait at most, so a revision whose case never comes (a crash
// between the two) is scored on the suite as it stands rather than never.
func (p *Pipeline) awaitsCase(d qualityDue) bool {
	want := map[string]journal.Verdict{}
	for _, gv := range d.now {
		if gv.Verdict != "" {
			want[gv.Goal] = gv.Verdict
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	stale := false
	for _, c := range p.st.Cases {
		if v, ok := want[c.Task]; ok && !c.Security && !backs(v, c.Outcome) {
			stale = true
			break
		}
	}
	now := p.cfg.Now()
	since, held := p.qualityHeld[d.id]
	if !stale || held && !now.Before(since.Add(QualityRetry)) {
		delete(p.qualityHeld, d.id)
		return false
	}
	if !held {
		if p.qualityHeld == nil {
			p.qualityHeld = map[string]time.Time{}
		}
		p.qualityHeld[d.id] = now
	}
	return true
}

// backs reports whether verdict v is the one outcome o records, as
// AddTaskCase requires of a case.
func backs(v journal.Verdict, o Outcome) bool {
	switch v {
	case journal.VerdictGood:
		return o == Accepted
	case journal.VerdictWrong:
		return o == Corrected || o == Rejected
	}
	return true
}

// rememberVerdicts replaces the verdicts active adoption id was evaluated
// on, and saves.
func (p *Pipeline) rememberVerdicts(id string, now []GoalVerdict) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.adoptionLocked(id)
	if a == nil || a.Reverted != "" || slices.Equal(a.GoalVerdicts, now) {
		return
	}
	a.GoalVerdicts = now
	_ = p.saveLocked()
}
