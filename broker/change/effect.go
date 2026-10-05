package change

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Revert reasons, also the last part of a revert intent ID.
const (
	WhyOwner      = "owner"
	WhyRegression = "regression"
	WhySecurity   = "security"
	WhyFallback   = "fallback" // a staged image did not boot cleanly
)

// Check is the policy for meta.change intents (OP-3), run at authorize and
// again before dispatch. It returns nil when the pipeline's own standing
// rules allow the intent, ErrNeedsOwner when only the owner may, and any
// other error to deny.
func (p *Pipeline) Check(_ context.Context, _ journal.Phase, in journal.Intent) error {
	if in.Account != journal.BrokerAccount || in.Executor != Executor {
		return errors.New("change: not a change intent")
	}
	parts := parseID(in.ID)
	if parts == nil {
		return errors.New("change: malformed change intent")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != nil {
		return p.broken
	}
	switch in.Action {
	case ActionAdopt:
		pr := p.props[parts[1]]
		if pr == nil || in.ID != adoptID(parts[1]) || in.Origin != OriginPipeline {
			return errors.New("change: no qualified candidate for this intent")
		}
		if pr.report.Basis != in.GrantRef {
			return errors.New("change: basis differs from the evaluation")
		}
		if pr.base != p.st.Active.Hash() {
			return errors.New("change: the active state changed since evaluation; propose again")
		}
		switch in.GrantRef {
		case BasisStanding:
			if !p.st.AutoAdopt {
				return ErrNeedsOwner
			}
			return nil
		case BasisSecurity:
			if !p.cfg.SecurityAutoStage {
				return ErrNeedsOwner
			}
			return nil
		}
		return ErrNeedsOwner
	case ActionRevert:
		if len(parts) != 5 || parts[2] != "revert" {
			return errors.New("change: malformed revert")
		}
		switch {
		case in.Origin == OriginOwner && parts[4] == WhyOwner:
		case in.Origin == OriginPipeline && (parts[4] == WhyRegression || parts[4] == WhySecurity || parts[4] == WhyFallback):
		default:
			return errors.New("change: only the owner or the pipeline reverts")
		}
		a := p.adoptionLocked(parts[1])
		if a == nil || a.Reverted != "" {
			return errors.New("change: no active adoption " + parts[1])
		}
		return nil
	case ActionPolicy, ActionPolicyOff:
		if in.Origin != OriginOwner || len(parts) != 5 || parts[1] != "policy" {
			return errors.New("change: only the owner changes adoption policy")
		}
		if parts[3] != "auto_adopt" && parts[3] != "sharing" {
			return errors.New("change: unknown policy setting")
		}
		switch {
		case in.Action == ActionPolicyOff && parts[4] == "off":
			return nil // narrowing needs only the owner's text
		case in.Action == ActionPolicy && parts[4] == "on":
			return ErrNeedsOwner // widening is an owner-approved intent (CHG-2)
		}
		return errors.New("change: policy action and value disagree")
	case ActionSuite:
		if in.Origin != OriginOwner || len(parts) != 5 || parts[1] != "suite" || parts[3] != "remove" {
			return errors.New("change: only the owner changes a suite")
		}
		if _, ok := p.st.Cases[parts[4]]; !ok {
			return errors.New("change: no such case")
		}
		return ErrNeedsOwner
	}
	return errors.New("change: unknown change action")
}

func (p *Pipeline) adoptionLocked(ref string) *Adoption {
	for _, a := range p.st.Adoptions {
		if a.ID == ref {
			return a
		}
	}
	// Owner-facing IDs can be reused after a revert; the active one wins,
	// then the newest.
	var hit *Adoption
	for _, a := range p.st.Adoptions {
		if a.Short == ref && (hit == nil || a.Reverted == "" || hit.Reverted != "") {
			hit = a
		}
	}
	return hit
}

// Execute performs a change intent; the journal calls it after the
// dispatch record is durable.
func (p *Pipeline) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	parts := parseID(in.ID)
	if parts == nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed change intent"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: p.broken.Error()}
	}
	if p.st.Applied[in.ID] {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "already applied"}
	}
	var err error
	switch in.Action {
	case ActionAdopt:
		err = p.adoptLocked(parts[1], in.GrantRef)
	case ActionRevert:
		err = p.revertLocked(parts[1], parts[4])
	case ActionPolicy, ActionPolicyOff:
		on := in.Action == ActionPolicy
		if parts[3] == "auto_adopt" {
			p.st.AutoAdopt = on
		} else {
			p.st.Sharing = on
		}
	case ActionSuite:
		next := p.st.copyCases()
		delete(next, parts[4])
		p.st.Cases = next
	default:
		err = errors.New("unknown change action")
	}
	if err != nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: err.Error()}
	}
	p.st.Applied[in.ID] = true
	if err := p.saveLocked(); err != nil {
		// The in-memory state moved but is not durable; go back to what
		// is. If that fails too, stop taking changes.
		if rerr := p.reloadLocked(); rerr != nil {
			p.broken = fmt.Errorf("change: state cannot be saved (%v) or reloaded (%v); restart needed", err, rerr)
		}
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "state not saved: " + err.Error()}
	}
	return journal.Outcome{Result: journal.ResultSucceeded}
}

// Reconcile reports from the pipeline's own durable state. A crash before
// the state was saved leaves the old tree, which New re-applies, so the
// effect did not happen.
func (p *Pipeline) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st.Applied[in.ID] {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "in saved state"}
	}
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not in saved state"}
}

func (p *Pipeline) reloadLocked() error {
	raw, err := p.cfg.Store.Load()
	if err != nil {
		return err
	}
	if raw == nil {
		return errors.New("no saved state")
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	if st.Applied == nil {
		st.Applied = map[string]bool{}
	}
	p.st = st
	for ns, tg := range p.cfg.Targets {
		if err := tg.Apply(p.st.Active.under(ns)); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) adoptLocked(id, basis string) error {
	pr := p.props[id]
	if pr == nil {
		return errors.New("no qualified candidate")
	}
	if pr.base != p.st.Active.Hash() {
		return errors.New("the active state changed since evaluation")
	}
	short, err := p.shortLocked()
	if err != nil {
		return err
	}
	if err := p.activateLocked(p.st.Active, pr.next, pr.edits); err != nil {
		return err
	}
	staged := false
	for _, c := range pr.classes {
		staged = staged || c == ClassGuestImage || c == ClassHostImage
	}
	p.st.Active = pr.next
	p.st.Adoptions = append(p.st.Adoptions, &Adoption{ID: id, Short: short, Source: pr.cand.Source,
		Classes: pr.classes, Basis: basis, Edits: pr.edits, Score: pr.report.Score, Public: pr.cand.Public,
		Staged: staged, Origin: pr.cand.Origin, At: p.cfg.Now()})
	return nil
}

// activateLocked applies next to every target whose namespace an edit
// touches. If one fails, the targets already changed get prev back:
// activate with fallback. For image namespaces the target stages into the
// inactive slot (UPD-1).
func (p *Pipeline) activateLocked(prev, next Tree, edits []Edit) error {
	touched := map[string]bool{}
	for _, e := range edits {
		touched[namespace(e.Path)] = true
	}
	nss := make([]string, 0, len(touched))
	for ns := range touched {
		if p.cfg.Targets[ns] != nil {
			nss = append(nss, ns)
		}
	}
	sort.Strings(nss)
	for i, ns := range nss {
		if err := p.cfg.Targets[ns].Apply(next.under(ns)); err != nil {
			for _, done := range nss[:i+1] {
				_ = p.cfg.Targets[done].Apply(prev.under(done))
			}
			return fmt.Errorf("activating %s failed, kept the previous state: %v", ns, err)
		}
	}
	return nil
}

// UndoError is a revert refused because a later adoption changed the same
// files. Its text is the owner-facing reply.
type UndoError struct{ Short, Later string }

func (e *UndoError) Error() string {
	return fmt.Sprintf("Can't undo %s alone: %s changed the same thing later. Reply UNDO %s %s to undo both.",
		e.Short, e.Later, e.Later, e.Short)
}

// undoTreeLocked returns the active tree with one adoption's edits undone,
// or an UndoError if any path it changed has changed again since.
func (p *Pipeline) undoTreeLocked(a *Adoption) (Tree, error) {
	next, path, err := undoTree(p.st.Active, a)
	if err == nil {
		return next, nil
	}
	later := "a later change"
	for i := len(p.st.Adoptions) - 1; i >= 0; i-- {
		b := p.st.Adoptions[i]
		if b == a {
			break
		}
		for _, e := range b.Edits {
			if e.Path == path && b.Reverted == "" {
				later = b.Short
			}
		}
	}
	return nil, &UndoError{Short: a.Short, Later: later}
}

func undoTree(cur Tree, a *Adoption) (Tree, string, error) {
	next := cur.clone()
	for _, e := range a.Edits {
		now, present := cur[e.Path]
		if present != (e.After != nil) || !bytes.Equal(now, e.After) {
			return nil, e.Path, errors.New(e.Path + " changed since")
		}
		if e.Before == nil {
			delete(next, e.Path)
		} else {
			next[e.Path] = append([]byte{}, e.Before...)
		}
	}
	return next, "", nil
}

func (p *Pipeline) revertLocked(id, why string) error {
	a := p.adoptionLocked(id)
	if a == nil || a.Reverted != "" {
		return errors.New("no active adoption " + id)
	}
	next, err := p.undoTreeLocked(a)
	if err != nil {
		return err
	}
	if err := p.activateLocked(p.st.Active, next, a.Edits); err != nil {
		return err
	}
	p.st.Active = next
	a.Reverted = why
	return nil
}

// Revert undoes an adoption by its ID or owner-facing short ID: the
// owner's UNDO <id>, or the pipeline itself on a regression, a security
// failure, or a staged image that fell back. Each attempt is its own
// intent, so a refused or foreign attempt never blocks a later one.
func (p *Pipeline) Revert(ctx context.Context, ref, origin string) error {
	why := WhyOwner
	if origin == OriginPipeline {
		why = WhyRegression
	}
	return p.revert(ctx, ref, origin, why)
}

func (p *Pipeline) revert(ctx context.Context, ref, origin, why string) error {
	p.mu.Lock()
	a := p.adoptionLocked(ref)
	if a == nil || a.Reverted != "" {
		p.mu.Unlock()
		return fmt.Errorf("change: %s is not an active adoption", ref)
	}
	id := a.ID
	if _, err := p.undoTreeLocked(a); err != nil {
		p.mu.Unlock()
		return err
	}
	p.mu.Unlock()
	n, err := p.nonce()
	if err != nil {
		return err
	}
	return p.run(ctx, journal.Intent{ID: fmt.Sprintf("chg:%s:revert:%s:%s", id, n, why), Origin: origin,
		Account: journal.BrokerAccount, Action: ActionRevert, Executor: Executor})
}

// ConfirmStaged records that a staged image booted and passed its health
// check (UPD-1); the update code calls it.
func (p *Pipeline) ConfirmStaged(ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.adoptionLocked(ref)
	if a == nil || !a.Staged || a.Reverted != "" {
		return fmt.Errorf("change: %s is not a staged adoption", ref)
	}
	a.Staged = false
	a.Listed = false // the digest says it is now installed
	return p.saveLocked()
}

// StageFailed reverts a staged image that fell back by boot counting.
func (p *Pipeline) StageFailed(ctx context.Context, ref string) error {
	return p.revert(ctx, ref, OriginPipeline, WhyFallback)
}

// SetAutoAdopt turns the CHG-6 standing grant off (the owner's text is
// enough) or back on (an owner-approved intent).
func (p *Pipeline) SetAutoAdopt(ctx context.Context, on bool) error {
	return p.setPolicy(ctx, "auto_adopt", on)
}

// SetSharing opts in to sharing (an owner-approved intent) or out (CHG-4).
func (p *Pipeline) SetSharing(ctx context.Context, on bool) error {
	return p.setPolicy(ctx, "sharing", on)
}

func (p *Pipeline) setPolicy(ctx context.Context, key string, on bool) error {
	v, action := "off", ActionPolicyOff
	if on {
		v, action = "on", ActionPolicy
	}
	n, err := p.nonce()
	if err != nil {
		return err
	}
	return p.run(ctx, journal.Intent{ID: fmt.Sprintf("chg:policy:%s:%s:%s", n, key, v),
		Origin: OriginOwner, Account: journal.BrokerAccount, Action: action, Executor: Executor})
}

// RemoveCase removes a case from a suite, which only the owner approves
// (CHG-2, LOOP-10).
func (p *Pipeline) RemoveCase(ctx context.Context, caseID string) error {
	n, err := p.nonce()
	if err != nil {
		return err
	}
	return p.run(ctx, journal.Intent{ID: fmt.Sprintf("chg:suite:%s:remove:%s", n, caseID),
		Origin: OriginOwner, Account: journal.BrokerAccount, Action: ActionSuite, Executor: Executor})
}

// nonce returns a fresh sequence number, saved before use so it never
// repeats after a restart.
func (p *Pipeline) nonce() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.st.Seq++
	if err := p.saveLocked(); err != nil {
		p.st.Seq--
		return "", err
	}
	return "n" + strconv.Itoa(p.st.Seq), nil
}

// ErrPending means the intent is waiting for the owner.
var ErrPending = errors.New("change: waiting for the owner")

func (p *Pipeline) run(ctx context.Context, in journal.Intent) error {
	if p.j == nil {
		return errors.New("change: no journal attached")
	}
	st, err := p.j.Submit(in)
	if err != nil {
		return err
	}
	if st.State == journal.Pending {
		if st, err = p.j.Authorize(ctx, in.ID); err != nil {
			return err
		}
	}
	switch st.State {
	case journal.Pending:
		return ErrPending
	case journal.Denied:
		return errors.New("change: refused: " + st.Permission.Reason)
	case journal.Authorized:
		if st, err = p.j.Dispatch(ctx, in.ID); err != nil {
			return err
		}
	}
	if st.State != journal.Succeeded {
		ev := ""
		if n := len(st.Attempts); n > 0 {
			ev = st.Attempts[n-1].Evidence
		}
		return errors.New("change: not applied: " + ev)
	}
	return nil
}

// Recheck re-evaluates active adoptions, newest first, on the current
// held-out and security suites, which grow after adoption. One that now
// regresses against the state without it, or fails a security fixture, is
// reverted (ADP-4: roll back on regression; LOOP-10). It returns the
// reverted IDs.
func (p *Pipeline) Recheck(ctx context.Context) ([]string, error) {
	p.mu.Lock()
	type job struct {
		id        string
		cur, prev Tree
		set       frozen
	}
	var jobs []job
	for i := len(p.st.Adoptions) - 1; i >= 0; i-- {
		a := p.st.Adoptions[i]
		if a.Reverted != "" {
			continue
		}
		prev, _, err := undoTree(p.st.Active, a)
		if err != nil {
			continue
		}
		jobs = append(jobs, job{a.ID, p.st.Active.clone(), prev, p.freezeLocked(a.Classes)})
	}
	p.mu.Unlock()
	var out []string
	for _, jb := range jobs {
		s := p.evaluate(ctx, jb.prev, jb.cur, jb.set)
		why := ""
		switch {
		case s.SecurityPassed < s.Security:
			why = WhySecurity
		case s.Regressions > 0 || s.Passed < s.BaselinePassed:
			why = WhyRegression
		default:
			continue
		}
		if err := p.revert(ctx, jb.id, OriginPipeline, why); err != nil {
			return out, err
		}
		out = append(out, jb.id)
	}
	return out, nil
}
