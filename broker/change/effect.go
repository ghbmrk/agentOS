package change

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Revert reasons, also the last part of a revert intent ID.
const (
	WhyOwner      = "owner"
	WhyRegression = "regression"
	WhySecurity   = "security"
	WhyFallback   = "fallback" // a staged image did not boot cleanly
	// WhyDropped: the update applier dropped a staged image before it
	// was installed (SR3-4f-2b).
	WhyDropped = "dropped"
	// WhySettings: the owner's own configuration replaced the adopted
	// state outside the pipeline (Superseded); never an intent ID.
	WhySettings = "settings"
	// WhyForgotten: the owner forgot a task it was learned from
	// (ForgetGoal, C23); never an intent ID.
	WhyForgotten = "forgotten"
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
	case ActionRevert, ActionRevertAuto:
		if len(parts) != 5 || parts[2] != "revert" {
			return errors.New("change: malformed revert")
		}
		switch {
		case in.Action == ActionRevert && in.Origin == OriginOwner && parts[4] == WhyOwner:
		case in.Action == ActionRevertAuto && in.Origin == OriginPipeline && (parts[4] == WhyRegression || parts[4] == WhySecurity || parts[4] == WhyFallback || parts[4] == WhyDropped):
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
	case ActionRevert, ActionRevertAuto:
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
	p.dropOldBasesLocked(p.st.Active.Hash())
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
	p.dropOldBasesLocked(pr.next.Hash())
	if pr.cand.Source == Upstream {
		// A later release supersedes declined ones in the namespaces it
		// installs.
		kept := p.st.Declined[:0]
		for _, d := range p.st.Declined {
			if !touchesNS(pr.edits, d.NS) {
				kept = append(kept, d)
			}
		}
		p.st.Declined = kept
	}
	p.st.Adoptions = append(p.st.Adoptions, &Adoption{ID: id, Short: short, Source: pr.cand.Source,
		Classes: pr.classes, Basis: basis, Edits: pr.edits, Score: pr.report.Score, Public: pr.cand.Public,
		Staged: staged, Origin: pr.cand.Origin, Goals: pr.cand.Goals, At: p.cfg.Now()})
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
	if p.unsettledLocked(a, why) {
		return unsettledErr(a)
	}
	next, err := p.undoTreeLocked(a)
	if err != nil {
		return err
	}
	if ns := emptiedSlot(a, next); ns != "" {
		return fmt.Errorf("undoing %s would leave %s with nothing to boot; install another version instead", a.Short, ns)
	}
	if err := p.activateLocked(p.st.Active, next, a.Edits); err != nil {
		return err
	}
	p.st.Active = next
	p.dropOldBasesLocked(next.Hash())
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
	id, w := a.ID, p.withdrawer
	withdraw := p.unsettledLocked(a, why)
	if withdraw && w == nil {
		p.mu.Unlock()
		return unsettledErr(a) // no applier to ask: fail closed
	}
	next, err := p.undoTreeLocked(a)
	if err == nil && withdraw {
		// Checked before the applier gives the release up, so a revert
		// that cannot run does not withdraw it.
		if ns := emptiedSlot(a, next); ns != "" {
			err = fmt.Errorf("undoing %s would leave %s with nothing to boot; install another version instead", a.Short, ns)
		}
	}
	v := safe(strings.TrimPrefix(a.Origin, "update:"))
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if withdraw {
		// Never under p.mu: the applier holds its lock while it calls
		// StageFailed and StageDropped (lock order applier, then
		// pipeline).
		if err := w.Withdraw(id, why); handover(err) {
			return installingErr(v)
		} else if err != nil {
			return fmt.Errorf("change: withdrawing update %s: %w", v, err)
		}
		p.mu.Lock()
		if p.withdrawn == nil {
			p.withdrawn = map[string]bool{}
		}
		p.withdrawn[id] = true
		p.mu.Unlock()
	}
	n, err := p.nonce()
	if err != nil {
		return err
	}
	action := ActionRevert
	if origin == OriginPipeline {
		action = ActionRevertAuto // not narrowing: held by STOP like other automation
	}
	err = p.run(ctx, journal.Intent{ID: fmt.Sprintf("chg:%s:revert:%s:%s", id, n, why), Origin: origin,
		Account: journal.BrokerAccount, Action: action, Executor: Executor,
		Params: map[string]any{"adoption": id, "why": why}})
	if err != nil && withdraw && p.revertedByID(id) {
		// The withdrawal is also a drop, and the applier's StageDropped
		// reverted it first: the owner's undo is done (SR3-4f-2 L3-1).
		return nil
	}
	return err
}

// installingErr: the applier refused to withdraw update v while it is
// being installed. Its Handover method lets Recheck tell it apart.
type installingErr string

func (v installingErr) Error() string {
	return "Update " + string(v) + " is being installed; undo it after it starts."
}
func (installingErr) Handover() bool { return true }

// revertedByID: adoption id exists and is reverted.
func (p *Pipeline) revertedByID(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.adoptionByIDLocked(id)
	return a != nil && a.Reverted != ""
}

// Withdrawer is the update applier as the pipeline sees it (SR3-4f-2a).
// Withdraw gives up a staged adoption's release before it is installed,
// durably, and refuses it from then on; it returns nil for an adoption
// the applier does not hold. While the release is being installed, from
// the save before the install until the boot after it settles, it
// returns an error whose Handover method reports true.
type Withdrawer interface {
	Withdraw(adoption, why string) error
}

// ErrNotStaged: StageFailed or StageDropped named an adoption that is not
// staged, confirmed or unknown. It is permanent: the same call is refused
// again (SR3-4f-3c).
var ErrNotStaged error = notStaged{}

type notStaged struct{}

func (notStaged) Error() string   { return "not a staged adoption" }
func (notStaged) Permanent() bool { return true }

// SetWithdrawer sets the update applier the pipeline asks before it
// undoes a staged image. Without one, a staged image is not undone until
// it settles.
func (p *Pipeline) SetWithdrawer(w Withdrawer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.withdrawer = w
}

// handover reports whether a Withdraw error says the release is being
// installed.
func handover(err error) bool {
	var h interface{ Handover() bool }
	return errors.As(err, &h) && h.Handover()
}

// unsettledLocked reports whether a staged image must be withdrawn from
// the update applier before it is undone for why. Until the update code
// settles it, the image may already be installed, and an adoption undone
// under it could never be confirmed, so the applier would wait forever
// (SR3-4). Its own settling (a fallback, a drop) needs no withdraw.
func (p *Pipeline) unsettledLocked(a *Adoption, why string) bool {
	return a.Staged && why != WhyFallback && why != WhyDropped && !p.withdrawn[a.ID]
}

// unsettledErr is the refusal when no applier can withdraw the image.
func unsettledErr(a *Adoption) error {
	return errors.New("Update " + safe(strings.TrimPrefix(a.Origin, "update:")) + " starts at the next restart; undo it after.")
}

// ConfirmStaged records that a staged image booted and passed its health
// check (UPD-1); the update code calls it with the adoption's exact ID,
// since an owner-facing ID can be reused. Confirming it again is a
// success that changes nothing, so the update code can retry until it
// has recorded the answer (SR3-4). A failed save changes nothing either.
func (p *Pipeline) ConfirmStaged(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.adoptionByIDLocked(id)
	switch {
	case a != nil && a.Confirmed:
		return nil
	case a == nil || !a.Staged || a.Reverted != "":
		return fmt.Errorf("change: %s is not a staged adoption", id)
	}
	listed := a.Listed
	a.Staged, a.Confirmed = false, true
	a.Listed = false // the digest says it is now installed
	if err := p.saveLocked(); err != nil {
		a.Staged, a.Confirmed, a.Listed = true, false, listed
		return err
	}
	return nil
}

// StageFailed reverts a staged image that fell back by boot counting, by
// the adoption's exact ID. One already undone, by a fallback or by the
// owner, is a success that changes nothing, so the update code can retry
// (SR3-4); a confirmed image never fell back.
func (p *Pipeline) StageFailed(ctx context.Context, id string) error {
	return p.settleStaged(ctx, id, WhyFallback)
}

// StageDropped reverts a staged image the update applier dropped before
// it was installed: a narrowed policy, a newer release, a release it
// refuses (SR3-4f-2b). Like StageFailed it is idempotent by the exact ID,
// and a confirmed or unknown image is the permanent ErrNotStaged.
func (p *Pipeline) StageDropped(ctx context.Context, id string) error {
	return p.settleStaged(ctx, id, WhyDropped)
}

func (p *Pipeline) settleStaged(ctx context.Context, id, why string) error {
	p.mu.Lock()
	a := p.adoptionByIDLocked(id)
	var err error
	switch {
	case a == nil || a.Confirmed || (!a.Staged && a.Reverted == ""):
		err = fmt.Errorf("change: %s is %w", id, ErrNotStaged)
	case a.Reverted != "":
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if err := p.revert(ctx, id, OriginPipeline, why); err != nil && !p.revertedByID(id) {
		return err
	}
	return nil // reverted, by this call or one that raced it
}

// adoptionByIDLocked finds an adoption by its exact ID only.
func (p *Pipeline) adoptionByIDLocked(id string) *Adoption {
	for _, a := range p.st.Adoptions {
		if a.ID == id {
			return a
		}
	}
	return nil
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
		Origin: OriginOwner, Account: journal.BrokerAccount, Action: action, Executor: Executor,
		Params: map[string]any{"setting": key, "value": v}})
}

// RemoveCase removes a case from a suite, which only the owner approves
// (CHG-2, LOOP-10).
func (p *Pipeline) RemoveCase(ctx context.Context, caseID string) error {
	n, err := p.nonce()
	if err != nil {
		return err
	}
	return p.run(ctx, journal.Intent{ID: fmt.Sprintf("chg:suite:%s:remove:%s", n, caseID),
		Origin: OriginOwner, Account: journal.BrokerAccount, Action: ActionSuite, Executor: Executor,
		Params: map[string]any{"case": caseID}})
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
// regresses against the state without it, or fails a security fixture that
// state passes, is reverted (ADP-4: roll back on regression; LOOP-10).
// Nothing is blamed during an evaluator outage (nothing passes on either
// side). An image the owner approved or an attested security release is
// never auto-reverted: its new regression is put to the owner instead
// (arbitrator R2). It returns the reverted IDs.
func (p *Pipeline) Recheck(ctx context.Context) ([]string, error) {
	p.mu.Lock()
	var ids []string
	for i := len(p.st.Adoptions) - 1; i >= 0; i-- {
		if p.st.Adoptions[i].Reverted == "" {
			ids = append(ids, p.st.Adoptions[i].ID)
		}
	}
	p.mu.Unlock()
	var out []string
	var errs []error
	outage, interrupted := false, false
	defer func() {
		p.mu.Lock()
		if interrupted {
			p.mu.Unlock()
			return
		}
		if outage {
			p.st.Outages++
		} else {
			p.st.Outages, p.st.OutageSeen = 0, false
		}
		_ = p.saveLocked()
		p.mu.Unlock()
	}()
	for _, id := range ids {
		// Read the tree per adoption, so earlier reverts in this pass
		// are seen.
		p.mu.Lock()
		a := p.adoptionLocked(id)
		if a == nil || a.Reverted != "" {
			p.mu.Unlock()
			continue
		}
		prev, _, err := undoTree(p.st.Active, a)
		if err != nil {
			p.mu.Unlock()
			continue
		}
		cur, set := p.st.Active.clone(), p.freezeLocked(a.Classes)
		p.mu.Unlock()

		s, err := p.evaluate(ctx, prev, cur, set, strictFor(a.Source, a.Classes), "")
		if err != nil {
			// Preempted: blame nothing, and leave the outage count as it
			// was. The next pass resumes from the kept pairs.
			interrupted = true
			return out, errors.Join(append(errs, err)...)
		}
		why := ""
		switch {
		case s.outage():
			outage = true
			continue
		case s.SecurityRegressions > 0:
			why = WhySecurity
		case s.Regressions > 0 || s.Passed < s.BaselinePassed:
			why = WhyRegression
		default:
			continue
		}
		p.mu.Lock()
		// a was read before the evaluation; a forget meanwhile replaces
		// the history with copies (C23), so read it again.
		if a = p.adoptionLocked(id); a == nil || a.Reverted != "" {
			p.mu.Unlock()
			continue
		}
		protected := a.protected()
		if protected && a.Concern == "" {
			a.Concern, a.ConcernScore = why, s
			_ = p.saveLocked()
		}
		p.mu.Unlock()
		if protected {
			continue
		}
		// A failed revert is reported and the pass goes on to older
		// adoptions; only STOP ends it.
		if err := p.revert(ctx, id, OriginPipeline, why); err != nil {
			if errors.Is(err, journal.ErrStopped) {
				return out, err
			}
			if why == WhySecurity && handover(err) {
				// The applier is installing it and withdraws it once it
				// can; the next pass reverts it. Until then the digest
				// says so (SR3-4f-3b).
				p.concern(id, why, s)
				continue
			}
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		out = append(out, id)
	}
	return out, errors.Join(errs...)
}

// protected reports an image adoption the owner approved or that rests on
// an attested security release: the pipeline never undoes it on its own.
// concern records why and s on adoption id once, and saves.
func (p *Pipeline) concern(id, why string, s Score) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a := p.adoptionLocked(id); a != nil && a.Reverted == "" && a.Concern == "" {
		a.Concern, a.ConcernScore = why, s
		_ = p.saveLocked()
	}
}

func (a *Adoption) protected() bool {
	image := false
	for _, c := range a.Classes {
		image = image || c == ClassGuestImage || c == ClassHostImage
	}
	return image && (a.Basis == BasisOwner || a.Basis == BasisSecurity)
}

// emptiedSlot names an image slot the tree after undoing a would leave
// empty: the first image a box installed cannot be undone, only replaced.
// Other namespaces may go empty; their targets run with nothing adopted.
func emptiedSlot(a *Adoption, next Tree) string {
	for _, e := range a.Edits {
		ns := namespace(e.Path)
		if c := classOf(e.Path); (c == ClassGuestImage || c == ClassHostImage) && len(next.under(ns)) == 0 {
			return ns
		}
	}
	return ""
}

// undoableLocked reports whether the owner can be offered UNDO for a.
func (p *Pipeline) undoableLocked(a *Adoption) bool {
	next, _, err := undoTree(p.st.Active, a)
	return err != nil || emptiedSlot(a, next) == ""
}

func touchesNS(edits []Edit, ns string) bool {
	for _, e := range edits {
		if namespace(e.Path) == ns {
			return true
		}
	}
	return false
}
