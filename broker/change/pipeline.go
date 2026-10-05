package change

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Source is where a candidate comes from (§11).
type Source string

const (
	Local    Source = "local"    // Loop 1: procedures, skills, routing, context, config
	Upstream Source = "upstream" // new guest or host images
	Shared   Source = "shared"   // packages from other installations (Import)
)

// Candidate is a proposed change to the managed tree.
type Candidate struct {
	Source Source
	// Origin names what produced it, for the journal ("loop1", "router",
	// "update"). It never affects a decision.
	Origin string
	// Files are new or changed files; Delete lists files to remove.
	Files  map[string][]byte
	Delete []string
	// Claim is the candidate's description of itself. No decision reads
	// it, and no owner-facing text carries it (CHG-6).
	Claim string
	// Public marks a candidate built only from public inputs, which is
	// required to share it (CHG-5).
	Public bool
	// Security marks an upstream security fix, set by the update channel
	// from signed release metadata (UPD-8). Refused on any other source.
	Security bool
}

// Evaluator runs one case against a candidate tree inside an agent machine,
// by counterfactual replay against recorded external responses (LOOP-5):
// no live effects, and any unrecorded call fails closed. It returns the
// output the grader judges.
type Evaluator interface {
	Run(ctx context.Context, state Tree, c Case) ([]byte, error)
}

// Grader judges an output against a case. Graders are broker code chosen
// per class in Config, never supplied by a candidate.
type Grader func(c Case, out []byte) bool

// DefaultGrader passes an output equal to what the owner accepted (or the
// owner's correction), and for a rejected outcome any output other than the
// one the owner rejected.
func DefaultGrader(c Case, out []byte) bool {
	if c.Outcome == Rejected {
		return !bytes.Equal(out, c.Expect)
	}
	return bytes.Equal(out, c.Expect)
}

// Target applies one namespace of the tree to the component that uses it,
// such as the model router for routing/.
type Target interface {
	Current() (Tree, error)
	Apply(Tree) error
}

// Journal is the part of the intent engine the pipeline uses; both
// *journal.Engine and a policy gate that wraps it satisfy it.
type Journal interface {
	Submit(journal.Intent) (journal.Status, error)
	Authorize(ctx context.Context, id string) (journal.Status, error)
	Dispatch(ctx context.Context, id string) (journal.Status, error)
	Get(id string) (journal.Status, error)
}

// Config configures New.
type Config struct {
	Store     Store
	Evaluator Evaluator
	// Targets are keyed by namespace ("routing"). Namespaces without a
	// target are held by the pipeline and read with Files.
	Targets map[string]Target
	// Initial seeds the tree on first start, beside the targets' current
	// state.
	Initial Tree
	Graders map[Class]Grader
	// OwnerSource is the quality-verdict source that marks the owner's own
	// outcome (OP-7). Default "owner".
	OwnerSource string
	// DevPercent is the share of cases a candidate's builder may see.
	// Default 30.
	DevPercent int
	// MinHeldOut is the fewest relevant held-out cases an auto-adoption
	// needs; MinSecurity the fewest security fixtures. Defaults 5 and 1.
	MinHeldOut  int
	MinSecurity int
	// SecurityAutoStage is the standing policy that lets an upstream
	// security fix adopt without a prompt (CHG-3).
	SecurityAutoStage bool
	// RouteGranted reports whether the owner granted a provider; a routing
	// candidate naming one that is not granted fails (ADP-4, CAP-9).
	RouteGranted func(provider string) bool
	// Receives lists the data sources a machine already receives; a
	// context rule may only select among them (CHG-6). Nil: none.
	Receives func(machine string) []string
	// Private reports content that must never leave the box: vault values,
	// canaries, private corpora (CHG-5). Nil: nothing can be shared.
	Private func([]byte) bool
	Now     func() time.Time
	Rand    io.Reader
}

// Bases: why an adoption may run.
const (
	BasisStanding = "CHG-6" // default standing grant, authority-neutral
	BasisSecurity = "CHG-3" // standing policy for upstream security fixes
	BasisOwner    = ""      // the owner approves this change
)

// Journal vocabulary. Decisions are read from the intent ID and grant
// reference, which the journal never redacts; params are for audit.
const (
	Executor       = "change"
	OriginPipeline = "change"
	OriginOwner    = "owner"

	ActionAdopt  = "meta.change.adopt"
	ActionRevert = "meta.change.revert"
	ActionPolicy = "meta.change.policy"
	ActionSuite  = "meta.change.suite"
)

// ErrNeedsOwner is returned by Check for a change only the owner may
// approve. The broker's policy turns it into an approval request.
var ErrNeedsOwner = errors.New("change: needs the owner's approval")

// State is where a proposal ended up.
type State string

const (
	StateRejected      State = "rejected"
	StateAwaitingOwner State = "awaiting_owner"
	StateAdopted       State = "adopted"
)

// Report is the result of a proposal.
type Report struct {
	ID      string  `json:"id"`
	State   State   `json:"state"`
	Classes []Class `json:"classes"`
	Neutral bool    `json:"neutral"`
	Basis   string  `json:"basis"`
	Reason  string  `json:"reason,omitempty"`
	Score
}

// Score is the evaluation evidence: counts only, no case content.
type Score struct {
	HeldOut        int `json:"held_out"`
	Passed         int `json:"passed"`
	BaselinePassed int `json:"baseline_passed"`
	Regressions    int `json:"regressions"`
	Security       int `json:"security"`
	SecurityPassed int `json:"security_passed"`
}

// Adoption is a change that took effect and its rollback point.
type Adoption struct {
	ID      string    `json:"id"`
	Source  Source    `json:"source"`
	Classes []Class   `json:"classes"`
	Basis   string    `json:"basis"`
	Edits   []Edit    `json:"edits"`
	Score   Score     `json:"score"`
	Public  bool      `json:"public,omitempty"`
	At      time.Time `json:"at"`
	// Reverted names why the adoption was undone ("owner", "regression"),
	// empty while it is active.
	Reverted   string `json:"reverted,omitempty"`
	Listed     bool   `json:"listed,omitempty"`
	RevertSeen bool   `json:"revert_seen,omitempty"`
}

// state is everything the pipeline persists.
type state struct {
	Seq       int             `json:"seq"`
	SplitKey  []byte          `json:"split_key"`
	Active    Tree            `json:"active"`
	Adoptions []*Adoption     `json:"adoptions"`
	AutoAdopt bool            `json:"auto_adopt"`
	Sharing   bool            `json:"sharing"`
	Cases     map[string]Case `json:"cases"`
	// Applied lists intents whose effect took place, for Reconcile.
	Applied map[string]bool `json:"applied"`
}

func (s *state) copyCases() map[string]Case {
	out := make(map[string]Case, len(s.Cases)+1)
	for k, v := range s.Cases {
		out[k] = v
	}
	return out
}

// proposal is a qualified candidate waiting for its adoption intent.
type proposal struct {
	cand    Candidate
	base    string // hash of the tree it was evaluated against
	next    Tree
	edits   []Edit
	report  Report
	classes []Class
}

// Pipeline is the one change pipeline (§11). It is safe for concurrent use.
type Pipeline struct {
	cfg Config
	j   Journal

	mu    sync.Mutex
	st    state
	props map[string]*proposal
}

// New loads the persisted state, or seeds it on first start, and applies
// the active tree to every target so they match what was last adopted.
func New(cfg Config) (*Pipeline, error) {
	if cfg.Store == nil || cfg.Evaluator == nil {
		return nil, errors.New("change: Store and Evaluator are required")
	}
	if cfg.OwnerSource == "" {
		cfg.OwnerSource = "owner"
	}
	if cfg.DevPercent <= 0 || cfg.DevPercent >= 100 {
		cfg.DevPercent = 30
	}
	if cfg.MinHeldOut <= 0 {
		cfg.MinHeldOut = 5
	}
	if cfg.MinSecurity <= 0 {
		cfg.MinSecurity = 1
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	p := &Pipeline{cfg: cfg, props: map[string]*proposal{}}
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &p.st); err != nil {
			return nil, fmt.Errorf("change: corrupt state: %w", err)
		}
		for ns, t := range cfg.Targets {
			if err := t.Apply(p.st.Active.under(ns)); err != nil {
				return nil, fmt.Errorf("change: restoring %s: %w", ns, err)
			}
		}
	} else {
		p.st = state{Active: Tree{}, AutoAdopt: true, Cases: map[string]Case{}, Applied: map[string]bool{}}
		p.st.SplitKey = make([]byte, 32)
		if _, err := io.ReadFull(cfg.Rand, p.st.SplitKey); err != nil {
			return nil, err
		}
		for path, b := range cfg.Initial {
			if err := cleanPath(path); err != nil {
				return nil, err
			}
			p.st.Active[path] = append([]byte(nil), b...)
		}
		for ns, t := range cfg.Targets {
			cur, err := t.Current()
			if err != nil {
				return nil, err
			}
			for path, b := range cur {
				if namespace(path) != ns {
					return nil, fmt.Errorf("change: target %s reports %s", ns, path)
				}
				p.st.Active[path] = b
			}
		}
		if err := p.saveLocked(); err != nil {
			return nil, err
		}
	}
	if p.st.Cases == nil {
		p.st.Cases = map[string]Case{}
	}
	if p.st.Applied == nil {
		p.st.Applied = map[string]bool{}
	}
	return p, nil
}

// Attach connects the journal. The pipeline must also be registered as the
// journal's executor named Executor, and the broker's policy must delegate
// meta.change intents to Check.
func (p *Pipeline) Attach(j Journal) { p.j = j }

func (p *Pipeline) saveLocked() error {
	b, err := json.Marshal(p.st)
	if err != nil {
		return err
	}
	return p.cfg.Store.Save(b)
}

// Files returns the active files in a namespace.
func (p *Pipeline) Files(ns string) Tree {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st.Active.under(ns)
}

// AutoAdopt reports whether the CHG-6 standing grant is on.
func (p *Pipeline) AutoAdopt() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st.AutoAdopt
}

// Adoptions returns every adoption, oldest first.
func (p *Pipeline) Adoptions() []Adoption {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Adoption, len(p.st.Adoptions))
	for i, a := range p.st.Adoptions {
		out[i] = *a
	}
	return out
}

// Propose evaluates a candidate on the frozen held-out and security suites
// and, if it qualifies, submits its adoption intent: candidate → build →
// evaluate → adoption intent → activate with fallback → rollback point.
func (p *Pipeline) Propose(ctx context.Context, c Candidate) (Report, error) {
	if p.j == nil {
		return Report{}, errors.New("change: no journal attached")
	}
	switch c.Source {
	case Local, Upstream, Shared:
	default:
		return Report{}, fmt.Errorf("change: unknown source %q", c.Source)
	}
	if c.Security && c.Source != Upstream {
		return Report{}, errors.New("change: only an upstream release can be a security fix")
	}
	for path := range c.Files {
		if err := cleanPath(path); err != nil {
			return Report{}, err
		}
	}
	for _, path := range c.Delete {
		if err := cleanPath(path); err != nil {
			return Report{}, err
		}
	}

	p.mu.Lock()
	base := p.st.Active.clone()
	next := base.clone()
	for _, path := range c.Delete {
		delete(next, path)
	}
	for path, b := range c.Files {
		next[path] = append([]byte{}, b...)
	}
	edits := diff(base, next)
	if len(edits) == 0 {
		p.mu.Unlock()
		return Report{}, errors.New("change: candidate changes nothing")
	}
	p.st.Seq++
	id := "c" + strconv.Itoa(p.st.Seq)
	if err := p.saveLocked(); err != nil {
		p.mu.Unlock()
		return Report{}, err
	}
	cl := p.classify(edits, c.Source)
	set := p.freezeLocked(cl.classes)
	auto := p.st.AutoAdopt
	p.mu.Unlock()

	rep := Report{ID: id, Classes: cl.classes, Neutral: cl.neutral}
	if cl.forbidden != "" {
		rep.State, rep.Reason = StateRejected, cl.forbidden
		return rep, nil
	}
	rep.Score = p.evaluate(ctx, base, next, set)
	switch {
	case rep.Regressions > 0 || rep.Passed < rep.BaselinePassed:
		rep.State, rep.Reason = StateRejected, "regresses on the held-out suite"
		return rep, nil
	case rep.SecurityPassed < rep.Security:
		rep.State, rep.Reason = StateRejected, "fails the security suite"
		return rep, nil
	}
	enough := rep.HeldOut >= p.cfg.MinHeldOut && rep.Security >= p.cfg.MinSecurity
	switch {
	case c.Source == Local && cl.neutral && auto && enough:
		rep.Basis = BasisStanding
	case c.Source == Upstream && c.Security && p.cfg.SecurityAutoStage && rep.Security >= p.cfg.MinSecurity:
		rep.Basis = BasisSecurity
	default:
		rep.Basis = BasisOwner
	}

	p.mu.Lock()
	p.props[id] = &proposal{cand: c, base: base.Hash(), next: next, edits: edits, report: rep, classes: cl.classes}
	p.mu.Unlock()

	in := journal.Intent{
		ID: adoptID(id), Origin: OriginPipeline, Account: journal.BrokerAccount,
		Action: ActionAdopt, GrantRef: rep.Basis, Executor: Executor,
		Params: map[string]any{"from": base.Hash(), "to": next.Hash(), "classes": joinClasses(cl.classes),
			"source": string(c.Source), "held_out": rep.HeldOut, "passed": rep.Passed},
	}
	if _, err := p.j.Submit(in); err != nil {
		p.drop(id)
		return rep, err
	}
	return p.drive(ctx, id, rep, true)
}

// Settle continues a proposal that waited for the owner: once its intent is
// authorized it is dispatched.
func (p *Pipeline) Settle(ctx context.Context, id string) (Report, error) {
	p.mu.Lock()
	pr := p.props[id]
	p.mu.Unlock()
	if pr == nil {
		return Report{}, fmt.Errorf("change: no open proposal %s", id)
	}
	return p.drive(ctx, id, pr.report, false)
}

func (p *Pipeline) drive(ctx context.Context, id string, rep Report, authorize bool) (Report, error) {
	st, err := p.j.Get(adoptID(id))
	if err != nil {
		return rep, err
	}
	if authorize && st.State == journal.Pending {
		if st, err = p.j.Authorize(ctx, adoptID(id)); err != nil {
			return rep, err
		}
	}
	switch st.State {
	case journal.Pending:
		rep.State = StateAwaitingOwner
		return rep, nil
	case journal.Denied:
		rep.State, rep.Reason = StateRejected, st.Permission.Reason
		p.drop(id)
		return rep, nil
	case journal.Authorized:
		st, err = p.j.Dispatch(ctx, adoptID(id))
		if err != nil {
			rep.State, rep.Reason = StateRejected, err.Error()
			p.drop(id)
			return rep, nil
		}
	}
	p.drop(id)
	if st.State == journal.Succeeded {
		rep.State = StateAdopted
		return rep, nil
	}
	rep.State = StateRejected
	if n := len(st.Attempts); n > 0 {
		rep.Reason = st.Attempts[n-1].Evidence
	}
	return rep, nil
}

func (p *Pipeline) drop(id string) {
	p.mu.Lock()
	delete(p.props, id)
	p.mu.Unlock()
}

// evaluate runs the frozen suites against the baseline and the candidate.
// An evaluator error fails the case on that side.
func (p *Pipeline) evaluate(ctx context.Context, base, next Tree, set frozen) Score {
	var s Score
	for _, c := range set.heldOut {
		s.HeldOut++
		b := p.pass(ctx, base, c)
		n := p.pass(ctx, next, c)
		if b {
			s.BaselinePassed++
		}
		if n {
			s.Passed++
		}
		if b && !n {
			s.Regressions++
		}
	}
	for _, c := range set.security {
		s.Security++
		if p.pass(ctx, next, c) {
			s.SecurityPassed++
		}
	}
	return s
}

func (p *Pipeline) pass(ctx context.Context, t Tree, c Case) bool {
	out, err := p.cfg.Evaluator.Run(ctx, t.clone(), c)
	if err != nil {
		return false
	}
	g := p.cfg.Graders[c.Class]
	if g == nil {
		g = DefaultGrader
	}
	return g(c, out)
}

func adoptID(id string) string { return "chg:" + id + ":adopt" }

func joinClasses(cs []Class) string {
	ss := make([]string, len(cs))
	for i, c := range cs {
		ss[i] = string(c)
	}
	return strings.Join(ss, ",")
}

// parseID splits a change intent ID "chg:<a>:<b>[:<rest>]".
func parseID(id string) []string {
	parts := strings.SplitN(id, ":", 5)
	if len(parts) < 3 || parts[0] != "chg" {
		return nil
	}
	return parts
}

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
		if in.Origin != OriginOwner && in.Origin != OriginPipeline {
			return errors.New("change: only the owner or the pipeline reverts")
		}
		a := p.adoptionLocked(parts[1])
		if a == nil || a.Reverted != "" {
			return errors.New("change: no active adoption " + parts[1])
		}
		return nil
	case ActionPolicy:
		if in.Origin != OriginOwner || len(parts) != 5 {
			return errors.New("change: only the owner changes adoption policy")
		}
		if parts[3] != "auto_adopt" && parts[3] != "sharing" {
			return errors.New("change: unknown policy setting")
		}
		switch parts[4] {
		case "off":
			return nil // narrowing needs only the owner's text
		case "on":
			return ErrNeedsOwner // widening is an owner-approved intent (CHG-2)
		}
		return errors.New("change: policy value is on or off")
	case ActionSuite:
		if in.Origin != OriginOwner || len(parts) != 5 || parts[3] != "remove" {
			return errors.New("change: only the owner changes a suite")
		}
		if _, ok := p.st.Cases[parts[4]]; !ok {
			return errors.New("change: no such case")
		}
		return ErrNeedsOwner
	}
	return errors.New("change: unknown change action")
}

func (p *Pipeline) adoptionLocked(id string) *Adoption {
	for _, a := range p.st.Adoptions {
		if a.ID == id {
			return a
		}
	}
	return nil
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
	if p.st.Applied[in.ID] {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "already applied"}
	}
	var err error
	switch in.Action {
	case ActionAdopt:
		err = p.adoptLocked(parts[1], in.GrantRef)
	case ActionRevert:
		why := "owner"
		if in.Origin == OriginPipeline {
			why = "regression"
		}
		err = p.revertLocked(parts[1], why)
	case ActionPolicy:
		on := parts[4] == "on"
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
		// The in-memory state moved but is not durable; reload what is.
		p.reloadLocked()
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

func (p *Pipeline) reloadLocked() {
	raw, err := p.cfg.Store.Load()
	if err != nil || raw == nil {
		return
	}
	var st state
	if json.Unmarshal(raw, &st) == nil {
		p.st = st
		p.applyAllLocked(p.st.Active)
	}
}

func (p *Pipeline) applyAllLocked(t Tree) {
	for ns, tg := range p.cfg.Targets {
		_ = tg.Apply(t.under(ns))
	}
}

func (p *Pipeline) adoptLocked(id, basis string) error {
	pr := p.props[id]
	if pr == nil {
		return errors.New("no qualified candidate")
	}
	if pr.base != p.st.Active.Hash() {
		return errors.New("the active state changed since evaluation")
	}
	if err := p.activateLocked(p.st.Active, pr.next, pr.edits); err != nil {
		return err
	}
	p.st.Active = pr.next
	p.st.Adoptions = append(p.st.Adoptions, &Adoption{ID: id, Source: pr.cand.Source, Classes: pr.classes,
		Basis: basis, Edits: pr.edits, Score: pr.report.Score, Public: pr.cand.Public, At: p.cfg.Now()})
	return nil
}

// activateLocked applies next to every target whose namespace an edit
// touches. If one fails, the targets already changed get prev back:
// activate with fallback.
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

// undoTree returns the active tree with one adoption's edits undone, or an
// error if any path it changed has changed again since.
func undoTree(cur Tree, a *Adoption) (Tree, error) {
	next := cur.clone()
	for _, e := range a.Edits {
		now, present := cur[e.Path]
		if present != (e.After != nil) || !bytes.Equal(now, e.After) {
			return nil, fmt.Errorf("%s changed since %s; undo the later change first", e.Path, a.ID)
		}
		if e.Before == nil {
			delete(next, e.Path)
		} else {
			next[e.Path] = append([]byte{}, e.Before...)
		}
	}
	return next, nil
}

func (p *Pipeline) revertLocked(id, why string) error {
	a := p.adoptionLocked(id)
	if a == nil || a.Reverted != "" {
		return errors.New("no active adoption " + id)
	}
	next, err := undoTree(p.st.Active, a)
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

// Revert undoes an adoption: the owner's one-word reply (UNDO <id>), or
// the pipeline itself on a regression.
func (p *Pipeline) Revert(ctx context.Context, id, origin string) error {
	p.mu.Lock()
	a := p.adoptionLocked(id)
	active := a != nil && a.Reverted == ""
	p.mu.Unlock()
	if !active {
		return fmt.Errorf("change: %s is not an active adoption", id)
	}
	return p.run(ctx, journal.Intent{ID: "chg:" + id + ":revert", Origin: origin,
		Account: journal.BrokerAccount, Action: ActionRevert, Executor: Executor})
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
	v := "off"
	if on {
		v = "on"
	}
	return p.run(ctx, journal.Intent{ID: fmt.Sprintf("chg:policy:%s:%s:%s", p.nonce(), key, v),
		Origin: OriginOwner, Account: journal.BrokerAccount, Action: ActionPolicy, Executor: Executor})
}

// RemoveCase removes a case from a suite, which only the owner approves
// (CHG-2, LOOP-10).
func (p *Pipeline) RemoveCase(ctx context.Context, caseID string) error {
	return p.run(ctx, journal.Intent{ID: fmt.Sprintf("chg:suite:%s:remove:%s", p.nonce(), caseID),
		Origin: OriginOwner, Account: journal.BrokerAccount, Action: ActionSuite, Executor: Executor})
}

func (p *Pipeline) nonce() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.st.Seq++
	_ = p.saveLocked()
	return "n" + strconv.Itoa(p.st.Seq)
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
// held-out suite, which grows with owner outcomes after adoption. One that
// now regresses against the state without it is reverted (ADP-4: roll back
// on regression). It returns the reverted IDs.
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
		prev, err := undoTree(p.st.Active, a)
		if err != nil {
			continue
		}
		jobs = append(jobs, job{a.ID, p.st.Active.clone(), prev, p.freezeLocked(a.Classes)})
	}
	p.mu.Unlock()
	var out []string
	for _, jb := range jobs {
		s := p.evaluate(ctx, jb.prev, jb.cur, jb.set)
		if s.Regressions == 0 && s.Passed >= s.BaselinePassed {
			continue
		}
		if err := p.Revert(ctx, jb.id, OriginPipeline); err != nil {
			return out, err
		}
		out = append(out, jb.id)
	}
	return out, nil
}

// Digest returns one fixed-template line per adoption or revert not yet
// listed, and marks them listed. No line carries a candidate's own text.
func (p *Pipeline) Digest() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, a := range p.st.Adoptions {
		if !a.Listed {
			how := "with your approval"
			switch a.Basis {
			case BasisStanding:
				how = "without asking (authority-neutral)"
			case BasisSecurity:
				how = "as a security update"
			}
			ev := "no held-out cases yet"
			if a.Score.HeldOut > 0 {
				ev = fmt.Sprintf("held-out %d/%d, no regression", a.Score.Passed, a.Score.HeldOut)
			}
			line := fmt.Sprintf("Adopted %s change %s %s; %s.", joinClasses(a.Classes), a.ID, how, ev)
			if a.Reverted == "" {
				line += " UNDO " + a.ID
			}
			out = append(out, line)
			a.Listed = true
		}
		if a.Reverted != "" && !a.RevertSeen {
			why := "by your reply"
			if a.Reverted == "regression" {
				why = "after it regressed on new cases"
			}
			out = append(out, fmt.Sprintf("Reverted %s %s.", a.ID, why))
			a.RevertSeen = true
		}
	}
	if len(out) > 0 {
		_ = p.saveLocked()
	}
	return out
}
