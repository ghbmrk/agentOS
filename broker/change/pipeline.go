package change

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
)

// Source is where a candidate comes from (§11).
type Source string

const (
	Local    Source = "local"    // Loop 1: procedures, skills, routing, context, config
	Upstream Source = "upstream" // new guest or host images
	Shared   Source = "shared"   // packages from other installations (Import)
)

// Candidate is a proposed change to the managed tree. Propose takes only
// local candidates; upstream ones come from ProposeRelease and shared ones
// from Import, which set Source themselves.
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
	// required to share it (CHG-5). Loop 1 sets it in broker code from the
	// REV-5 labels of every input; the builder never asserts it.
	Public bool
}

// Probe is what the evaluator sees of a case: its ID and input. The
// expected output, the owner's outcome, and whether it is a security
// fixture stay in the broker, which grades (CHG-1).
type Probe struct {
	ID    string
	Input []byte
}

// Evaluator runs one probe against a candidate tree inside an agent
// machine, by counterfactual replay against recorded external responses
// (LOOP-5): no live effects, and any unrecorded call fails closed. It
// returns the output the broker's grader judges.
type Evaluator interface {
	Run(ctx context.Context, state Tree, p Probe) ([]byte, error)
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
	// LocalProvider reports a provider that is a local model, so the
	// digest can say when a reorder drops the local fallback. Nil: none.
	LocalProvider func(provider string) bool
	// Receives lists the data sources a machine already receives; a
	// context rule may only select among them (CHG-6). Nil: none.
	Receives func(machine string) []string
	// Private reports content that must never leave the box: vault values,
	// canaries, private corpora (CHG-5). Nil: nothing can be shared.
	Private func([]byte) bool
	// ShortID gives the owner-facing ID for an adoption (CH-12: at most 3
	// characters). The wiring passes the owner channel's allocator so IDs
	// never clash with open requests; taken reports IDs the pipeline still
	// uses. Nil: the pipeline's own letter-and-digits sequence.
	ShortID func(taken func(string) bool) (string, error)
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
	ActionRevert = journal.ActionChangeRevert // authority-narrowing (journal A9)
	ActionPolicy = "meta.change.policy"       // turning a setting on
	ActionSuite  = "meta.change.suite"
	// ActionPolicyOff turns a setting off; authority-narrowing, so it
	// works during STOP (journal A9).
	ActionPolicyOff = journal.ActionChangePolicyOff
	// ActionRevertAuto is the pipeline's own revert (regression, security,
	// fallback). It is not narrowing, so STOP holds it.
	ActionRevertAuto = "meta.change.revert.auto"
)

// ErrNeedsOwner is returned by Check for a change only the owner may
// approve. The broker's policy turns it into an approval request.
// It reports NeedsOwner, which is how the grants gate tells it apart
// without importing this package (ARC-2).
var ErrNeedsOwner error = needsOwner{}

type needsOwner struct{}

func (needsOwner) Error() string    { return "change: needs the owner's approval" }
func (needsOwner) NeedsOwner() bool { return true }

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
	Short   string  `json:"short,omitempty"` // owner-facing, once adopted
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
	// NotEvaluated counts cases the evaluator could not run on this box
	// (ErrNotEvaluated); they are in no other count.
	NotEvaluated int `json:"not_evaluated,omitempty"`
	// Security fixtures on the baseline, so Recheck blames an adoption
	// only for a fixture the state without it passes.
	BaselineSecurityPassed int   `json:"baseline_security_passed"`
	SecurityRegressions    int   `json:"security_regressions"`
	example                *Case // first regressed case, for the owner's line
}

// Adoption is a change that took effect and its rollback point.
type Adoption struct {
	ID      string    `json:"id"`
	Short   string    `json:"short"` // owner-facing (UNDO, MORE)
	Source  Source    `json:"source"`
	Classes []Class   `json:"classes"`
	Basis   string    `json:"basis"`
	Edits   []Edit    `json:"edits"`
	Score   Score     `json:"score"`
	Origin  string    `json:"origin,omitempty"`
	Public  bool      `json:"public,omitempty"`
	At      time.Time `json:"at"`
	// Staged marks an image change written to the inactive slot and not
	// yet confirmed by the update code after boot (UPD-1).
	Staged bool `json:"staged,omitempty"`
	// Reverted names why the adoption was undone ("owner", "regression",
	// "security", "fallback"), empty while it is active.
	Reverted string `json:"reverted,omitempty"`
	// Concern is a regression Recheck found on a protected adoption, which
	// the owner decides (arbitrator R2); ConcernScore its counts.
	Concern      string `json:"concern,omitempty"`
	ConcernScore Score  `json:"concern_score,omitempty"`
	ConcernSeen  bool   `json:"concern_seen,omitempty"`
	Listed       bool   `json:"listed,omitempty"`
	RevertSeen   bool   `json:"revert_seen,omitempty"`
}

// state is everything the pipeline persists.
type state struct {
	Seq       int         `json:"seq"`
	SplitKey  []byte      `json:"split_key"`
	Active    Tree        `json:"active"`
	Adoptions []*Adoption `json:"adoptions"`
	AutoAdopt bool        `json:"auto_adopt"`
	Sharing   bool        `json:"sharing"`
	// Declined lists security releases the owner declined; the digest
	// repeats them until a later release is adopted (arbitrator R2).
	Declined []declined `json:"declined,omitempty"`
	// Outages counts consecutive Recheck passes the evaluator could not
	// run; the digest says so once it reaches OutageAlert.
	Outages    int             `json:"outages,omitempty"`
	OutageSeen bool            `json:"outage_seen,omitempty"`
	Cases      map[string]Case `json:"cases"`
	// Forgotten counts task cases removed because a record they used
	// was deleted (ForgetTasks, CAP-3).
	Forgotten int `json:"forgotten,omitempty"`
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
	cand     Candidate
	base     string // hash of the tree it was evaluated against
	next     Tree
	edits    []Edit
	report   Report
	classes  []Class
	security bool // a verified, attested security release
}

// Pipeline is the one change pipeline (§11). It is safe for concurrent use.
type Pipeline struct {
	cfg Config
	j   Journal
	key []byte // split and probe key, fixed after New

	mu     sync.Mutex
	st     state
	props  map[string]*proposal
	broken error // set when state could neither be saved nor reloaded
	// probes of running evaluations: use count and task intent.
	probes    map[string]int
	probeTask map[string]string
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
	p := &Pipeline{cfg: cfg, props: map[string]*proposal{}, probes: map[string]int{}, probeTask: map[string]string{}}
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &p.st); err != nil {
			return nil, fmt.Errorf("change: corrupt state: %w", err)
		}
		if len(p.st.SplitKey) != 32 {
			return nil, errors.New("change: corrupt state: bad split key")
		}
		for path := range p.st.Active {
			if err := cleanPath(path); err != nil {
				return nil, fmt.Errorf("change: corrupt state: %w", err)
			}
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
	p.key = append([]byte(nil), p.st.SplitKey...)
	return p, nil
}

// healthy refuses new work once the state could not be saved or reloaded:
// the pipeline then fails stop rather than run on state it cannot keep.
func (p *Pipeline) healthy() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.broken
}

// Attach connects the journal. The pipeline must also be registered as the
// journal's executor named Executor, and the broker's policy must delegate
// meta.change intents to Check.
func (p *Pipeline) Attach(j Journal) { p.j = j }

func (p *Pipeline) saveLocked() error {
	if p.broken != nil {
		return p.broken
	}
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
	if c.Source == "" {
		c.Source = Local
	}
	if c.Source != Local {
		return Report{}, errors.New("change: Propose takes local candidates; use ProposeRelease or Import")
	}
	return p.propose(ctx, c, false)
}

// ProposeRelease runs a verified upstream release through the pipeline.
// The candidate is built here from the signed image digests, so what is
// evaluated and staged is exactly what the maintainers signed. Only a
// release that update.Verify marked as security (signature threshold plus
// an independent attestation, UPD-8) can use the security standing policy.
func (p *Pipeline) ProposeRelease(ctx context.Context, v update.Verified) (Report, error) {
	if !v.OK() {
		return Report{}, errors.New("change: release is not verified")
	}
	files := Tree{}
	for path, d := range v.Images() {
		files[path] = []byte(d)
	}
	return p.propose(ctx, Candidate{Source: Upstream, Origin: "update:" + v.Version(), Files: files}, v.Security())
}

// propose runs a candidate and returns its report without held-out
// content: Loop 1 sees counts, never a case.
func (p *Pipeline) propose(ctx context.Context, c Candidate, security bool) (Report, error) {
	rep, err := p.proposeInner(ctx, c, security)
	rep.example = nil
	return rep, err
}

func (p *Pipeline) proposeInner(ctx context.Context, c Candidate, security bool) (Report, error) {
	if p.j == nil {
		return Report{}, errors.New("change: no journal attached")
	}
	if err := p.healthy(); err != nil {
		return Report{}, err
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
	cl := p.classify(edits, base, c.Source)
	set := p.freezeLocked(cl.classes)
	auto := p.st.AutoAdopt
	p.mu.Unlock()

	rep := Report{ID: id, Classes: cl.classes, Neutral: cl.neutral}
	if cl.forbidden != "" {
		rep.State, rep.Reason = StateRejected, cl.forbidden
		return rep, nil
	}
	rep.Score = p.evaluate(ctx, base, next, set, strictFor(c.Source, cl.classes))
	images := cl.imagesOnly()
	regressed := rep.Regressions > 0 || rep.Passed < rep.BaselinePassed
	switch {
	case regressed && !(security && images):
		rep.State, rep.Reason = StateRejected, "regresses on the held-out suite"
		return rep, nil
	case rep.SecurityPassed < rep.Security:
		rep.State, rep.Reason = StateRejected, "fails the security suite"
		return rep, nil
	case rep.Security < p.cfg.MinSecurity && (rep.NotEvaluated == 0 || c.Source != Upstream):
		// Without fixtures nothing shows the evaluator ran at all.
		rep.State, rep.Reason = StateRejected, "too few security fixtures to qualify anything"
		return rep, nil
	case rep.HeldOut > 0 && rep.Passed == 0 && rep.BaselinePassed == 0:
		// Zero passes on both sides reads as "no regression" when the
		// evaluator cannot run (no model access, every case erroring). A
		// candidate passing nothing where the baseline passed is a
		// regression, handled above.
		rep.State, rep.Reason = StateRejected, "passes no held-out case"
		return rep, nil
	}
	// A change the box cannot evaluate is never authority-neutral by
	// evidence: it goes to the owner, marked not tested, or for an attested
	// security release rests on the signatures and attestation (UPD-8).
	enough := rep.HeldOut >= p.cfg.MinHeldOut && rep.Security >= p.cfg.MinSecurity && rep.NotEvaluated == 0
	switch {
	case c.Source == Local && cl.neutral && auto && enough:
		rep.Basis = BasisStanding
	case c.Source == Upstream && security && images && !regressed && p.cfg.SecurityAutoStage:
		rep.Basis = BasisSecurity
	default:
		// A security release that regresses still goes to the owner with
		// its counts: rejecting it would leave the box on the vulnerable
		// image.
		rep.Basis = BasisOwner
	}

	p.mu.Lock()
	p.props[id] = &proposal{cand: c, base: base.Hash(), next: next, edits: edits, report: rep, classes: cl.classes,
		security: security && cl.imagesOnly()}
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
	rep, err := p.drive(ctx, id, pr.report, false)
	rep.example = nil
	return rep, err
}

// Decided is the wiring's call once the owner's request for a change
// intent closes (C7). declined is true only when the owner said NO; then
// the adoption settles as Settle does, so a declined security release is
// recorded. One still pending was never answered (the request expired,
// was voided, or was dropped by a restart), and one denied for any other
// reason (an approval gone stale before dispatch) is not the owner's no:
// both drop the proposal and record nothing, so only the owner's NO reads
// as a decline. Loop 1 proposes again.
func (p *Pipeline) Decided(ctx context.Context, in journal.Intent, declined bool) {
	parts := parseID(in.ID)
	if in.Action != ActionAdopt || parts == nil || in.ID != adoptID(parts[1]) || p.prop(parts[1]) == nil {
		return
	}
	st, err := p.j.Get(in.ID)
	switch {
	case err != nil:
	case st.State == journal.Pending, st.State == journal.Denied && !declined:
		p.drop(parts[1])
	case st.State == journal.Denied || st.State == journal.Succeeded || st.State == journal.NotApplied:
		_, _ = p.Settle(ctx, parts[1])
	}
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
		// Record a decline only when the owner was all that was missing:
		// a stale base or a gate refusal is not the owner's no.
		if pr := p.prop(id); pr != nil && pr.security &&
			errors.Is(p.Check(ctx, journal.PhaseAuthorize, st.Intent), ErrNeedsOwner) {
			p.mu.Lock()
			for _, ns := range nsOf(pr.edits) {
				d := declined{Version: strings.TrimPrefix(pr.cand.Origin, "update:"), NS: ns}
				if !slices.Contains(p.st.Declined, d) {
					p.st.Declined = append(p.st.Declined, d)
				}
			}
			_ = p.saveLocked()
			p.mu.Unlock()
		}
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
		p.mu.Lock()
		if a := p.adoptionLocked(id); a != nil {
			rep.Short = a.Short
		}
		p.mu.Unlock()
		return rep, nil
	}
	rep.State = StateRejected
	if n := len(st.Attempts); n > 0 {
		rep.Reason = st.Attempts[n-1].Evidence
	}
	return rep, nil
}

// declined is a security release the owner declined, per namespace.
type declined struct {
	Version string `json:"version"`
	NS      string `json:"ns"`
}

func nsOf(edits []Edit) []string {
	var out []string
	for _, e := range edits {
		if ns := namespace(e.Path); !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out
}

func (p *Pipeline) prop(id string) *proposal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.props[id]
}

func (p *Pipeline) drop(id string) {
	p.mu.Lock()
	delete(p.props, id)
	p.mu.Unlock()
}

// evaluate runs the frozen suites against the baseline and the candidate.
// Every case, security fixtures included, runs on both sides in a shuffled
// order under probe IDs keyed with a fresh nonce, so the evaluator cannot
// tell sides, kinds, or the same case across evaluations (CHG-1). An
// evaluator error fails the case on that side.
func (p *Pipeline) evaluate(ctx context.Context, base, next Tree, set frozen, st strictness) Score {
	type run struct {
		c     Case
		cand  bool
		probe string
		ok    bool
		ev    bool
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	var runs []*run
	for _, cs := range [][]Case{set.heldOut, set.security} {
		for _, c := range cs {
			runs = append(runs, &run{c: c, probe: p.probeID(nonce, c.ID)}, &run{c: c, cand: true, probe: p.probeID(nonce, c.ID)})
		}
	}
	mrand.Shuffle(len(runs), func(i, j int) { runs[i], runs[j] = runs[j], runs[i] })
	p.mu.Lock()
	for _, r := range runs {
		p.probes[r.probe]++
		if !r.c.Security {
			p.probeTask[r.probe] = r.c.Task
		}
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		for _, r := range runs {
			if p.probes[r.probe]--; p.probes[r.probe] <= 0 {
				delete(p.probes, r.probe)
				delete(p.probeTask, r.probe)
			}
		}
		p.mu.Unlock()
	}()
	for _, r := range runs {
		t := base
		if r.cand {
			t = next
		}
		r.ok, r.ev = p.pass(ctx, t, r.c, r.probe)
	}
	res := map[string][2]*run{}
	var order []string
	for _, r := range runs {
		pair, seen := res[r.c.ID]
		if !seen {
			order = append(order, r.c.ID)
		}
		if r.cand {
			pair[1] = r
		} else {
			pair[0] = r
		}
		res[r.c.ID] = pair
	}
	sort.Strings(order)
	var s Score
	for _, id := range order {
		b, n := res[id][0], res[id][1]
		if !b.ev {
			s.NotEvaluated++
			continue
		}
		if !n.ev {
			// The baseline ran but the candidate's tree declined: honoured
			// only where the evaluator legitimately cannot test (C5).
			if n.c.Security && st.security || !n.c.Security && st.heldOut {
				n.ev, n.ok = true, false
			} else {
				s.NotEvaluated++
				continue
			}
		}
		if n.c.Security {
			s.Security++
			if n.ok {
				s.SecurityPassed++
			}
			if b.ok {
				s.BaselineSecurityPassed++
			}
			if b.ok && !n.ok {
				s.SecurityRegressions++
			}
			continue
		}
		s.HeldOut++
		if b.ok {
			s.BaselinePassed++
		}
		if n.ok {
			s.Passed++
		}
		if b.ok && !n.ok {
			s.Regressions++
			if s.example == nil {
				cc := n.c
				s.example = &cc
			}
		}
	}
	return s
}

// OutageAlert is how many failed Recheck passes in a row the digest
// reports.
const OutageAlert = 3

// strictness says which not-evaluated candidate results count as fails.
type strictness struct{ heldOut, security bool }

// strictFor: only an upstream release may rest on its signatures when the
// box cannot run security fixtures on it, and only images, config, and
// routing (while replay has no model) may go untested on held-out cases. A
// shared package is always tested in full (C5, LOOP-10).
func strictFor(src Source, classes []Class) strictness {
	// No class names nothing the evaluator legitimately cannot test, so
	// strict is the default.
	st := strictness{heldOut: src == Shared || len(classes) == 0, security: src != Upstream}
	for _, c := range classes {
		switch c {
		case ClassGuestImage, ClassHostImage, ClassConfig, ClassRouting:
		default:
			st.heldOut = true
		}
	}
	return st
}

// outage reports a score where nothing passed on either side: the
// evaluator is down, so no adoption can be blamed.
func (s Score) outage() bool {
	return s.HeldOut+s.Security > 0 && s.Passed == 0 && s.BaselinePassed == 0 &&
		s.SecurityPassed == 0 && s.BaselineSecurityPassed == 0
}

// ErrNotEvaluated is what an Evaluator returns (wrapped is fine) when it
// cannot exercise a tree on this box, for example a changed image or
// config that replay does not boot. Such a case is neither a pass nor a
// fail: it is counted as not evaluated.
var ErrNotEvaluated = errors.New("change: not evaluated on this box")

// pass reports whether the case passed on t, and whether it was evaluated
// at all. Any other evaluator error is a fail.
func (p *Pipeline) pass(ctx context.Context, t Tree, c Case, probe string) (ok, evaluated bool) {
	out, err := p.cfg.Evaluator.Run(ctx, t.clone(), Probe{ID: probe, Input: append([]byte(nil), c.Input...)})
	if errors.Is(err, ErrNotEvaluated) {
		return false, false
	}
	if err != nil {
		return false, true
	}
	g := p.cfg.Graders[c.Class]
	if g == nil {
		g = DefaultGrader
	}
	return g(c, out), true
}

// ProbeTask maps a probe ID of a running evaluation back to the journal
// intent of the task case it names, so the replay evaluator can find that
// task's recordings. Security fixtures, finished evaluations, and unknown
// probes give ok=false. That ok=false tells its caller which probes are
// fixtures, so only the trusted replay layer may call it, and nothing it
// returns may reach the tree under test.
func (p *Pipeline) ProbeTask(probeID string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	task, ok := p.probeTask[probeID]
	return task, ok && task != ""
}

// probeID is an opaque name for a case within one evaluation, so the
// evaluator cannot tell a security fixture or a task case by its name, nor
// link a case across evaluations.
func (p *Pipeline) probeID(nonce []byte, caseID string) string {
	m := hmac.New(sha256.New, p.key)
	m.Write(nonce)
	m.Write([]byte("probe:" + caseID))
	return hex.EncodeToString(m.Sum(nil)[:8])
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
