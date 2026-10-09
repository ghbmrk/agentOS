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
	// Goals are the goals of the owner tasks its builder read: the
	// journal intents behind its hypothesis and its dev cases. Loop 1 sets
	// them in broker code; the builder never asserts them. Forgetting one
	// undoes the adoption (ForgetGoal, C23).
	Goals []string
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
	// EvaluatorID names the evaluator's current configuration (image,
	// model route, price ceiling). A preempted evaluation's kept pairs
	// resume only under the same ID (PE1, security R1 on #103). Nil: the
	// evaluator is fixed for the pipeline's life.
	EvaluatorID func() string
	// ResumeFor is how long a preempted evaluation's pairs are kept;
	// zero means the package's ResumeFor. A box whose agent sleeps for
	// learning sets 36 h, so a candidate cut at the end of one night
	// resumes the next (PE7).
	ResumeFor time.Duration
	// Logf logs each counted candidate cut by a fixed class only (PE5).
	// Nil: not logged.
	Logf func(string, ...any)
	Now  func() time.Time
	Rand io.Reader
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
	// NeedsExplicit is set when the candidate would have adopted on its
	// own but passed no explicit owner case: it went to the owner instead
	// (security B1(d) on #90; counted in Loop 1's digest line).
	NeedsExplicit bool `json:"needs_explicit,omitempty"`
	Score
}

// weighed is s's held-out evidence: explicit cases count one, implicit
// ones half, rounded down (potency C3(c) on #90).
func weighed(s Score) int { return s.HeldOut - s.Implicit + s.Implicit/2 }

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
	// Implicit, ImplicitPassed and ImplicitBaselinePassed are the part of
	// HeldOut, Passed and BaselinePassed from implicit acceptances (loops
	// L6): they count half toward MinHeldOut and never alone toward an
	// auto-adoption (security B1(d), potency C3 on #90).
	Implicit               int `json:"implicit,omitempty"`
	ImplicitPassed         int `json:"implicit_passed,omitempty"`
	ImplicitBaselinePassed int `json:"implicit_baseline_passed,omitempty"`
	// EndorsedPassed counts the passed explicit cases whose reference the
	// owner approved (YES) or wrote (an edit): only these anchor an
	// auto-adoption (C17; L3 SHOULD-5 on #109), since not repeating a
	// refused item is a weaker signal.
	EndorsedPassed int `json:"endorsed_passed,omitempty"`
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
	// Goals are the candidate's Goals, IDs only (C23).
	Goals []string `json:"goals,omitempty"`
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
	// Notices are broker notices for the digest, kept once per key
	// (Notice).
	Notices []notice `json:"notices,omitempty"`
	// Cuts counts each (candidate, case) pair's cut candidate-side runs
	// (PE5b), so a restart cannot reset them.
	Cuts map[string]cutCount `json:"cuts,omitempty"`
	// Loop2Passed are the Loop 2 fixtures the active tree has passed, by
	// loop2Key: they must pass from then on (PS1). Losing it fails toward
	// must-not-regress, never toward pass.
	Loop2Passed map[string]bool `json:"loop2_passed,omitempty"`
}

// notice is one broker digest line; Seen once the digest listed it.
type notice struct {
	Key  string `json:"key"`
	Line string `json:"line"`
	Seen bool   `json:"seen,omitempty"`
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

	mu    sync.Mutex
	st    state
	props map[string]*proposal
	// lapsed holds release proposals dropped because the owner's request
	// closed unanswered, until Loop 3 asks (Lapsed). Memory only, like
	// props: a restart drops both, and Loop 3 re-asks after one anyway.
	lapsed map[string]bool
	broken error // set when state could neither be saved nor reloaded
	// probes of running evaluations: use count and task intent.
	probes    map[string]int
	probeTask map[string]string
	// kept holds preempted evaluations' completed pairs (PE1).
	kept      map[string]pairResult
	keptOrder []keptAt // put order, for dropping the oldest
	keptSeq   uint64
	// exempt counts each candidate's exempt interruptions (MaxExempt),
	// in first-seen order for dropping the oldest.
	exempt      map[string]int
	exemptOrder []string
	// parks and parkSeq order parked candidates' idle turns (PE5b).
	parks   map[string]*parkMark
	parkSeq uint64
	// gone holds the goals forgotten since start, so a candidate built
	// from one and still in flight is never adopted (C23). In memory: a
	// restarted Loop 1 builds nothing from a forgotten goal.
	gone map[string]bool
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
	p := &Pipeline{cfg: cfg, props: map[string]*proposal{}, probes: map[string]int{}, probeTask: map[string]string{}, kept: map[string]pairResult{}}
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
// release whose Security() holds (threshold signatures plus an independent
// attestation, checked by update.Verified.WithAttestations; UPD-8) can use
// the security standing policy. Only update.Store.Check makes a
// *update.Verified; nil or a zero value is refused.
func (p *Pipeline) ProposeRelease(ctx context.Context, v *update.Verified) (Report, error) {
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
	if p.goneLocked(c.Goals) {
		p.mu.Unlock()
		return Report{}, ErrForgotten
	}
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
	if !p.parkedMayRunLocked(ctx, p.candidateKey(base, next)) {
		// Parked (PE5): refused before it spends an ID or a save.
		p.mu.Unlock()
		return Report{}, ErrParked
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
	if len(c.Goals) > 0 && slices.ContainsFunc(cl.classes, func(k Class) bool { return !learnedClass[k] }) {
		// The forget cascade undoes only what Loop 1 builds (L3 on #160):
		// an image, setting or authority is never learned from a task.
		rep.State, rep.Reason = StateRejected, "learned from owner tasks, so it may change only skills, procedures and context"
		return rep, nil
	}
	score, err := p.evaluate(ctx, base, next, set, strictFor(c.Source, cl.classes))
	if err != nil {
		// Preempted: not a verdict. The ID is spent; the next proposal
		// of the same candidate resumes from the kept pairs.
		return Report{}, err
	}
	rep.Score = score
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
	enough := weighed(rep.Score) >= p.cfg.MinHeldOut && rep.Security >= p.cfg.MinSecurity && rep.NotEvaluated == 0
	anchored := rep.EndorsedPassed > 0
	switch {
	case c.Source == Local && cl.neutral && auto && enough && anchored:
		rep.Basis = BasisStanding
	case c.Source == Local && cl.neutral && auto && enough:
		rep.Basis, rep.NeedsExplicit = BasisOwner, true
	case c.Source == Upstream && security && images && !regressed && p.cfg.SecurityAutoStage:
		rep.Basis = BasisSecurity
	default:
		// A security release that regresses still goes to the owner with
		// its counts: rejecting it would leave the box on the vulnerable
		// image.
		rep.Basis = BasisOwner
	}

	p.mu.Lock()
	if p.goneLocked(c.Goals) {
		// Forgotten while it was evaluated.
		p.mu.Unlock()
		return Report{}, ErrForgotten
	}
	c.Goals = slices.Clone(c.Goals)
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
// intent closes (C7). why is the request's denial cause: "owner" when the
// owner said NO, "not chosen" when it was left out of a partial YES, and
// anything else ("expired", "void", "restart", or "") when it closed
// without an answer or was approved.
// On the owner's NO the adoption settles as Settle does, so a declined
// security release is recorded. One still pending was never answered (the
// request expired, was voided, or was dropped by a restart), and one denied
// for any other reason (an approval gone stale before dispatch) is not the
// owner's no: both drop the proposal and record nothing, so only the
// owner's NO reads as a decline. A release dropped this way is reported
// once by Lapsed, so the next update check (UPD-5, maintain Loop 3) offers
// it again (C25); one left out of a partial YES is dropped without a
// decline and is not reported, so it is not re-asked. A local change is
// proposed again only if Loop 1 produces it again.
func (p *Pipeline) Decided(ctx context.Context, in journal.Intent, why string) {
	parts := parseID(in.ID)
	if in.Action != ActionAdopt || parts == nil || in.ID != adoptID(parts[1]) || p.prop(parts[1]) == nil {
		return
	}
	st, err := p.j.Get(in.ID)
	switch {
	case err != nil:
	case why == "not chosen" && (st.State == journal.Pending || st.State == journal.Denied):
		p.drop(parts[1])
	case st.State == journal.Pending, st.State == journal.Denied && why != "owner":
		p.lapse(parts[1])
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

// Waiting reports whether proposal id still waits on the owner: it is
// dropped once adopted, declined, refused or lapsed.
func (p *Pipeline) Waiting(id string) bool { return p.prop(id) != nil }

// Lapsed reports, once, whether release proposal id was dropped because
// the owner's request closed without the owner's answer (Decided), so Loop
// 3 offers the release again. It is false for one still waiting, adopted,
// declined or refused, and after it has been reported.
func (p *Pipeline) Lapsed(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	ok := p.lapsed[id]
	delete(p.lapsed, id)
	return ok
}

// lapse drops proposal id unanswered and, for a release, keeps that for
// Lapsed.
func (p *Pipeline) lapse(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pr := p.props[id]; pr != nil && pr.cand.Source == Upstream {
		if p.lapsed == nil {
			p.lapsed = map[string]bool{}
		}
		p.lapsed[id] = true
	}
	delete(p.props, id)
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
//
// If ctx ends part way (preemption), evaluate stops at once and returns
// ErrInterrupted instead of a score; the run in flight is discarded, and
// every side that finished is kept, so the next evaluation of the same
// trees runs only the rest (PE1). A candidate side cut short
// MaxInterruptions times fails. A finished evaluation uses up what was
// kept.
func (p *Pipeline) evaluate(ctx context.Context, base, next Tree, set frozen, st strictness) (Score, error) {
	type run struct {
		c     Case
		cand  bool
		probe string
		ok    bool
		ev    bool
		done  bool
		// struck: failed without running (MaxInterruptions).
		struck bool
		err    bool // the evaluator errored (a fail, unlike a grader's)
	}
	ck := p.candidateKey(base, next)
	p.mu.Lock()
	// The active tree when the evaluation starts: if it moves on before
	// the evaluation is cut, nothing finished is kept (PE7).
	active := p.st.Active.Hash()
	mayRun := p.exempt[ck] < MaxExempt || IsIdle(ctx) // proposeInner took the turn
	p.mu.Unlock()
	if !mayRun {
		return Score{}, ErrParked
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	keys := map[string]string{}
	res := map[string]pairResult{} // kept sides, then this evaluation's
	var runs []*run
	p.mu.Lock()
	for _, cs := range [][]Case{set.heldOut, set.security} {
		for _, c := range cs {
			k := p.resumeKey(base, next, c)
			keys[c.ID] = k
			r, _ := p.keptLocked(k)
			res[c.ID] = r
			if !r.baseDone {
				runs = append(runs, &run{c: c, probe: p.probeID(nonce, c.ID)})
			}
			switch {
			case r.nextDone:
			case p.cutsLocked(k).Counted >= MaxInterruptions:
				// Cut short too often on this case: failed without
				// another run (security F1 on #103).
				runs = append(runs, &run{c: c, cand: true, ev: true, done: true, struck: true})
			default:
				runs = append(runs, &run{c: c, cand: true, probe: p.probeID(nonce, c.ID)})
			}
		}
	}
	p.mu.Unlock()
	mrand.Shuffle(len(runs), func(i, j int) { runs[i], runs[j] = runs[j], runs[i] })
	p.mu.Lock()
	for _, r := range runs {
		if r.struck {
			continue
		}
		p.probes[r.probe]++
		if !r.c.Security {
			p.probeTask[r.probe] = r.c.Task
		}
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		for _, r := range runs {
			if r.struck {
				continue
			}
			if p.probes[r.probe]--; p.probes[r.probe] <= 0 {
				delete(p.probes, r.probe)
				delete(p.probeTask, r.probe)
			}
		}
		p.mu.Unlock()
	}()
	var cut *run      // the run in flight when ctx ended or the evaluator was interrupted
	var stopped error // the evaluator's interruption, if any
	for _, r := range runs {
		if r.struck {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		t := base
		if r.cand {
			t = next
		}
		var err error
		r.ok, r.ev, err = p.pass(ctx, t, r.c, r.probe)
		r.err = err != nil
		if errors.Is(err, ErrInterrupted) {
			// The evaluator was interrupted under this run (admission
			// refused or preempted its machine, PE3): the evaluation
			// stops as if ctx had ended.
			cut, stopped = r, err
			break
		}
		// A run that returns after the preemption may have failed
		// because of it: it is discarded, never counted or kept.
		r.done = ctx.Err() == nil
		if !r.done {
			cut = r
		}
	}
	interrupted := ctx.Err() != nil || stopped != nil
	for _, r := range runs {
		if !r.done {
			continue
		}
		if interrupted && r.err && !r.cand {
			// An erroring baseline (a model outage, a rate limit) is
			// not kept: kept as a fail it could hide a regression for
			// as long as it is kept. It runs again on resume. A
			// candidate's error stays a fail: the candidate may cause
			// it, and must not re-roll by it (security F1 on #103).
			continue
		}
		pr := res[r.c.ID]
		if r.cand {
			pr.NextOK, pr.NextEv, pr.nextDone = r.ok, r.ev, true
		} else {
			pr.BaseOK, pr.BaseEv, pr.baseDone = r.ok, r.ev, true
		}
		res[r.c.ID] = pr
	}
	if interrupted {
		// Only a cut the candidate could have caused counts (PE5): any
		// cause the host did not mark as the owner's, unknown included.
		// Both the evaluator's interruption and the context's cause are
		// read, and either one unmarked makes the cut count; that one is
		// the cause logged.
		var causes []error
		if stopped != nil {
			causes = append(causes, stopped)
		}
		if ctx.Err() != nil {
			causes = append(causes, context.Cause(ctx))
		}
		cause, exempt := causes[0], true
		for _, c := range causes {
			if !errors.Is(c, ErrOwnerPreempt) {
				cause, exempt = c, false
				break
			}
		}
		p.mu.Lock()
		if exempt {
			p.exemptLocked(ck)
		}
		// The candidate side cut short is counted, so a candidate that
		// forces preemptions cannot re-roll a case without limit; an
		// owner's cut is exempt only MaxExemptPerCase times per pair
		// (PE5b). The counts are saved, so a restart does not reset them.
		counted := false
		var saveErr error
		if cut != nil && cut.cand {
			counted = p.cutLocked(keys[cut.c.ID], exempt)
			saveErr = p.saveLocked()
		}
		// Every side that finished is kept, so a result once seen is
		// never run again; none when the active tree moved on meanwhile,
		// since dropOldBasesLocked already ran for that move (PE7).
		for id, pr := range res {
			if (pr.baseDone || pr.nextDone) && active == p.st.Active.Hash() {
				pr.base, pr.cand = base.Hash(), ck
				p.keepLocked(keys[id], pr)
			}
		}
		p.mu.Unlock()
		if p.cfg.Logf != nil {
			if saveErr != nil {
				p.cfg.Logf("change: saving a cut count failed; it holds until restart")
			}
			switch {
			case counted && exempt:
				p.cfg.Logf("change: a candidate run was cut short (%s, past its exempt limit); counted", exemptClass(cause))
			case counted:
				p.cfg.Logf("change: a candidate run was cut short (%s); counted", cutClass(cause, stopped != nil && cause == stopped))
			case exempt:
				p.cfg.Logf("change: a candidate run was cut short (%s); not counted", exemptClass(cause))
			}
		}
		if stopped != nil {
			return Score{}, stopped
		}
		return Score{}, fmt.Errorf("%w: %w", ErrInterrupted, ctx.Err())
	}
	p.mu.Lock()
	for _, k := range keys {
		delete(p.kept, k)    // kept sides are used up
		delete(p.st.Cuts, k) // and so are the cut counts; saved with the verdict
	}
	// Loop 2 fixtures the active tree has never passed (PS1).
	open := map[string]bool{}
	for _, c := range set.security {
		if strings.HasPrefix(c.ID, Loop2Fixture) && !p.st.Loop2Passed[loop2Key(c)] {
			open[c.ID] = true
		}
	}
	p.mu.Unlock()
	// Which side is the active tree: the baseline at proposal, the
	// candidate side in Recheck.
	baseActive, nextActive := base.Hash() == active, next.Hash() == active
	var passed []string
	defer func() {
		if len(passed) == 0 {
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.st.Loop2Passed == nil {
			p.st.Loop2Passed = map[string]bool{}
		}
		for _, id := range passed {
			p.st.Loop2Passed[id] = true
		}
		if err := p.saveLocked(); err != nil && p.cfg.Logf != nil {
			p.cfg.Logf("change: saving a passed Loop 2 fixture failed; it is marked again when next passed")
		}
	}()
	cases := map[string]Case{}
	var order []string
	for _, cs := range [][]Case{set.heldOut, set.security} {
		for _, c := range cs {
			if _, seen := cases[c.ID]; !seen {
				order = append(order, c.ID)
			}
			cases[c.ID] = c
		}
	}
	sort.Strings(order)
	var s Score
	for _, id := range order {
		c, pr := cases[id], res[id]
		if !pr.BaseEv {
			s.NotEvaluated++
			continue
		}
		if !pr.NextEv {
			// The baseline ran but the candidate's tree declined: honoured
			// only where the evaluator legitimately cannot test (C5).
			if c.Security && st.security || !c.Security && st.heldOut {
				pr.NextEv, pr.NextOK = true, false
			} else {
				s.NotEvaluated++
				continue
			}
		}
		if c.Security {
			if open[c.ID] && (pr.BaseOK && baseActive || pr.NextOK && nextActive) {
				// The active tree passes it: must pass from now on.
				passed = append(passed, loop2Key(c))
			}
			switch {
			case open[c.ID] && !pr.BaseOK && !pr.NextOK:
				// An open finding the candidate leaves as it is: no
				// regression, and no pass either (PS1).
				continue
			}
			s.Security++
			if pr.NextOK {
				s.SecurityPassed++
			}
			if pr.BaseOK {
				s.BaselineSecurityPassed++
			}
			if pr.BaseOK && !pr.NextOK {
				s.SecurityRegressions++
			}
			continue
		}
		s.HeldOut++
		if pr.BaseOK {
			s.BaselinePassed++
		}
		if pr.NextOK {
			s.Passed++
		}
		if pr.NextOK && !c.Implicit && (c.Outcome == Accepted || c.Outcome == Corrected) {
			s.EndorsedPassed++
		}
		if c.Implicit {
			s.Implicit++
			if pr.BaseOK {
				s.ImplicitBaselinePassed++
			}
			if pr.NextOK {
				s.ImplicitPassed++
			}
		}
		if pr.BaseOK && !pr.NextOK {
			s.Regressions++
			if s.example == nil && !c.Implicit {
				cc := c
				s.example = &cc
			}
		}
	}
	return s, nil
}

// OutageAlert is how many failed Recheck passes in a row the digest
// reports.
const OutageAlert = 3

// Loop2Fixture prefixes Loop 2's regression fixture IDs (loops S5). Such
// a fixture encodes a finding the active tree has now, so until the active
// tree first passes it, it only must not regress; then it must pass for
// good (loops PS1, C5).
const Loop2Fixture = "loop2/"

// loop2Key keys a Loop 2 fixture's must-pass mark by its ID and contents,
// so a fixture replaced under the same ID starts again as must not regress
// (security L4 on W5a).
func loop2Key(c Case) string {
	h := sha256.New()
	for _, b := range [][]byte{[]byte(c.ID), c.Input, c.Expect} {
		fmt.Fprintf(h, "%d:", len(b))
		h.Write(b)
	}
	return c.ID + "@" + hex.EncodeToString(h.Sum(nil))[:32]
}

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
func (p *Pipeline) pass(ctx context.Context, t Tree, c Case, probe string) (ok, evaluated bool, err error) {
	out, err := p.cfg.Evaluator.Run(ctx, t.clone(), Probe{ID: probe, Input: append([]byte(nil), c.Input...)})
	if errors.Is(err, ErrNotEvaluated) {
		return false, false, nil
	}
	if err != nil {
		return false, true, err
	}
	g := p.cfg.Graders[c.Class]
	if g == nil {
		g = DefaultGrader
	}
	return g(c, out), true, nil
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
