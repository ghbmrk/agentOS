package grants

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/reversible"
	"github.com/ghbmrk/agentos/broker/verb"
)

// Defaults.
const (
	// DefaultFresh bounds how long an owner approval stays good for the
	// recheck before dispatch (OP-3). An intent held longer (by STOP, say)
	// is refused and must be asked again.
	DefaultFresh = time.Hour
	// DefaultTick is how often Run checks the batch and releases
	// auto-replies whose undo window has passed.
	DefaultTick = 10 * time.Second
	// DefaultCoalesce caps how long the first item of a batch waits, and
	// DefaultCoalesceIdle is the quiet gap after the last item that ends a
	// batch early (CH-10 batching, CH-15 pacing).
	DefaultCoalesce     = 3 * time.Minute
	DefaultCoalesceIdle = 30 * time.Second
	// DefaultRequestsPerHour is CH-15's default unsolicited-text rate,
	// applied to approval requests.
	DefaultRequestsPerHour = 3
	// activeFor: an owner who texted within this long gets requests at
	// once.
	activeFor = 5 * time.Minute
	// MaxBatch is the owner channel's limit on items per request.
	MaxBatch = 20
	// window is the period scope bounds count over (ADP-9: a daily rate).
	window = 24 * time.Hour
)

// Owner is the owner channel (owner.Channel) as the gate uses it.
type Owner interface {
	Request(items []owner.Item, ttl time.Duration) (string, error)
	RequestEach(items []owner.Item, ttls []time.Duration) ([]string, error)
	// RequestLocalEach asks items on the local page, one request each,
	// when their recipients cannot be shown in a text
	// (owner.SMSApprovable; P2-2a), their notices texted together.
	RequestLocalEach(items []owner.Item, ttls []time.Duration) ([]string, error)
	Tier(owner.Facts) owner.Tier
	Active(within time.Duration) bool
	QueueAutoReply(owner.AutoReply) (owner.QueueResult, error)
	DueAutoReplies() []owner.Queued
	// UndoneAfterRelease reports whether the owner texted UNDO for a
	// released auto-reply after its release (owner O18).
	UndoneAfterRelease(id string) bool
	Inform(text string) error
}

// Changes is the change pipeline (change.Pipeline) as the gate uses it:
// the policy for meta.change.* intents (change C8). The gate does not
// import the pipeline: its dependencies are outside the control path
// (ARC-2).
type Changes interface {
	// Check returns nil to allow, change.ErrNeedsOwner itself (an error
	// whose NeedsOwner() is true, not wrapped or joined) to ask the owner,
	// and any other error to deny.
	Check(ctx context.Context, phase journal.Phase, in journal.Intent) error
	// Line is the approval item for an intent Check sends to the owner:
	// verb, object, detail, how to reverse it, and its kind. The gate sets
	// Ref, keeps it free of recipients and amounts, and treats any kind
	// but Ordinary as GrantChange (high tier). Verb "install" marks the
	// adoption of a release, which also needs the local page (CH-3).
	Line(in journal.Intent) (owner.Item, error)
	// Decided is called once the owner's request for a change intent has
	// closed, answered or not (change C7); declined is true only when the
	// owner said NO.
	Decided(ctx context.Context, in journal.Intent, declined bool)
}

// Loops is the loop scheduler (loops.Scheduler) as the gate uses it: the
// policy for meta.loops.* intents, the owner's spare-time settings
// (LOOP-0, loops L2). Like Changes, it is an interface so the gate does
// not import the scheduler (ARC-2).
type Loops interface {
	// Check returns nil to allow, the scheduler's ErrNeedsOwner itself
	// (NeedsOwner() true, not wrapped or joined) to ask the owner, and
	// any other error to deny.
	Check(ctx context.Context, phase journal.Phase, in journal.Intent) error
	// Line is the approval item for an intent Check sends to the owner
	// (raising the spare budget), rendered from broker state.
	Line(in journal.Intent) (owner.Item, error)
}

// loopsAction reports a loop setting action.
func loopsAction(action string) bool { return strings.HasPrefix(action, "meta.loops.") }

// changeAction reports a change pipeline action.
func changeAction(action string) bool { return strings.HasPrefix(action, "meta.change.") }

// Verifier reads, from the source system, the fields of one intent that
// the owner judges and pre-allowances test (CH-10, ADP-9). An account's
// adapter supplies it. The agent's claims never fill these fields.
type Verifier interface {
	Verify(ctx context.Context, in journal.Intent) (Verified, error)
}

// Escalator is implemented by verifiers whose adapter guards a
// reversible verb (ADP-2's organize guards): it reads the source and says
// whether this one effect must be treated more strictly. It runs at
// authorization and again at the recheck before dispatch (OP-3).
type Escalator interface {
	Escalate(ctx context.Context, in journal.Intent) (Escalation, error)
}

// Escalation is what an Escalator decided. The zero value changes
// nothing. An error denies the effect: a target the adapter never allows.
type Escalation struct {
	// Verb, if set, applies when stricter than the granted verb (an
	// archive that hides a security alert is change-account).
	Verb string
	// Ask sends the effect to the owner at its verb, reversible or not
	// (past a daily bound).
	Ask bool
	// Reason is why the effect is asked, in the adapter's fixed wording
	// built only from broker-held fields (never a message's subject or
	// body). It becomes the approval line's Detail.
	Reason string
	// Held refuses the effect for now, with a reason that says it may be
	// tried again (past a daily bound while the owner has not allowed
	// more).
	Held bool
}

// Verified is what a Verifier read.
type Verified struct {
	// Item is the approval line as the source shows it: object, canonical
	// recipient, amount, undo window, and the CH-10 facts. The gate sets
	// Ref, Facts.Verb (from the grant), and Facts.Kind.
	Item owner.Item
	// Recipients are the canonical recipients the source record names.
	Recipients []string
	// Record identifies the source record the intent acts on.
	Record string
	// Edited is when the record last changed; zero if the source cannot
	// say, which fails any hold.
	Edited time.Time
	// ADP-11: the thread was started by the owner or by a contact that
	// meets CH-10's existence rule, and the reply carries attachments.
	ThreadVerified bool
	Attachments    bool
}

// Config configures New.
type Config struct {
	// Declared maps each adapter executor registered with the engine to
	// the operations it declares and each one's verb (ADP-2), as the
	// adapter's own declaration (e.g. egress.Adapter) states them. A grant
	// may name only these executors and choose only among these
	// operations, at the declared verb or a stricter one.
	Declared map[string]map[string]string
	// Verifiers read source fields, by account. An account without one
	// gets unverified approval items, which are always high risk, and no
	// pre-allowance can match on it.
	Verifiers map[string]Verifier
	// LocalUI says a local confirmation page exists (P2-2). New or wider
	// grants need it (CH-3); without it they are refused outright rather
	// than asking the owner for a code that could not complete them.
	LocalUI bool
	// Isolated reports whether machine is a reply-composer machine built
	// as ADP-11 requires (fresh, thread messages only, no recall, no
	// egress). It is keyed by machine, not lineage, so a fork of a
	// composer is not one. Nil: none is, so reply rules never match.
	Isolated func(machine string) bool
	// Contained reports an agent lineage that still holds a record the
	// owner deleted (recalltool W10); its intents get no pre-allowance.
	// Nil: none is.
	Contained func(lineage string) bool
	// Forms maps an executor's irreversible operations to their
	// reversible forms (REV-3), from the adapter's own declaration next to
	// Declared. An effect the owner approves under one is held for its
	// undo window, staged first if the form says so, and cancelled (and
	// unstaged) by UNDO. A form reversible.Check refuses is dropped and
	// logged, so its operation is asked with no undo window.
	Forms map[string]map[string]reversible.Form
	// Changes decides meta.change.* intents. Nil: they are denied.
	Changes Changes
	// Loops decides meta.loops.* intents. Nil: they are denied.
	Loops Loops
	// Outcome receives the owner's verdict on an agent's effect once it is
	// final, for Loop 1's harvesting (W3, potency PW3 on #90). It is
	// called once per asked intent, outside the gate's lock, on the
	// settling goroutine, so it must not block; a panic in it is logged
	// and changes nothing. Nil: none.
	Outcome func(OwnerOutcome)
	// Observe is shown each guest intent the policy authorized, as the
	// guest wrote it, before the journal redacts it: the learning plane
	// keeps the values compiled skills need (W3-values). It gets a deep
	// copy, after the check passed, never for broker-state intents; it
	// must not block, and a panic in it is logged and changes nothing
	// (security V1 on W3-values). Nil: none.
	Observe func(journal.Intent)
	// ForgetItem gives the approval line for the owner's forget of a
	// task (W3-forget): the task as the owner may see it and what the
	// forget undoes, by goal ID, so the journal never holds the task's
	// text. ok false: no such task, and the forget is denied. Nil: every
	// forget is denied.
	ForgetItem func(goal string) (object, detail string, ok bool)
	// ForgetAgentItem gives the line for item 2 of a forget request
	// (W3-forget-b2b), by item 2's ID: the agent's work since the task,
	// taken back; its detail is from the intent's "actions" param
	// (ForgetAgentActions), fixed when asked, not this one. By ID, not
	// goal, so the line stands after item 1 forgot the task. ok false:
	// nothing to take back, and item 2 is denied. Nil: every item 2 is
	// denied.
	ForgetAgentItem func(id string) (object, detail string, ok bool)
	// Unpaused is told the ID of a grant whose pause the owner ended by
	// resuming or revoking it, so Loop 2 stops listing it as paused (loops
	// S4, W5a). Called outside the gate's lock, never on replay; it must
	// not block, and a panic in it is logged. Nil: none.
	Unpaused func(grantID string)
	// Delivery names, per adapter executor, the one declared share
	// operation that delivers to the owner's evidence destination (CH-20;
	// mail.OpDeliver). Only OriginEvidence submits it, and it runs
	// without asking only to that destination; from any other origin it
	// is denied. Destination reports whether addr may be the destination,
	// as one of a connected account's own addresses, and names that
	// account. Nil: no destination can be set.
	Delivery    map[string]string
	Destination func(addr string) (account string, ok bool)
	// Coalesce, CoalesceIdle, and RequestsPerHour pace approval requests
	// (CH-15); zero takes the defaults. Urgent marks owner-defined urgent
	// items, sent at once and in quiet hours. Quiet reports the owner's
	// quiet hours: non-urgent requests wait for them to end.
	Coalesce        time.Duration
	CoalesceIdle    time.Duration
	RequestsPerHour int
	Urgent          func(owner.Item) bool
	Quiet           func(time.Time) bool
	Fresh           time.Duration
	Now             func() time.Time
	Logf            func(format string, args ...any)
}

// Gate is the approval policy. It is the engine's journal.Policy, the
// executor of grant intents, the guest plane's Effects, and the owner
// channel's Decide and Narrow hooks.
type Gate struct {
	cfg Config

	mu     sync.Mutex
	eng    *journal.Engine
	own    Owner
	grants map[string]*Grant
	// evidence is the owner's evidence destination, if set (CH-20).
	evidence destination
	waiting  map[string]*wait
	batch    []string
	first    time.Time // when the batch's first item arrived
	last     time.Time // when its latest item arrived
	sent     []time.Time
	// asked are owner-question texts reserved on the same budget
	// (Reserve, W9).
	asked []time.Time
	// agedAt is when a question last went ahead of a waiting batch
	// (Reserve, question PQ5).
	agedAt    time.Time
	decided   map[string]decision
	reported  map[string]bool // intents whose owner verdict went to Outcome
	reportedQ []string        // their order, to bound reported
	confirmed map[string]bool
	failed    map[string]string
	// carried holds the intents a restart left pending until the owner
	// channel's Boot hands back what it can re-issue (Reissue); reissue
	// is what waits for STOP to end before it is asked again.
	carried map[string]bool
	reissue []owner.Carried
	// forms are Config.Forms that passed reversible.Check. derived holds
	// the stage and inverse intents this gate submitted, the only ones
	// with reversible.Origin it allows; staging closes when a held
	// effect's stage attempt has ended.
	forms   map[string]map[string]reversible.Form
	derived map[string]bool
	staging map[string]chan struct{}
	// retry explains a pending intent whose hold ended without the
	// owner's answer (PV1): the agent's retry asks again.
	retry map[string]string
	// after holds released effects that STOP kept from running, whose
	// staged copy is settled once they end.
	after map[string]afterRef
	// sending holds owner acceptances of effects that were authorized
	// but not yet sent; each is reported once its send ends (L3 MUST-1
	// on #101), never for a failed send or a changed draft.
	sending map[string]pending
	// implicit holds implicit acceptances of sent auto-replies until
	// LateRelease after the send, reported only if the owner did not
	// text UNDO meanwhile (L3 MUST-4 on #109).
	implicit []heldImplicit
	wg       sync.WaitGroup
}

// pending is an owner verdict not yet reported, and the request it
// answered (an auto-reply's UNDO ID).
type pending struct {
	v   OwnerVerdict
	req string
}

// heldImplicit is an implicit acceptance waiting out the late-UNDO grace.
type heldImplicit struct {
	in  journal.Intent
	req string
	due time.Time
}

// wait is an intent waiting on the owner.
type wait struct {
	item    owner.Item
	local   bool   // also needs local confirmation
	onlyUI  bool   // waits for the local page (a hold); never texted
	request string // owner request ID, "" while batched
	reply   string // queued auto-reply ID
	sendAt  time.Time
	held    bool      // approved, and held under reply until sendAt (REV-3)
	attempt int       // which hold of the intent this is, from 1
	expires time.Time // a re-issued item's original expiry; zero otherwise
}

// afterRef names the hold of a released effect still to end.
type afterRef struct {
	hold string
	n    int
}

// decision is the owner's answer on one intent.
type decision struct {
	approved bool
	why      string
	// asked is set when the decision answered a waiting request, and
	// implicit when it released an auto-reply the owner never answered.
	asked, implicit bool
	// late is set when it released an auto-reply whose silence is not the
	// owner's (owner Queued.Late): no verdict (security B1(a) on PW3).
	late bool
	// req is the request the decision answered (an auto-reply's ID).
	req   string
	at    time.Time
	item  owner.Item
	local bool
	// hold is the UNDO ID a held effect was under, and attempt which hold
	// of the intent it was (REV-3).
	hold    string
	attempt int
	// tries is how many attempts the intent had when the owner answered.
	// The approval covers the next one only: the journal's dispatch
	// record uses it up (GR8, Security on #76).
	tries int
}

// New returns a gate that denies everything until Attach.
func New(cfg Config) *Gate {
	if cfg.Fresh <= 0 {
		cfg.Fresh = DefaultFresh
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Coalesce <= 0 {
		cfg.Coalesce = DefaultCoalesce
	}
	if cfg.CoalesceIdle <= 0 {
		cfg.CoalesceIdle = DefaultCoalesceIdle
	}
	if cfg.RequestsPerHour <= 0 {
		cfg.RequestsPerHour = DefaultRequestsPerHour
	}
	return &Gate{cfg: cfg, grants: map[string]*Grant{},
		waiting: map[string]*wait{}, decided: map[string]decision{}, confirmed: map[string]bool{}, failed: map[string]string{},
		carried: map[string]bool{}, forms: checkForms(cfg), derived: map[string]bool{}, staging: map[string]chan struct{}{},
		retry: map[string]string{}, after: map[string]afterRef{}, sending: map[string]pending{}, reported: map[string]bool{}}
}

// checkForms keeps the forms reversible.Check accepts against each
// executor's declaration.
func checkForms(cfg Config) map[string]map[string]reversible.Form {
	out := map[string]map[string]reversible.Form{}
	for _, ex := range slices.Sorted(maps.Keys(cfg.Forms)) {
		for _, op := range slices.Sorted(maps.Keys(cfg.Forms[ex])) {
			f, err := reversible.Check(cfg.Declared[ex], op, cfg.Forms[ex][op])
			if err != nil {
				cfg.Logf("grants: dropping the reversible form of %s %s: %v", ex, op, err)
				continue
			}
			if out[ex] == nil {
				out[ex] = map[string]reversible.Form{}
			}
			out[ex][op] = f
		}
	}
	return out
}

// Attach connects the engine and the owner channel (nil if there is
// none) and rebuilds grants from the journal. Every intent a restart left
// pending is held until the owner channel's Boot calls Reissue, so none is
// asked twice or under a new expiry before then. Without an owner channel
// nothing is held: nothing can be approved, and a retry asks again. Call
// it after journal.Open and before anything submits.
func (g *Gate) Attach(eng *journal.Engine, own Owner) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.eng, g.own = eng, own
	g.grants = map[string]*Grant{}
	for _, r := range eng.Trail() {
		if r.Type != journal.RecObserved || r.Result != journal.ResultSucceeded {
			continue
		}
		if st, err := eng.Get(r.ID); err == nil && st.Intent.Executor == ExecutorName {
			if _, err := g.applyLocked(st.Intent); err != nil {
				g.cfg.Logf("grants: replaying %s: %v", r.ID, err)
			}
		}
	}
	if own == nil {
		return
	}
	for _, st := range eng.List() {
		if st.State == journal.Pending {
			g.carried[st.Intent.ID] = true
		}
	}
}

// Reissue takes what a restart left open (owner.Config Reissue; GR10).
// Items of requests that were open and unexpired are asked again, each
// with its own new code and its original expiry, once the OP-3 recheck
// shows nothing changed; any other intent left pending was never shown to
// the owner and is asked as new. Boot has already denied what it closed.
// Nothing is re-issued while STOP holds; Tick resumes it.
func (g *Gate) Reissue(cs []owner.Carried) {
	g.mu.Lock()
	for _, c := range cs {
		if g.carried[c.Ref] {
			g.reissue = append(g.reissue, c)
			delete(g.carried, c.Ref)
		}
	}
	rest := make([]string, 0, len(g.carried))
	for id := range g.carried {
		rest = append(rest, id)
	}
	sort.Strings(rest)
	for _, id := range rest {
		g.reissue = append(g.reissue, owner.Carried{Ref: id})
	}
	g.carried = map[string]bool{}
	g.mu.Unlock()
	g.reissueDue()
}

// reissueDue asks again what Reissue took, unless STOP holds.
func (g *Gate) reissueDue() {
	g.mu.Lock()
	eng := g.eng
	if len(g.reissue) == 0 || eng == nil || eng.Stopped() {
		g.mu.Unlock()
		return
	}
	cs := g.reissue
	g.reissue = nil
	g.mu.Unlock()
	ctx := context.Background()
	now := g.cfg.Now()
	for _, c := range cs {
		st, err := eng.Get(c.Ref)
		g.mu.Lock()
		_, decided := g.decided[c.Ref]
		g.mu.Unlock()
		if err != nil || st.State != journal.Pending || decided {
			continue
		}
		if c.Sum == "" {
			// Never shown to the owner: an ordinary ask.
			if _, err := g.Authorize(ctx, c.Ref); err != nil {
				g.cfg.Logf("grants: asking %s after restart: %v", c.Ref, err)
			}
			continue
		}
		if !now.Before(c.Expires) {
			g.closeIntent(c.Ref, "the approval request expired; ask again with a new request_id")
			continue
		}
		v := g.evaluate(ctx, journal.PhaseAuthorize, st.Intent)
		if v.kind != ask || owner.ItemSum(v.item) != c.Sum {
			// OP-3 at re-issue: what the owner was asked no longer
			// holds, so it is not re-sent.
			g.closeIntent(c.Ref, "the details changed while the box restarted; ask again with a new request_id")
			continue
		}
		it := v.item
		it.Asked = c.Asked
		g.mu.Lock()
		if g.waiting[c.Ref] == nil {
			g.waiting[c.Ref] = &wait{item: it, local: v.local, expires: c.Expires}
			if len(g.batch) == 0 {
				g.first = now
			}
			g.last = now
			g.batch = append(g.batch, c.Ref)
		}
		g.mu.Unlock()
	}
}

// RecipientsNotTextable is the reason an action is refused when its
// recipients cannot be shown in an approval text (owner.SMSApprovable).
const RecipientsNotTextable = "can't be approved by text: each recipient must be a plain email address, a full +country number or acct ...1234, at most 100 characters in all; ask again with a new request_id"

// WaitingOnThePage is the reason an agent sees while an action waits for
// the owner on the Wi-Fi page; it says how to ask by text instead
// (Potency R1 on P2-2a).
const WaitingOnThePage = "waiting for the owner's approval on the box's Wi-Fi page; to ask by text instead, each recipient must be a plain email address, a full +country number or acct ...1234, at most 100 characters in all, in a new request_id"

// onPage reports whether a waiting intent is asked on the local page:
// its recipients cannot be texted, or it needs the owner's confirmation
// there (CH-3), which the page's one answer gives (Security Q1 on P2-2a
// part 2).
func (g *Gate) onPage(w *wait) bool {
	return g.cfg.LocalUI && (w.local || !owner.SMSApprovable(w.item))
}

// closeIntent denies a pending intent with a fixed reason.
func (g *Gate) closeIntent(id, why string) {
	g.mu.Lock()
	delete(g.waiting, id)
	g.decided[id] = decision{why: why, at: g.cfg.Now()}
	eng := g.eng
	g.mu.Unlock()
	if _, err := eng.Authorize(context.Background(), id); err != nil {
		g.cfg.Logf("grants: closing %s: %v", id, err)
	}
	g.mu.Lock()
	delete(g.decided, id)
	g.mu.Unlock()
}

// Route names the executor for a guest's effects on account: the live
// adapter grant's. False: no grant. The broker account never routes, so
// no guest reaches broker-state actions (OP-5).
func (g *Gate) Route(account string) (string, bool) {
	if account == journal.BrokerAccount {
		return "", false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if ag := g.adapterLocked(account); ag != nil {
		return ag.Spec.Executor, true
	}
	return "", false
}

// Grants lists the live grants, by ID.
func (g *Gate) Grants() []Grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Grant, 0, len(g.grants))
	for _, gr := range g.grants {
		out = append(out, *gr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// adapterLocked is the live (unpaused) adapter grant for account.
func (g *Gate) adapterLocked(account string) *Grant {
	for _, gr := range g.grants {
		if !gr.Paused && gr.Spec.Rule == nil && gr.Spec.Account == account {
			return gr
		}
	}
	return nil
}

type kind int

const (
	deny kind = iota
	allow
	ask
	autoReply
)

// verdict is what an intent needs now.
type verdict struct {
	kind  kind
	why   string
	item  owner.Item
	local bool
	hold  bool // waits for the local page without texting the owner
	reply *owner.AutoReply
}

// evaluate decides what in needs. Only structural faults deny: no grant,
// an undeclared operation, a malformed grant, or narrowing from anyone
// but the owner. Every irreversible effect that no pre-allowance covers
// is asked of the owner (REV-2).
func (g *Gate) evaluate(ctx context.Context, phase journal.Phase, in journal.Intent) verdict {
	if in.Origin == reversible.Origin {
		return g.evaluateDerived(in)
	}
	if strings.HasPrefix(in.ID, reversible.Prefix) {
		return verdict{kind: deny, why: "only the broker submits this intent"}
	}
	return g.evaluateEffect(ctx, phase, in)
}

// evaluateEffect is evaluate for an intent that is not derived.
func (g *Gate) evaluateEffect(ctx context.Context, phase journal.Phase, in journal.Intent) verdict {
	if in.Account == journal.BrokerAccount {
		return g.evaluateBroker(ctx, phase, in)
	}
	if op, ok := g.cfg.Delivery[in.Executor]; (ok && in.Action == op) || in.Origin == OriginEvidence {
		return g.evaluateDelivery(in)
	}
	// Reasons are fixed wording: a guest reads them back through
	// effect_status, so they never echo what a guest wrote (REV-5).
	g.mu.Lock()
	ag := g.adapterLocked(in.Account)
	var rules []Grant
	if ag != nil {
		for _, gr := range g.grants {
			if !gr.Paused && gr.Spec.Rule != nil && gr.Spec.Account == in.Account && gr.Spec.Rule.Action == in.Action {
				rules = append(rules, *gr)
			}
		}
	}
	var spec Spec
	if ag != nil {
		spec = ag.Spec
	}
	g.mu.Unlock()
	if ag == nil {
		return verdict{kind: deny, why: "no grant connects this account"}
	}
	if in.Executor != spec.Executor {
		return verdict{kind: deny, why: "the executor is not the one the grant connects"}
	}
	v, ok := spec.Ops[in.Action]
	dv, declared := g.cfg.Declared[spec.Executor][in.Action]
	if !ok || !declared {
		return verdict{kind: deny, why: "this operation is not granted for the account (ADP-1)"}
	}
	v = stricter(v, dv)
	cls, ok := verb.ClassOf(v)
	if !ok {
		return verdict{kind: deny, why: "this operation's verb is not on the broker's list (ADP-2)"}
	}
	var esc Escalation
	if e, ok := g.cfg.Verifiers[in.Account].(Escalator); ok {
		var err error
		if esc, err = e.Escalate(ctx, in); err != nil {
			g.cfg.Logf("grants: guarding %s: %v", in.ID, err)
			return verdict{kind: deny, why: "the adapter's guard refuses this effect (ADP-2)"}
		}
		if esc.Held {
			return verdict{kind: deny, why: "held: past the account's daily bound until the owner allows more; try again later (ADP-2)"}
		}
		if esc.Verb != "" {
			// Only a strictly higher class replaces the granted verb, so
			// an escalation can never relabel an effect sideways.
			ec, ok := verb.ClassOf(esc.Verb)
			if !ok {
				return verdict{kind: deny, why: "this operation's verb is not on the broker's list (ADP-2)"}
			}
			if ec > cls {
				v, cls = esc.Verb, ec
			}
		}
	} else if v == verb.Organize {
		// Organize is reversible only behind its adapter's guards
		// (ADP-2): without them, every effect is asked.
		esc = Escalation{Ask: true, Reason: "no guard for this account"}
	}
	if cls == verb.Reversible && !esc.Ask {
		return verdict{kind: allow}
	}
	var ver Verified
	verified := false
	if vf := g.cfg.Verifiers[in.Account]; vf != nil {
		var err error
		if ver, err = vf.Verify(ctx, in); err == nil {
			verified = true
		} else {
			g.cfg.Logf("grants: verifying %s: %v", in.ID, err)
		}
	}
	item := approvalItem(in, v, cls, ver, verified)
	// The undo window is the broker's to promise, from the declared form,
	// never the verifier's (REV-3).
	item.UndoWindow = 0
	if f, ok := g.forms[in.Executor][in.Action]; ok && cls == verb.Irreversible {
		item.UndoWindow = f.Window
	}
	if esc.Reason != "" {
		item.Detail = esc.Reason
	}
	if cls == verb.Irreversible && verified && !g.contained(in.Origin) {
		sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
		for _, r := range rules {
			if g.matches(*r.Spec.Rule, in, ver) != nil {
				continue
			}
			if r.Spec.Rule.Reply {
				body, _ := in.Params[ParamBody].(string)
				return verdict{kind: autoReply, item: item, reply: &owner.AutoReply{
					Ref: in.ID, Recipients: append([]string(nil), ver.Recipients...), Body: body, Facts: item.Facts}}
			}
			return verdict{kind: allow}
		}
	}
	return verdict{kind: ask, item: item}
}

// contained reports a guest lineage that still holds a record the owner
// deleted (recalltool W10): no pre-allowance acts for it, so each of its
// irreversible effects is asked.
func (g *Gate) contained(origin string) bool {
	l, ok := strings.CutPrefix(origin, "guest:")
	return ok && g.cfg.Contained != nil && g.cfg.Contained(l)
}

// approvalItem is the line the owner approves (CH-12): source fields when
// verified, otherwise the intent's own operation and recipients, which are
// what will run, marked unverified and high risk (CH-10).
func approvalItem(in journal.Intent, v string, cls verb.Class, ver Verified, verified bool) owner.Item {
	it := owner.Item{Object: in.Action + " on " + in.Account, Recipient: strings.Join(in.Recipients, ", "), Unverified: true}
	if verified {
		it = ver.Item
		it.Unverified = false
	}
	it.Ref = in.ID
	it.Facts.Verb = v
	it.Facts.Kind = owner.Ordinary
	if cls == verb.Secret {
		it.Facts.Kind = owner.SecretReveal
	}
	if !verified {
		it.Facts = owner.Facts{Verb: v, Kind: it.Facts.Kind}
	}
	return it
}

// matches tests one pre-allowance (ADP-9) and returns why it fails.
func (g *Gate) matches(r Rule, in journal.Intent, v Verified) error {
	want := len(r.Params) + 1
	if r.Reply {
		want++
	}
	if len(in.Params) != want {
		return errors.New("params are not the rule's template")
	}
	for k, x := range r.Params {
		if s, ok := in.Params[k].(string); !ok || s != x {
			return errors.New("params are not the rule's template")
		}
	}
	rec, _ := in.Params[ParamRecord].(string)
	if rec == "" || rec != v.Record {
		return errors.New("record is not the verified record")
	}
	if !sameSet(in.Recipients, v.Recipients) {
		return errors.New("recipients are not the ones the source names")
	}
	if len(r.Recipients) > 0 {
		for _, x := range v.Recipients {
			if !contains(r.Recipients, x) {
				return errors.New("recipient outside the rule")
			}
		}
	}
	f := v.Item.Facts
	if f.HasAmount && (r.AmountCap == 0 || f.Amount < 0 || f.Amount > r.AmountCap) {
		return errors.New("amount outside the rule")
	}
	now := g.cfg.Now()
	if r.HoldDays > 0 && (v.Edited.IsZero() || now.Sub(v.Edited) < time.Duration(r.HoldDays)*window) {
		return errors.New("record edited within the hold")
	}
	if r.Reply {
		body, _ := in.Params[ParamBody].(string)
		if g.cfg.Isolated == nil || in.Machine == "" || !g.cfg.Isolated(in.Machine) || !v.ThreadVerified || v.Attachments || f.HasAmount || strings.TrimSpace(body) == "" {
			return errors.New("not a context-scoped reply (ADP-11)")
		}
	}
	day, perRec := 0, 0
	for _, x := range g.eng.AuthorizedSince(in.Account, in.Action, now.Add(-window)) {
		if x.ID == in.ID {
			continue
		}
		day++
		if s, _ := x.Params[ParamRecord].(string); s == rec {
			perRec++
		}
	}
	if day >= r.PerDay || perRec >= r.PerRecord {
		return errors.New("scope bound reached")
	}
	return nil
}

// evaluateDerived decides a stage or inverse intent (REV-3). It is
// allowed only if this gate submitted it for an effect whose form names
// its operation, and only while the grant that connects the account is
// live: a stage while its hold is on, an inverse once the effect was
// cancelled, not sent, or is no longer under that stage's hold. Neither
// needs a grant of its own: the owner approved the effect they belong to,
// and the form's operations are reversible (reversible.Check).
func (g *Gate) evaluateDerived(in journal.Intent) verdict {
	parent, n, ok := reversible.Parent(in)
	g.mu.Lock()
	ours := g.derived[in.ID]
	w := g.waiting[parent]
	live := w != nil && w.held && w.attempt == n // this stage's hold is on
	ag := g.adapterLocked(in.Account)
	g.mu.Unlock()
	if !ok || !ours {
		return verdict{kind: deny, why: "only the broker submits this intent"}
	}
	p, err := g.eng.Get(parent)
	if err != nil {
		return verdict{kind: deny, why: "the effect it belongs to is not in the journal"}
	}
	f, ok := g.forms[p.Intent.Executor][p.Intent.Action]
	if !ok || in.Account != p.Intent.Account || in.Executor != p.Intent.Executor {
		return verdict{kind: deny, why: "the effect it belongs to has no reversible form"}
	}
	if ag == nil || ag.Spec.Executor != in.Executor {
		return verdict{kind: deny, why: "no grant connects this account"}
	}
	switch {
	case in.ID == reversible.StageID(parent, n) && in.Action == f.Stage && live:
	case in.ID == reversible.InverseID(parent, n) && in.Action == f.Inverse &&
		(p.State == journal.Denied || p.State == journal.NotApplied || (p.State == journal.Pending && !live)):
	default:
		return verdict{kind: deny, why: "the effect it belongs to is not in a state that allows it"}
	}
	return verdict{kind: allow}
}

// evaluateBroker decides broker-state intents (OP-5).
func (g *Gate) evaluateBroker(ctx context.Context, phase journal.Phase, in journal.Intent) verdict {
	if strings.HasPrefix(in.Origin, "guest:") {
		return verdict{kind: deny, why: "broker actions are not available to agents"}
	}
	if changeAction(in.Action) {
		return g.evaluateChange(ctx, phase, in)
	}
	if loopsAction(in.Action) {
		return g.evaluateLoops(ctx, phase, in)
	}
	switch in.Action {
	case journal.ActionGrantChange:
		s, err := parseSpec(in)
		if err != nil {
			return verdict{kind: deny, why: err.Error()}
		}
		if !g.cfg.LocalUI {
			return verdict{kind: deny, why: "a new or wider grant needs confirmation on the box's local page, which this build does not have yet (CH-3)"}
		}
		g.mu.Lock()
		err = g.validateLocked(s)
		g.mu.Unlock()
		if err != nil {
			return verdict{kind: deny, why: err.Error()}
		}
		return verdict{kind: ask, local: true, item: owner.Item{Ref: in.ID, Object: short(s),
			Facts: owner.Facts{Kind: owner.GrantChange, Verb: "grant", NoRecipient: true}}}
	case journal.ActionRecallRollback:
		// Recall's deletion reach asks before taking back agent work
		// (recalltool W10). Only the broker submits it; its line is the
		// broker's own text.
		obj, _ := in.Params["object"].(string)
		detail, _ := in.Params["detail"].(string)
		if in.Origin != OriginRecall || in.Executor != RecallExecutor || obj == "" {
			return verdict{kind: deny, why: "a recall rollback comes only from the broker's recall"}
		}
		return verdict{kind: ask, item: owner.Item{Ref: in.ID, Object: obj, Detail: detail,
			Facts: owner.Facts{Kind: owner.Ordinary, Verb: "forget", NoRecipient: true}}}
	case journal.ActionLearnForget:
		// The owner's forget of a task (W3-forget): only the broker
		// submits it, on the owner's FORGET; the line is the box's own,
		// from the goal, and the owner's YES with the request's code is
		// what runs it (security C1).
		// Item 2 of the same request, the agent's work since the task
		// taken back (W3-forget-b2b), is asked the same way with its own
		// line from ForgetAgentItem.
		goal, key, lookup, agent := ForgetGoal(in.ID), ForgetGoal(in.ID), g.cfg.ForgetItem, false
		if goal == "" {
			goal, key, lookup, agent = ForgetAgentGoal(in.ID), in.ID, g.cfg.ForgetAgentItem, true
		}
		if in.Origin != OriginForget || in.Executor != ForgetExecutor || goal == "" {
			return verdict{kind: deny, why: "a forget comes only from the owner's FORGET"}
		}
		if lookup == nil {
			return verdict{kind: deny, why: "forgetting is not available"}
		}
		obj, detail, ok := lookup(key)
		if !ok || obj == "" {
			return verdict{kind: deny, why: "no such task"}
		}
		if agent {
			// The work so far, fixed when asked, so a re-issue asks what
			// was asked (OP-3; #327 L3 B-1).
			detail = ForgetAgentActions(in.Params)
		}
		return verdict{kind: ask, item: owner.Item{Ref: in.ID, Object: obj, Detail: detail,
			Facts: owner.Facts{Kind: owner.Ordinary, Verb: "forget", NoRecipient: true}}}
	case journal.ActionEvidence:
		return g.evaluateEvidence(in)
	case journal.ActionUpdateFollow:
		return g.evaluateFollow(in)
	case journal.ActionGrantPause, journal.ActionGrantRevoke:
		// Loop 2 may pause on a finding (loops K-S2): pausing only
		// narrows, and revoking stays the owner's.
		loop2Pause := in.Origin == OriginLoop2 && in.Action == journal.ActionGrantPause
		if in.Origin != OriginOwner && !loop2Pause {
			return verdict{kind: deny, why: "only the owner pauses or revokes a grant"}
		}
		g.mu.Lock()
		gr := g.grants[in.GrantRef]
		g.mu.Unlock()
		if gr == nil {
			return verdict{kind: deny, why: "no such grant"}
		}
		return verdict{kind: allow}
	}
	return verdict{kind: deny, why: "this broker action is not handled here"}
}

// evaluateEvidence decides a change to the evidence destination (CH-20).
// It is the owner's alone. Setting it chooses where private content goes,
// so it is high risk (CH-10) and, like a grant, needs the code and the
// local page: a SIM swapper holding the phone cannot move it. Clearing it
// needs neither.
func (g *Gate) evaluateEvidence(in journal.Intent) verdict {
	if in.Origin != OriginOwner && in.Origin != originLocal {
		return verdict{kind: deny, why: "only the owner sets where private replies go"}
	}
	d, err := parseDestination(in)
	if err != nil {
		return verdict{kind: deny, why: err.Error()}
	}
	if d.Address == "" {
		// Clearing needs no code (security C3 on #148): the broker tells
		// the old destination, so the owner sees it if it wasn't them.
		return verdict{kind: allow}
	}
	if !g.cfg.LocalUI {
		return verdict{kind: deny, why: "changing where private replies go needs confirmation on the box's local page, which this build does not have yet (CH-20)"}
	}
	if g.cfg.Destination == nil {
		return verdict{kind: deny, why: "no connected account can deliver private replies"}
	}
	if acct, ok := g.cfg.Destination(d.Address); !ok || acct != d.Account {
		return verdict{kind: deny, why: "the destination must be the connected mail account's own address (CH-20)"}
	}
	return verdict{kind: ask, local: true, item: owner.Item{Ref: in.ID, Object: "send private replies to " + d.Address,
		Facts: owner.Facts{Kind: owner.GrantChange, Verb: "share", NoRecipient: true}}}
}

// evaluateFollow decides a switch of the box's update source (OSS-10). It
// changes who decides what software the box installs, so it is a tier-4
// act: the owner's code-generator code plus confirmation on the local
// page, and it comes only from that page (Security C6). The request names
// only the owner's own name for the source; the page shows the keys,
// thresholds and expiry the digest binds. One intent runs once, so one
// approval buys one switch.
func (g *Gate) evaluateFollow(in journal.Intent) verdict {
	if in.Origin != originLocal {
		return verdict{kind: deny, why: "only the owner, on the box's local page, changes where updates come from"}
	}
	name, ok1 := in.Params[ParamFollowName].(string)
	digest, ok2 := in.Params[ParamFollowDigest].(string)
	if !ok1 || !ok2 || len(in.Params) != 2 || in.Executor != FollowExecutor || !hexDigest(digest) || !followName(name) {
		return verdict{kind: deny, why: "malformed request to change where updates come from"}
	}
	if !g.cfg.LocalUI {
		return verdict{kind: deny, why: "changing where updates come from needs confirmation on the box's local page, which this build does not have yet (OSS-10)"}
	}
	return verdict{kind: ask, local: true, item: owner.Item{Ref: in.ID, Object: "get updates from " + name,
		Facts: owner.Facts{Kind: owner.GrantChange, Verb: "follow", NoRecipient: true}}}
}

// hexDigest is 64 lower-case hex characters.
func hexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// followName is the owner's name for a source: 1 to MaxFollowName
// printable characters on one line (no control or bidi formatting
// characters), with no leading or trailing space, and at most
// MaxFollowDigits digits in all. The name reaches the owner in
// broker-voiced texts, so it must never carry a code, even spaced out
// (security R1 on #180; codes are 6 digits).
func followName(s string) bool {
	n, digits := 0, 0
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
		if unicode.IsDigit(c) {
			digits++
		}
		n++
	}
	return n > 0 && n <= MaxFollowName && digits <= MaxFollowDigits && strings.TrimSpace(s) == s
}

// evaluateDelivery decides a delivery to the evidence destination: a
// pre-allowed share to the owner only (CH-20). Every part of it is fixed
// by the broker, so anything else is denied, never asked.
func (g *Gate) evaluateDelivery(in journal.Intent) verdict {
	if in.Origin != OriginEvidence {
		return verdict{kind: deny, why: "only the broker delivers to the owner's destination (CH-20)"}
	}
	g.mu.Lock()
	d, ag := g.evidence, g.adapterLocked(in.Account)
	g.mu.Unlock()
	op, ok := g.cfg.Delivery[in.Executor]
	switch {
	case !ok || in.Action != op:
		return verdict{kind: deny, why: "the broker's evidence route only delivers"}
	case ag == nil || ag.Spec.Executor != in.Executor || in.Account != d.Account:
		return verdict{kind: deny, why: "no grant connects the destination's account"}
	case ag.Spec.Ops[in.Action] != verb.Share || g.cfg.Declared[in.Executor][in.Action] != verb.Share:
		return verdict{kind: deny, why: "delivery is not granted for the account"}
	case len(in.Recipients) != 1 || in.Recipients[0] != d.Address:
		return verdict{kind: deny, why: "delivery goes only to the owner's destination"}
	}
	b, _ := in.Params[ParamBody].(string)
	from, _ := in.Params[ParamFrom].(string)
	if b == "" || (from != DeliverFromAgent && from != DeliverFromBox) || len(in.Params) != 2 {
		return verdict{kind: deny, why: "a delivery carries only its body and author"}
	}
	n := 0
	for _, x := range g.eng.AuthorizedSince(in.Account, in.Action, g.cfg.Now().Add(-24*time.Hour)) {
		if x.Origin == OriginEvidence && x.ID != in.ID {
			n++
		}
	}
	if n >= DeliveryCap {
		return verdict{kind: deny, why: DeliveryCapReason}
	}
	if g.cfg.Destination == nil {
		return verdict{kind: deny, why: "the destination is no longer the account's own address"}
	}
	if acct, ok := g.cfg.Destination(d.Address); !ok || acct != d.Account {
		return verdict{kind: deny, why: "the destination is no longer the account's own address"}
	}
	return verdict{kind: allow}
}

// destination is the evidence destination: an address and the account
// whose own address it is.
type destination struct{ Address, Account string }

func parseDestination(in journal.Intent) (destination, error) {
	a, ok1 := in.Params[ParamEvidenceAddress].(string)
	c, ok2 := in.Params[ParamEvidenceAccount].(string)
	if !ok1 || !ok2 || len(in.Params) != 2 {
		return destination{}, errors.New("malformed evidence destination")
	}
	if a == "" {
		if c != "" {
			return destination{}, errors.New("malformed evidence destination")
		}
		return destination{}, nil
	}
	if !bareAddress(a) || c == "" {
		return destination{}, errors.New("the destination must be one bare, lower-case address")
	}
	return destination{Address: a, Account: c}, nil
}

// bareAddress is a lower-case local@domain with nothing around it. Whether
// it is the owner's is Config.Destination's to say.
func bareAddress(a string) bool {
	local, domain, ok := strings.Cut(a, "@")
	return ok && local != "" && domain != "" && !strings.ContainsAny(a, " \t\r\n<>,;\"()[]:") &&
		!strings.Contains(domain, "@") && strings.ToLower(a) == a
}

// Evidence returns the evidence destination and its account; empty when
// none is set (CH-20).
func (g *Gate) Evidence() (address, account string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.evidence.Address, g.evidence.Account
}

// evaluateChange delegates a meta.change.* intent to the change pipeline
// (change C8). What the pipeline's standing rules allow runs; what only the
// owner may allow is a high-tier request whose line the pipeline renders
// from broker-known fields; anything else is denied with the pipeline's
// reason, which only the owner and the pipeline can read (no guest reaches
// this point).
func (g *Gate) evaluateChange(ctx context.Context, phase journal.Phase, in journal.Intent) verdict {
	if g.cfg.Changes == nil {
		return verdict{kind: deny, why: "the change pipeline is not running"}
	}
	err := g.cfg.Changes.Check(ctx, phase, in)
	// Only the sentinel itself asks: an error that wraps or joins it with
	// a refusal denies (fails closed).
	no, ok := err.(interface{ NeedsOwner() bool })
	switch {
	case err == nil:
		return verdict{kind: allow}
	case !ok || !no.NeedsOwner():
		return verdict{kind: deny, why: err.Error()}
	}
	l, err := g.cfg.Changes.Line(in)
	if err != nil {
		return verdict{kind: deny, why: err.Error()}
	}
	local := sharingOn(in)
	if local && !g.cfg.LocalUI {
		return verdict{kind: deny, why: "turning sharing on needs confirmation on the box's local page, which this build does not have yet (CHG-4)"}
	}
	hold := false
	if l.Facts.Verb == "install" {
		// Adopting a release needs the code and the local page (CH-3).
		// Without the page it is held, not denied, so the box can still
		// take a security fix once the page exists; no code is texted
		// for a request that cannot complete.
		local, hold = true, !g.cfg.LocalUI
	}
	kind := owner.GrantChange
	if l.Facts.Kind == owner.Ordinary && !local {
		kind = owner.Ordinary // a tested, undoable learned change: low tier
	}
	return verdict{kind: ask, local: local, hold: hold, item: owner.Item{Ref: in.ID, Object: l.Object, Detail: l.Detail, UndoBy: l.UndoBy,
		Facts: owner.Facts{Kind: kind, Verb: l.Facts.Verb, NoRecipient: true}}}
}

// evaluateLoops delegates a meta.loops.* intent to the loop scheduler
// (GR18). What the scheduler allows on the owner's text runs; raising the
// spare budget is an owner request with the scheduler's line, low tier
// unless the scheduler marks it otherwise, with no recipient or amount.
func (g *Gate) evaluateLoops(ctx context.Context, phase journal.Phase, in journal.Intent) verdict {
	if g.cfg.Loops == nil {
		return verdict{kind: deny, why: "the loop scheduler is not running"}
	}
	err := g.cfg.Loops.Check(ctx, phase, in)
	no, ok := err.(interface{ NeedsOwner() bool })
	switch {
	case err == nil:
		return verdict{kind: allow}
	case !ok || !no.NeedsOwner():
		return verdict{kind: deny, why: err.Error()}
	}
	l, err := g.cfg.Loops.Line(in)
	if err != nil {
		return verdict{kind: deny, why: err.Error()}
	}
	return verdict{kind: ask, item: owner.Item{Ref: in.ID, Object: l.Object, Detail: l.Detail, UndoBy: l.UndoBy,
		Facts: owner.Facts{Kind: l.Facts.Kind, Verb: l.Facts.Verb, NoRecipient: true}}}
}

// sharingOn reports the intent that turns sharing on: it changes what
// leaves the box (CHG-4, CHG-5), so like a grant it also needs the local
// page (CH-3). Turning learning on, or any setting off, needs only the code.
func sharingOn(in journal.Intent) bool {
	return in.Action == "meta.change.policy" && strings.HasSuffix(in.ID, ":sharing:on")
}

// Check is the journal policy (OP-3): it runs at authorize and again
// immediately before dispatch.
func (g *Gate) Check(ctx context.Context, phase journal.Phase, in journal.Intent) error {
	err := g.check(ctx, phase, in)
	if err == nil && phase == journal.PhaseAuthorize && g.cfg.Observe != nil && in.Account != journal.BrokerAccount {
		g.observe(in)
	}
	return err
}

// observe hands Observe a deep copy of in; a panic in it is logged.
func (g *Gate) observe(in journal.Intent) {
	defer func() {
		if recover() != nil {
			g.cfg.Logf("grants: intent observer failed")
		}
	}()
	b, err := json.Marshal(in)
	if err != nil {
		return
	}
	var cp journal.Intent
	if json.Unmarshal(b, &cp) != nil {
		return
	}
	g.cfg.Observe(cp)
}

func (g *Gate) check(ctx context.Context, phase journal.Phase, in journal.Intent) error {
	g.mu.Lock()
	d, decided := g.decided[in.ID]
	ready := g.eng != nil
	g.mu.Unlock()
	if !ready {
		return errors.New("grants are not loaded")
	}
	if decided && !d.approved {
		return errors.New("not approved: " + d.why)
	}
	v := g.evaluate(ctx, phase, in)
	switch v.kind {
	case deny:
		return errors.New(v.why)
	case allow:
		return nil
	}
	if !decided {
		return errors.New("needs the owner's approval")
	}
	if v.local && !g.isConfirmed(in.ID) {
		return errors.New("needs confirmation on the box's local page")
	}
	if !sameItem(d.item, v.item) {
		return errors.New("the details changed after the owner approved; ask again")
	}
	if phase == journal.PhaseDispatch && g.cfg.Now().Sub(d.at) > g.cfg.Fresh {
		return fmt.Errorf("the approval is older than %s; ask again", g.cfg.Fresh)
	}
	// The engine commits the dispatch only if nothing was journaled since
	// this check, so an attempt started by a concurrent Dispatch, before
	// spend runs, is seen here or forces the check again (GR8).
	if phase == journal.PhaseDispatch {
		n, err := g.tries(in.ID)
		if err != nil {
			return fmt.Errorf("cannot read the intent's attempts: %w", err)
		}
		if n != d.tries {
			return errors.New("the owner's approval was used by an earlier attempt; ask again")
		}
	}
	return nil
}

// tries is how many attempts the intent has started. The engine is read
// without g.mu: its policy calls take g.mu. An error is a refusal at the
// recheck, never a count that might match an approval.
func (g *Gate) tries(id string) (int, error) {
	g.mu.Lock()
	eng := g.eng
	g.mu.Unlock()
	if eng == nil {
		return 0, errors.New("grants are not loaded")
	}
	st, err := eng.Get(id)
	if err != nil {
		return 0, err
	}
	return len(st.Attempts), nil
}

func (g *Gate) isConfirmed(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.confirmed[id]
}

// Submit, Dispatch, and Get pass through to the engine; with Authorize
// they are the guest plane's Effects.
// Submit refuses a derived intent's ID from anyone but the gate, so no
// one can take it first and block a stage or an UNDO's inverse (C1).
func (g *Gate) Submit(in journal.Intent) (journal.Status, error) {
	if strings.HasPrefix(in.ID, reversible.Prefix) {
		return journal.Status{}, errors.New("grants: intent IDs starting " + reversible.Prefix + " are the broker's")
	}
	return g.eng.Submit(in)
}

func (g *Gate) Dispatch(ctx context.Context, id string) (journal.Status, error) {
	st, err := g.eng.Dispatch(ctx, id)
	if err == nil && st.State != journal.Pending && st.State != journal.Authorized {
		g.spend(id)
	}
	g.endHeld(id)
	return st, err
}

// spend drops the owner's approval of an intent once its dispatch has
// ended, whatever the result: a retry of an effect that did not apply is
// asked again, never sent on the old YES (L3, Security on #76).
func (g *Gate) spend(id string) {
	g.mu.Lock()
	delete(g.decided, id)
	delete(g.confirmed, id)
	g.mu.Unlock()
}

// endHeld settles the staged copy of released effects that STOP kept from
// running, once each has ended (afterHold). With no id it checks them all.
func (g *Gate) endHeld(ids ...string) {
	g.mu.Lock()
	if len(ids) == 0 {
		for id := range g.after {
			ids = append(ids, id)
		}
		for id := range g.sending {
			if _, ok := g.after[id]; !ok {
				ids = append(ids, id)
			}
		}
	}
	g.mu.Unlock()
	for _, id := range ids {
		// The engine is read without g.mu: its policy calls take g.mu.
		st, err := g.eng.Get(id)
		if errors.Is(err, journal.ErrNotFound) {
			// Nothing will end it: drop its unsent verdict (security on #101).
			g.mu.Lock()
			delete(g.sending, id)
			g.mu.Unlock()
		}
		if err != nil || st.State == journal.Authorized || st.State == journal.InFlight {
			continue
		}
		g.mu.Lock()
		a, ok := g.after[id]
		delete(g.after, id)
		v := g.sending[id]
		delete(g.sending, id)
		g.mu.Unlock()
		g.reportSent(v, st)
		if !ok {
			continue
		}
		g.spend(id)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.afterHold(st, a.hold, a.n)
		}()
	}
}

// Withdraw closes a recall rollback question still waiting for the owner,
// as superseded by an earlier one for the same agent (recalltool W10): it
// is denied with "not approved: superseded" and an answer to it later
// does nothing. Only the broker's recall rollbacks can be withdrawn.
func (g *Gate) Withdraw(id string) error {
	st, err := g.eng.Get(id)
	if err != nil {
		return err
	}
	if st.Intent.Origin != OriginRecall || st.Intent.Action != journal.ActionRecallRollback {
		return errors.New("grants: only a recall rollback can be withdrawn")
	}
	if st.State != journal.Pending {
		return nil
	}
	g.closeIntent(id, "superseded")
	return nil
}

// List returns every intent the journal holds, in submission order.
func (g *Gate) List() []journal.Status {
	out := g.eng.List()
	for i := range out {
		g.annotate(&out[i])
	}
	return out
}

func (g *Gate) Get(id string) (journal.Status, error) {
	st, err := g.eng.Get(id)
	if err == nil {
		g.annotate(&st)
	}
	return st, err
}

// Authorize decides a pending intent: denied or allowed now, or left
// pending while the owner is asked (CH-10, ADP-11). A retry of a pending
// intent asks nothing twice.
func (g *Gate) Authorize(ctx context.Context, id string) (journal.Status, error) {
	st, err := g.eng.Get(id)
	if err != nil || st.State != journal.Pending {
		return st, err
	}
	g.mu.Lock()
	d, decided := g.decided[id]
	_, waiting := g.waiting[id]
	held := decided && d.approved && d.local && !g.confirmed[id]
	carried := g.carried[id] || g.reissuing(id)
	g.mu.Unlock()
	switch {
	case held, waiting, carried:
		g.annotate(&st)
		return st, nil
	case decided:
		return g.eng.Authorize(ctx, id)
	}
	v := g.evaluate(ctx, journal.PhaseAuthorize, st.Intent)
	switch v.kind {
	case deny, allow:
		return g.eng.Authorize(ctx, id)
	case ask:
		if !v.hold && !owner.SMSApprovable(v.item) && !g.cfg.LocalUI {
			// Recipients that cannot be shown in an approval text are never
			// approved by text (CH-10, CH-12). Without the local approvals
			// page to wait for, the agent is told what to change
			// (UX-144-2); with it, flush asks there (P2-2a).
			g.closeIntent(id, RecipientsNotTextable)
			return g.eng.Get(id)
		}
		onlyUI := v.hold
		g.mu.Lock()
		fresh := g.waiting[id] == nil
		if fresh {
			g.waiting[id] = &wait{item: v.item, local: v.local, onlyUI: onlyUI}
			if !onlyUI {
				now := g.cfg.Now()
				if len(g.batch) == 0 {
					g.first = now
				}
				g.last = now
				g.batch = append(g.batch, id)
			}
		}
		delete(g.failed, id)
		delete(g.retry, id)
		own := g.own
		g.mu.Unlock()
		if fresh && v.hold && own != nil {
			// Arbitrator Q1 on #48: one fixed line, no code.
			_ = own.Inform("Waiting for your confirmation on the box's Wi-Fi page, or your recovery key.")
		}
	case autoReply:
		g.queueReply(id, v)
	}
	g.annotate(&st)
	return st, nil
}

// reissuing reports whether id waits in the re-issue queue. g.mu is held.
func (g *Gate) reissuing(id string) bool {
	for _, c := range g.reissue {
		if c.Ref == id {
			return true
		}
	}
	return false
}

// annotate explains a pending intent to the guest. It never names the
// request or its code.
func (g *Gate) annotate(st *journal.Status) {
	if st.State != journal.Pending {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	id := st.Intent.ID
	if g.carried[id] || g.reissuing(id) {
		st.Permission.Reason = "the box restarted; the owner will be asked again"
	} else if d, ok := g.decided[id]; ok && d.approved && d.local && !g.confirmed[id] {
		st.Permission.Reason = "approved by code; waiting for the owner to confirm on the box's local page"
	} else if w := g.waiting[id]; w != nil && w.onlyUI {
		st.Permission.Reason = "waiting for the owner's approval on the box's local page"
	} else if w != nil && w.held {
		st.Permission.Reason = "approved; held for the owner's undo window until " + w.sendAt.UTC().Format("15:04") + " UTC"
	} else if w != nil && w.reply != "" {
		st.Permission.Reason = "auto-reply queued; it sends at " + w.sendAt.UTC().Format("15:04") + " UTC unless the owner cancels it"
	} else if w != nil && g.cfg.LocalUI && w.local {
		st.Permission.Reason = "waiting for the owner's approval on the box's Wi-Fi page"
	} else if w != nil && g.cfg.LocalUI && !owner.SMSApprovable(w.item) {
		// After held and reply: an approved page item is held, not
		// waiting (L3 S1 on #165).
		st.Permission.Reason = WaitingOnThePage
	} else if w != nil {
		st.Permission.Reason = "waiting for the owner's approval"
	} else if r := g.retry[id]; r != "" {
		st.Permission.Reason = r
	} else if f := g.failed[id]; f == LineDown {
		st.Permission.Reason = LineDown
	} else if f != "" {
		st.Permission.Reason = "could not ask the owner (" + f + "); retry later"
	}
}

// LineDown is the agent's reason for an ask that could not be texted
// because the owner's phone line was down: the request was dropped, and
// asking again once the line is back reaches the owner (UX on #170; the
// recovery text tells the owner the agent can ask again).
const LineDown = "not sent: the owner's phone line is down; ask again later"

func failReason(err error) string {
	if owner.LineDown(err) {
		return LineDown
	}
	return err.Error()
}

func (g *Gate) queueReply(id string, v verdict) {
	g.mu.Lock()
	own := g.own
	if g.waiting[id] != nil {
		g.mu.Unlock()
		return
	}
	g.waiting[id] = &wait{item: v.item}
	g.mu.Unlock()
	var res owner.QueueResult
	err := errors.New("no owner channel")
	if own != nil {
		res, err = own.QueueAutoReply(*v.reply)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	w := g.waiting[id]
	switch {
	case w == nil:
	case err != nil:
		delete(g.waiting, id)
		g.failed[id] = failReason(err)
	case res.Queued != nil:
		w.reply, w.sendAt = res.Queued.ID, res.Queued.SendAt
	default:
		// The commitment filter matched: the reply is a normal request.
		w.request = res.Request
	}
}

// flushDue sends the batch when it is due (CH-10, CH-15): at once for an
// urgent item or an owner active in chat; otherwise once the batch has
// been quiet for CoalesceIdle or open for Coalesce, outside quiet hours,
// and within RequestsPerHour, or past it for intents re-issued after a
// restart.
func (g *Gate) flushDue() {
	now := g.cfg.Now()
	g.mu.Lock()
	if len(g.batch) == 0 {
		g.mu.Unlock()
		return
	}
	urgent, reissued := false, false
	for _, id := range g.batch {
		w := g.waiting[id]
		if w == nil {
			continue
		}
		if g.cfg.Urgent != nil && g.cfg.Urgent(w.item) {
			urgent = true
		}
		if !w.expires.IsZero() {
			reissued = true
		}
	}
	own := g.own
	budget := g.textsLocked(now) < g.cfg.RequestsPerHour
	ripe := now.Sub(g.first) >= g.cfg.Coalesce || now.Sub(g.last) >= g.cfg.CoalesceIdle
	g.mu.Unlock()
	active := own != nil && own.Active(activeFor)
	quiet := g.cfg.Quiet != nil && g.cfg.Quiet(now)
	switch {
	case urgent || (!quiet && active):
		g.Flush()
	case !quiet && ripe && (budget || reissued):
		// A re-issued intent runs on its original expiry, so it goes
		// even past the budget (security R3 on #95); the rest stay paced.
		g.flush(true)
	}
}

// textsLocked is the unsolicited texts on the CH-15 budget in the hour
// before now: approval requests and reserved owner questions.
func (g *Gate) textsLocked(now time.Time) int {
	prune := func(ts []time.Time) []time.Time {
		keep := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < time.Hour {
				keep = append(keep, t)
			}
		}
		return keep
	}
	g.sent, g.asked = prune(g.sent), prune(g.asked)
	return len(g.sent) + len(g.asked)
}

// Reserve takes one text of the CH-15 budget for an owner question (W9,
// question Q3). Approval requests go first: it refuses while items wait
// in a batch, and when approval requests and questions together have
// used RequestsPerHour in the hour before now. A question that has waited
// unsent for its AgedAfter (aged, question Config.AgedAfter) may go ahead of a waiting batch,
// once an hour, so steady approval traffic never holds it indefinitely
// and approvals keep the rest of the budget (question PQ5). A granted
// reservation counts at once, sent or not, so the check and the count are
// one step. Time is the gate's own clock, as for request texts.
func (g *Gate) Reserve(aged bool) bool {
	now := g.cfg.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.textsLocked(now) >= g.cfg.RequestsPerHour {
		return false
	}
	if len(g.batch) > 0 {
		if !aged || !g.agedAt.IsZero() && now.Sub(g.agedAt) < time.Hour {
			return false
		}
		g.agedAt = now
	}
	g.asked = append(g.asked, now)
	return true
}

// take counts n request texts about to be sent and returns how many may
// go. Paced, it grants only what the budget has left; unpaced (an urgent
// item, an owner active in chat) it grants all. Counted before sending,
// so no question is reserved in between.
func (g *Gate) take(paced bool, n int) int {
	now := g.cfg.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if paced {
		n = max(0, min(n, g.cfg.RequestsPerHour-g.textsLocked(now)))
	}
	for range n {
		g.sent = append(g.sent, now)
	}
	return n
}

// requeue puts items the budget did not cover back in the batch.
func (g *Gate) requeue(items []owner.Item) {
	if len(items) == 0 {
		return
	}
	g.mu.Lock()
	for _, it := range items {
		if g.waiting[it.Ref] != nil {
			g.batch = append(g.batch, it.Ref)
		}
	}
	g.mu.Unlock()
}

// Flush sends batched items now: one request per tier, at most MaxBatch
// items each, so a high-risk item does not raise the code needed for
// low-risk ones (CH-10). Each request text counts toward RequestsPerHour,
// but Flush itself is unpaced: it sends everything batched.
func (g *Gate) Flush() { g.flush(false) }

// flush sends batched items, each request text counted on the CH-15
// budget before it goes; paced, texts past the budget stay batched,
// except re-issued intents, which always go.
func (g *Gate) flush(paced bool) {
	now := g.cfg.Now()
	g.mu.Lock()
	ids, own := g.batch, g.own
	stopped := g.eng != nil && g.eng.Stopped()
	g.batch = nil
	var low, high, again, page []owner.Item
	var ttls, pageTTLs []time.Duration
	var lapsed []string
	for _, id := range ids {
		w := g.waiting[id]
		if w == nil {
			continue
		}
		if !w.expires.IsZero() {
			// Re-issued after a restart (GR10): one request and code per
			// intent, under its original expiry, never while STOP holds.
			switch {
			case !now.Before(w.expires):
				lapsed = append(lapsed, id)
			case stopped:
				g.batch = append(g.batch, id)
			case g.onPage(w):
				page = append(page, w.item)
				pageTTLs = append(pageTTLs, w.expires.Sub(now))
			default:
				again = append(again, w.item)
				ttls = append(ttls, w.expires.Sub(now))
			}
			continue
		}
		if g.onPage(w) {
			// Its recipients cannot be texted, or it needs the owner's
			// confirmation: asked alone on the local page (P2-2a), never
			// in a texted batch, and never YES by text (Security Q1).
			page = append(page, w.item)
			pageTTLs = append(pageTTLs, 0)
			continue
		}
		if own != nil && own.Tier(w.item.Facts) == owner.Low {
			low = append(low, w.item)
		} else {
			high = append(high, w.item)
		}
	}
	g.mu.Unlock()
	for _, id := range lapsed {
		g.closeIntent(id, "the approval request expired; ask again with a new request_id")
	}
	// Each re-issued intent is its own request text: counted, but never
	// paced, so none lapses unseen behind a spent budget (security R3).
	g.take(false, len(again))
	if len(again) > 0 {
		reqs := make([]string, len(again))
		err := errors.New("no owner channel")
		if own != nil {
			reqs, err = own.RequestEach(again, ttls)
		}
		g.mu.Lock()
		for i, it := range again {
			w := g.waiting[it.Ref]
			switch {
			case w == nil:
			case i < len(reqs) && reqs[i] != "":
				w.request = reqs[i]
			default:
				delete(g.waiting, it.Ref)
				if err == nil {
					err = errors.New("not sent")
				}
				g.failed[it.Ref] = failReason(err)
			}
		}
		g.mu.Unlock()
	}
	var ask []owner.Item
	var askTTLs []time.Duration
	for i, it := range page {
		// Each counts like a request; re-issued ones always go, as above.
		// Their notices share texts (Potency R2).
		if pageTTLs[i] == 0 && g.take(paced, 1) == 0 {
			g.requeue([]owner.Item{it})
			continue
		}
		if pageTTLs[i] != 0 {
			g.take(false, 1)
		}
		ask, askTTLs = append(ask, it), append(askTTLs, pageTTLs[i])
	}
	if len(ask) > 0 {
		reqs := make([]string, len(ask))
		err := errors.New("no owner channel")
		if own != nil {
			reqs, err = own.RequestLocalEach(ask, askTTLs)
		}
		g.mu.Lock()
		for i, it := range ask {
			if w := g.waiting[it.Ref]; w != nil {
				if i >= len(reqs) || reqs[i] == "" {
					delete(g.waiting, it.Ref)
					why := "owner: not asked"
					if err != nil {
						why = failReason(err)
					}
					g.failed[it.Ref] = why
				} else {
					w.request = reqs[i]
				}
			}
		}
		g.mu.Unlock()
	}
	for _, items := range [][]owner.Item{low, high} {
		// An item that cannot be texted (one carried over a restart from
		// an earlier build's rules) fails alone, not with its batch
		// (UX-144-1).
		textable := items[:0:0]
		for _, it := range items {
			if owner.SMSApprovable(it) {
				textable = append(textable, it)
			} else {
				g.closeIntent(it.Ref, RecipientsNotTextable)
			}
		}
		items = textable
		for len(items) > 0 {
			if g.take(paced, 1) == 0 {
				g.requeue(items)
				break
			}
			n := min(len(items), MaxBatch)
			chunk := items[:n]
			items = items[n:]
			req := ""
			err := errors.New("no owner channel")
			if own != nil {
				req, err = own.Request(chunk, 0)
			}
			g.mu.Lock()
			for _, it := range chunk {
				w := g.waiting[it.Ref]
				if w == nil {
					continue
				}
				if err != nil {
					// Retrying the request_id asks again.
					delete(g.waiting, it.Ref)
					g.failed[it.Ref] = failReason(err)
				} else {
					w.request = req
				}
			}
			g.mu.Unlock()
		}
	}
}

// Decide takes the owner channel's decision on one item (owner.Config
// Decide). An approval settles only the request it answers; a denial for
// an intent this run never asked about (a restart's) still closes it.
func (g *Gate) Decide(d owner.Decision) {
	if !d.Approved && d.Why != "owner" && g.isSetting(d.Ref) {
		g.lapse(d)
		return
	}
	if d.Approved && d.Hold != "" {
		g.hold(d)
		return
	}
	if !d.Approved && (d.Why == "not held" || (d.Why == "restart" && d.Hold != "")) {
		g.unhold(d)
		return
	}
	unstaged := d.Approved && g.unstaged(d.Ref)
	tries, err := g.tries(d.Ref)
	if err != nil {
		tries = -1 // matches no count, so the recheck refuses it
	}
	g.mu.Lock()
	w := g.waiting[d.Ref]
	if w == nil && (d.Approved || g.eng == nil) {
		g.mu.Unlock()
		return
	}
	// While the request is being sent its ID is not yet known; the Ref is
	// unique to this intent, so a decision then can only answer it.
	if w != nil && w.request != "" && d.Request != w.request && d.Request != w.reply {
		g.mu.Unlock()
		return
	}
	var item owner.Item
	local := false
	if w != nil {
		item, local = w.item, w.local
	}
	delete(g.waiting, d.Ref)
	delete(g.carried, d.Ref)
	why := d.Why
	if why == "" {
		why = "owner"
	}
	if d.Approved && local && d.Page {
		// Approved on the page with a fresh code: that answer confirms
		// it, if the item is the one the page showed (Security P1).
		if d.Sum == owner.ItemSum(item) {
			g.confirmed[d.Ref] = true
		} else {
			d.Approved, why = false, "it changed since the page showed it"
		}
	}
	hold, attempt := "", 0
	if w != nil {
		attempt = w.attempt
	}
	switch {
	case !d.Approved && (d.Why == "undo" || d.Why == "restart"):
		hold = d.Request
	case d.Approved && w != nil && w.held:
		hold = w.reply
		if unstaged {
			// Released without its staged copy: the owner approved it as
			// staged, so it is not sent (arbitrator on #76).
			d.Approved, why = false, "its staged copy could not be made"
		}
	}
	unheld := d.Approved && (w == nil || !w.held)
	implicit := unheld && d.Why == whyReleased
	late := unheld && d.Why == whyReleasedLate
	g.decided[d.Ref] = decision{approved: d.Approved, why: why, asked: w != nil, implicit: implicit, late: late,
		req: d.Request, at: g.cfg.Now(), item: item, local: local, hold: hold, attempt: attempt, tries: tries}
	wait := d.Approved && local && !g.confirmed[d.Ref]
	own := g.own
	g.mu.Unlock()
	if unstaged && hold != "" && own != nil {
		_ = own.Inform(fmt.Sprintf("%s was not sent: its draft or staged copy could not be made. Ask your agent again if still needed.", clip(hold)))
	}
	if !wait {
		g.settle(d.Ref)
	}
}

// unhold ends a hold that closed without the owner's answer (PV1 on #76):
// the owner channel could not hold it, or a restart cancelled it. It is no
// refusal, so the intent is not denied and nothing counts it as one
// (CAP-6, ADP-11, Loop 1). After a restart it is asked again as new with
// the rest of what the restart left open (GR10, PV2); otherwise the
// agent's retry asks again. Any staged copy is removed first (C2).
func (g *Gate) unhold(d owner.Decision) {
	g.mu.Lock()
	w := g.waiting[d.Ref]
	if w != nil && w.request != "" && d.Request != w.request && d.Request != w.reply {
		g.mu.Unlock()
		return
	}
	n := 0
	if w != nil {
		n = w.attempt
	}
	delete(g.waiting, d.Ref)
	delete(g.decided, d.Ref)
	if d.Why == "not held" {
		delete(g.carried, d.Ref)
		g.retry[d.Ref] = "approved, but it could not be held for its undo window, so it did not run; retry to ask the owner again"
	}
	eng := g.eng
	g.mu.Unlock()
	if eng == nil {
		return
	}
	if n == 0 {
		// After a restart the gate kept no hold: the cancel is for the
		// latest one, resolved now, before Reissue can start the next
		// (security R1 on #76).
		n, _ = g.lastStage(d.Ref)
	}
	if st, err := eng.Get(d.Ref); err == nil && n > 0 {
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.unstage(st.Intent, d.Request, n)
		}()
	}
}

// lastStage returns the number of p's latest hold that has a stage
// intent in the journal, and that intent; 0 if none.
func (g *Gate) lastStage(p string) (int, journal.Status) {
	var last journal.Status
	n := 0
	for {
		st, err := g.eng.Get(reversible.StageID(p, n+1))
		if err != nil {
			return n, last
		}
		n, last = n+1, st
	}
}

// unstaged reports a held effect whose form stages it but whose stage did
// not succeed, once any stage attempt in flight has ended.
func (g *Gate) unstaged(id string) bool {
	g.mu.Lock()
	w := g.waiting[id]
	var done chan struct{}
	n := 0
	if w != nil {
		n = w.attempt
		done = g.staging[reversible.StageID(id, n)]
	}
	g.mu.Unlock()
	if w == nil || !w.held {
		return false
	}
	st, err := g.eng.Get(id)
	if err != nil {
		return false
	}
	if f, ok := g.forms[st.Intent.Executor][st.Intent.Action]; !ok || f.Stage == "" {
		return false
	}
	if done != nil {
		<-done
	}
	s, err := g.eng.Get(reversible.StageID(id, n))
	return err != nil || s.State != journal.Succeeded
}

// lastEvidence is the evidence of an intent's last attempt.
func lastEvidence(st journal.Status) string {
	if len(st.Attempts) == 0 {
		return ""
	}
	return st.Attempts[len(st.Attempts)-1].Evidence
}

// hold keeps an effect the owner approved from running until the owner
// channel releases it after its undo window (REV-3, CH-16), and stages it
// if its form says so. The approval is recorded at the release, so the
// recheck's freshness counts from then.
func (g *Gate) hold(d owner.Decision) {
	g.mu.Lock()
	w := g.waiting[d.Ref]
	if w == nil || w.held {
		g.mu.Unlock()
		return
	}
	if w.request != "" && d.Request != w.request {
		// A hold this intent's request did not make: never left pending
		// on a release that would not match it.
		own := g.own
		g.mu.Unlock()
		g.closeIntent(d.Ref, "the approval did not match its request; ask again with a new request_id")
		if own != nil {
			_ = own.Inform(fmt.Sprintf("%s did not run: its approval did not match its request. Ask your agent again if still needed.", clip(d.Hold)))
		}
		return
	}
	w.held, w.reply, w.sendAt = true, d.Hold, d.Until
	g.mu.Unlock()
	st, err := g.eng.Get(d.Ref)
	if err != nil {
		return
	}
	n, _ := g.lastStage(d.Ref)
	n++
	g.mu.Lock()
	if w := g.waiting[d.Ref]; w != nil && w.held {
		w.attempt = n
	}
	g.mu.Unlock()
	f, ok := g.forms[st.Intent.Executor][st.Intent.Action]
	if !ok || f.Stage == "" {
		return
	}
	in := reversible.Stage(st.Intent, f, n)
	done := make(chan struct{})
	g.mu.Lock()
	g.derived[in.ID] = true
	g.staging[in.ID] = done
	g.mu.Unlock()
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer close(done)
		if st := g.runDerived(in); st.State != journal.Succeeded {
			// The effect is then not sent at release (RV7).
			g.cfg.Logf("grants: staging %s: %s", d.Ref, st.State)
		}
	}()
}

// afterHold settles a held effect's staged copy once the effect is
// settled (arbitrator on #76). Sent: the copy is the sent message. Gone:
// it is gone (deleted), a cancel. Edited: it is not sent and stays for the
// owner, who is told in a fixed line offering no YES, because an approval
// could not be bound to the edited version (arbitrator re-ruling).
// Anything else that did not happen (UNDO, a restart, a
// recheck denial, a failed send) unstages (C2). An unknown outcome, or an
// effect STOP still holds, leaves it alone.
func (g *Gate) afterHold(st journal.Status, hold string, n int) {
	switch {
	case st.State == journal.NotApplied && lastEvidence(st) == reversible.EvidenceGone:
	case st.State == journal.NotApplied && lastEvidence(st) == reversible.EvidenceEdited:
		g.mu.Lock()
		own := g.own
		g.mu.Unlock()
		if own != nil {
			_ = own.Inform(fmt.Sprintf("%s not sent: its draft changed after you approved it. Send it from your mail app if you still want it.", clip(hold)))
		}
	case st.State == journal.Denied || st.State == journal.NotApplied:
		g.unstage(st.Intent, hold, n)
	}
}

// unstage removes what a cancelled effect's stage made (REV-3), once the
// stage attempt has ended. A stage that did not succeed left nothing. If
// the inverse is not applied (the copy changed since, or the grant is
// gone), the copy is left as is and the owner is told.
func (g *Gate) unstage(p journal.Intent, hold string, n int) {
	f, ok := g.forms[p.Executor][p.Action]
	if !ok || f.Stage == "" || n < 1 {
		return
	}
	sid := reversible.StageID(p.ID, n)
	g.mu.Lock()
	done := g.staging[sid]
	g.mu.Unlock()
	if done != nil {
		<-done
	}
	g.mu.Lock()
	delete(g.staging, sid)
	g.mu.Unlock()
	st, err := g.eng.Get(sid)
	if err != nil || st.State != journal.Succeeded || len(st.Attempts) == 0 {
		return
	}
	if _, err := g.eng.Get(reversible.InverseID(p.ID, n)); err == nil {
		return // already unstaged
	}
	in := reversible.Inverse(p, f, n, lastEvidence(st))
	g.mu.Lock()
	g.derived[in.ID] = true
	own := g.own
	g.mu.Unlock()
	if st := g.runDerived(in); st.State != journal.Succeeded && own != nil {
		_ = own.Inform(fmt.Sprintf("%s did not run, but its draft or staged copy could not be removed, so it was left as is.", clip(hold)))
	}
}

// runDerived journals and runs a stage or inverse intent, which stays
// allowed only while it runs.
func (g *Gate) runDerived(in journal.Intent) journal.Status {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	defer func() {
		g.mu.Lock()
		delete(g.derived, in.ID)
		g.mu.Unlock()
	}()
	st, err := g.eng.Submit(in)
	if err == nil && st.State == journal.Pending {
		st, err = g.eng.Authorize(ctx, in.ID)
	}
	if err == nil && st.State == journal.Authorized {
		st, err = g.eng.Dispatch(ctx, in.ID)
	}
	if err != nil {
		g.cfg.Logf("grants: %s: %v", in.ID, err)
	}
	return st
}

// isSetting reports a pending change pipeline or loop setting intent: one
// whose unanswered request lapses rather than being declined.
func (g *Gate) isSetting(id string) bool {
	g.mu.Lock()
	eng := g.eng
	g.mu.Unlock()
	if eng == nil {
		return false
	}
	st, err := eng.Get(id)
	return err == nil && st.State == journal.Pending && st.Intent.Account == journal.BrokerAccount &&
		(changeAction(st.Intent.Action) || loopsAction(st.Intent.Action))
}

// lapse closes the owner's request for a change or loop setting intent
// that ended without the owner's answer: expired, voided by wrong codes,
// left out of a partial YES, or dropped by a restart (change C7). For a
// change, the pipeline drops its
// proposal without recording a decline, then the intent closes as "lapsed,
// not declined" (arbitrator Q3 on #48): it never runs, the owner channel
// lists the expired item in the digest (CH-13), and neither learning nor
// Loop 1's backoff reads silence as a rejection. Only the owner's NO is a
// decline.
func (g *Gate) lapse(d owner.Decision) {
	g.mu.Lock()
	w := g.waiting[d.Ref]
	if w != nil && w.request != "" && d.Request != w.request {
		g.mu.Unlock()
		return
	}
	delete(g.waiting, d.Ref)
	eng := g.eng
	g.mu.Unlock()
	if st, err := eng.Get(d.Ref); err == nil && g.cfg.Changes != nil && changeAction(st.Intent.Action) {
		g.cfg.Changes.Decided(context.Background(), st.Intent, false)
	}
	g.closeIntent(d.Ref, lapsed)
}

// lapsed is the reason a change request closed without the owner's answer.
const lapsed = "lapsed, not declined: the owner did not answer"

// ConfirmLocal records the owner's confirmation on the local page for a
// grant intent (CH-3), or for a change that needs it: turning sharing on
// or adopting a release (GR17). The local UI (P2-2) calls it after showing
// Describe; the code and the confirmation may come in either order.
func (g *Gate) ConfirmLocal(id string) error {
	st, err := g.eng.Get(id)
	if err != nil {
		return err
	}
	if st.State != journal.Pending || st.Intent.Account != journal.BrokerAccount ||
		(st.Intent.Action != journal.ActionGrantChange && st.Intent.Action != journal.ActionEvidence &&
			st.Intent.Action != journal.ActionUpdateFollow && !(changeAction(st.Intent.Action) &&
			g.evaluate(context.Background(), journal.PhaseAuthorize, st.Intent).local)) {
		return errors.New("grants: nothing to confirm for " + clip(id))
	}
	g.mu.Lock()
	g.confirmed[id] = true
	d, ok := g.decided[id]
	g.mu.Unlock()
	if ok && d.approved {
		g.settle(id)
	}
	return nil
}

// settle authorizes and, if allowed, dispatches a decided intent, on its
// own goroutine: the owner channel calls Decide inline, and a slow
// executor must not delay its replies.
func (g *Gate) settle(id string) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		g.mu.Lock()
		d := g.decided[id]
		g.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		st, err := g.eng.Authorize(ctx, id)
		if err == nil && st.State == journal.Authorized {
			st, err = g.eng.Dispatch(ctx, id)
		}
		if err != nil && !errors.Is(err, journal.ErrStopped) && !errors.Is(err, journal.ErrState) {
			g.cfg.Logf("grants: settling %s: %v", id, err)
		}
		g.mu.Lock()
		if st.State != journal.Authorized {
			// Held intents (STOP) keep the decision for their recheck.
			delete(g.decided, id)
			delete(g.confirmed, id)
		}
		delete(g.failed, id)
		own := g.own
		g.mu.Unlock()
		if d.hold != "" {
			if st.State == journal.Authorized || st.State == journal.InFlight {
				// STOP held it after the release: settle its staged copy
				// when it ends, whoever dispatches it (L3 on #76).
				g.mu.Lock()
				g.after[id] = afterRef{hold: d.hold, n: d.attempt}
				g.mu.Unlock()
			} else {
				g.afterHold(st, d.hold, d.attempt)
			}
		}
		if st.Intent.Origin == reversible.Origin && st.State != journal.Pending && st.State != journal.Authorized {
			g.mu.Lock()
			delete(g.derived, id)
			g.mu.Unlock()
		}
		if g.cfg.Changes != nil && changeAction(st.Intent.Action) && st.Intent.Account == journal.BrokerAccount &&
			(st.State == journal.Denied || st.State == journal.Succeeded || st.State == journal.NotApplied) {
			// Only the owner's NO is a decline; a refusal at the recheck
			// (stale approval, changed state) is not (change C7).
			g.cfg.Changes.Decided(ctx, st.Intent, !d.approved && d.why == "owner")
		}
		switch v := (pending{ownerVerdict(d, st), d.req}); {
		case v.v == "" || g.cfg.Outcome == nil:
		case st.State == journal.Authorized || st.State == journal.InFlight:
			// STOP, a fence, or a slow send: the acceptance waits for
			// the send to end (endHeld, from Dispatch or Tick).
			g.mu.Lock()
			if len(g.sending) < maxReported {
				g.sending[id] = v
			} else {
				g.cfg.Logf("grants: owner verdict not reported: too many effects unsent")
			}
			g.mu.Unlock()
		default:
			g.reportSent(v, st)
		}
		if st.State == journal.Succeeded && st.Intent.Executor == ExecutorName && own != nil && len(st.Attempts) > 0 {
			if gid := st.Attempts[len(st.Attempts)-1].Evidence; gid != "" {
				_ = own.Inform(fmt.Sprintf("Added %s. Text PAUSE %s or REVOKE %s to stop it.", gid, gid, gid))
			}
		}
	}()
}

// The reasons Tick releases an auto-reply with: its undo window passed, on
// time or not (owner Queued.Late).
const (
	whyReleased     = "undo window passed"
	whyReleasedLate = "undo window passed late"
)

// OwnerVerdict is the owner's final verdict on an agent's effect.
type OwnerVerdict string

const (
	// OwnerAccepted: the owner said YES, and for a held effect let its
	// undo window pass.
	OwnerAccepted OwnerVerdict = "accepted"
	// OwnerAcceptedImplicitly: a pre-allowed auto-reply (ADP-11) the
	// owner was shown and let go without answering (potency PK2).
	OwnerAcceptedImplicitly OwnerVerdict = "accepted-implicitly"
	// OwnerDeclined: the owner said NO.
	OwnerDeclined OwnerVerdict = "declined"
	// OwnerUndone: the owner said UNDO inside the undo window.
	OwnerUndone OwnerVerdict = "undone"
)

// OwnerOutcome is an agent effect and the owner's verdict on it.
type OwnerOutcome struct {
	Intent  journal.Intent
	Verdict OwnerVerdict
}

// maxReported bounds the intents reportOnce remembers; the harvester
// itself keeps only the first verdict on an intent (loops L6).
const maxReported = 4096

// reportOnce reports whether intent id's verdict is not yet reported, and
// marks it reported (security A1 on PW3).
func (g *Gate) reportOnce(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reported[id] {
		return false
	}
	g.reported[id] = true
	g.reportedQ = append(g.reportedQ, id)
	if len(g.reportedQ) > maxReported {
		delete(g.reported, g.reportedQ[0])
		g.reportedQ = g.reportedQ[1:]
	}
	return true
}

// reportSent reports verdict p on st once it is final. An acceptance
// counts only once the effect was sent (or may have been); a failed send
// or a changed draft (not_applied) is not the owner's verdict. An implicit
// acceptance waits a further LateRelease for a late UNDO (reportImplicit).
func (g *Gate) reportSent(p pending, st journal.Status) {
	v := p.v
	if v == "" || g.cfg.Outcome == nil {
		return
	}
	if (v == OwnerAccepted || v == OwnerAcceptedImplicitly) && st.State != journal.Succeeded && st.State != journal.OutcomeUnknown {
		return
	}
	if v == OwnerAcceptedImplicitly {
		g.mu.Lock()
		if len(g.implicit) < maxReported {
			g.implicit = append(g.implicit, heldImplicit{in: st.Intent, req: p.req, due: g.cfg.Now().Add(owner.LateRelease)})
		} else {
			g.cfg.Logf("grants: owner verdict not reported: too many implicit acceptances waiting")
		}
		g.mu.Unlock()
		return
	}
	if g.reportOnce(st.Intent.ID) {
		g.report(OwnerOutcome{Intent: st.Intent, Verdict: v})
	}
}

// reportImplicit reports the implicit acceptances whose grace has passed,
// except one the owner texted UNDO for after its release: that reply was
// not let go, it was too late to stop (L3 MUST-4 on #109).
func (g *Gate) reportImplicit(own Owner) {
	now := g.cfg.Now()
	g.mu.Lock()
	var due []heldImplicit
	keep := g.implicit[:0]
	for _, h := range g.implicit {
		if now.Before(h.due) {
			keep = append(keep, h)
		} else {
			due = append(due, h)
		}
	}
	g.implicit = keep
	g.mu.Unlock()
	for _, h := range due {
		if own.UndoneAfterRelease(h.req) {
			continue
		}
		if g.reportOnce(h.in.ID) {
			g.report(OwnerOutcome{Intent: h.in, Verdict: OwnerAcceptedImplicitly})
		}
	}
}

// report calls Outcome outside the gate's lock, after the journal has the
// final state; a panic in it is logged, never the owner's answer's
// failure (security A2 on PW3).
func (g *Gate) report(o OwnerOutcome) {
	defer func() {
		if recover() != nil {
			g.cfg.Logf("grants: owner verdict hook failed")
		}
	}()
	g.cfg.Outcome(o)
}

// ownerVerdict is the owner's verdict d settled st with, or "" when it is
// not one: an expiry, a restart, a recheck's refusal, a draft changed
// after the YES or a failed send (not_applied: no correction text is
// known, and the content was never seen sent), or an intent that is not
// a guest's effect. An approval STOP holds is still the owner's verdict,
// reported only once its send ends (reportSent).
func ownerVerdict(d decision, st journal.Status) OwnerVerdict {
	if !d.asked || d.late || !strings.HasPrefix(st.Intent.Origin, "guest:") || st.Intent.Account == journal.BrokerAccount {
		return ""
	}
	switch {
	case d.approved && (st.State == journal.Authorized || st.State == journal.InFlight ||
		st.State == journal.Succeeded || st.State == journal.OutcomeUnknown):
		if d.implicit {
			return OwnerAcceptedImplicitly
		}
		return OwnerAccepted
	case !d.approved && st.State == journal.Denied && d.why == "owner":
		return OwnerDeclined
	case !d.approved && st.State == journal.Denied && d.why == "undo":
		return OwnerUndone
	}
	return ""
}

// Tick sends batched requests and releases auto-replies whose undo window
// has passed (ADP-11). The owner channel holds them while STOPped.
func (g *Gate) Tick() {
	g.reissueDue()
	g.flushDue()
	g.endHeld()
	g.mu.Lock()
	own := g.own
	g.mu.Unlock()
	if own == nil {
		return
	}
	g.reportImplicit(own)
	now := g.cfg.Now()
	for _, q := range own.DueAutoReplies() {
		why := whyReleased
		// Silence in quiet hours, when the owner asked not to be reached,
		// is not acceptance either (security F1 on #109).
		quiet := g.cfg.Quiet != nil && (g.cfg.Quiet(q.Alerted) || g.cfg.Quiet(now))
		if q.Late || quiet {
			why = whyReleasedLate
		}
		g.Decide(owner.Decision{Request: q.ID, Item: 1, Ref: q.Reply.Ref, Approved: true, Why: why})
	}
}

// Run ticks until ctx is done.
func (g *Gate) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = DefaultTick
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.Tick()
		}
	}
}

// Wait returns when no decision is being settled.
func (g *Gate) Wait() { g.wg.Wait() }

// Holding reports an effect the agent asked for (origin "guest:") that
// the gate holds: batched or waiting on the owner, approved but waiting
// for the local page, held for its undo window, carried over a restart,
// or released but kept from running by STOP. The sleeper does not stop
// the agent then (PE7 condition 2).
func (g *Gate) Holding() bool {
	g.mu.Lock()
	var ids []string
	for id := range g.waiting {
		ids = append(ids, id)
	}
	ids = append(ids, g.batch...)
	for id := range g.carried {
		ids = append(ids, id)
	}
	for _, c := range g.reissue {
		ids = append(ids, c.Ref)
	}
	for id := range g.after {
		ids = append(ids, id)
	}
	for id := range g.sending {
		ids = append(ids, id)
	}
	for id, d := range g.decided {
		if d.approved && d.local && !g.confirmed[id] {
			ids = append(ids, id)
		}
	}
	eng := g.eng
	g.mu.Unlock()
	if eng == nil {
		return false
	}
	for _, id := range ids {
		// The engine is read without g.mu: its policy calls take g.mu.
		if st, err := eng.Get(id); err == nil && strings.HasPrefix(st.Intent.Origin, "guest:") {
			return true
		}
	}
	return false
}

// Narrow pauses or revokes a grant on the owner's text (owner.Config
// Narrow; ADP-9: only the owner's number, like STOP). Narrowing intents
// are exempt from STOP holds and restart fences (journal A9).
func (g *Gate) Narrow(word, id string) string {
	action, done := journal.ActionGrantPause, "Paused"
	if word == "REVOKE" {
		action, done = journal.ActionGrantRevoke, "Revoked"
	}
	g.mu.Lock()
	gr, eng := g.grants[id], g.eng
	g.mu.Unlock()
	if gr == nil || eng == nil {
		return "No grant " + id + "."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Unique per text, so a second PAUSE after a resume is a new intent.
	iid := fmt.Sprintf("owner/%s/%s/%d.%d", strings.ToLower(word), id, g.cfg.Now().UnixNano(), len(eng.List()))
	st, err := eng.Submit(journal.Intent{ID: iid, Origin: OriginOwner, Account: journal.BrokerAccount,
		Action: action, GrantRef: id, Executor: ExecutorName})
	if err == nil {
		st, err = eng.Authorize(ctx, iid)
	}
	if err == nil && st.State == journal.Authorized {
		st, err = eng.Dispatch(ctx, iid)
	}
	if err != nil || st.State != journal.Succeeded {
		g.cfg.Logf("grants: %s %s: %v (%s)", word, id, err, st.State)
		return fmt.Sprintf("Could not %s %s. STOP still pauses everything.", strings.ToLower(word), id)
	}
	if gr.Spec.Rule != nil {
		return fmt.Sprintf("%s %s. Its actions now need your approval.", done, id)
	}
	return fmt.Sprintf("%s %s. Nothing runs on %s until it is granted again.", done, id, gr.Spec.Account)
}

// Execute runs a grant intent: it is the engine executor for ExecutorName.
func (g *Gate) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	g.mu.Lock()
	before := make([]string, 0, len(g.grants))
	for k := range g.grants {
		before = append(before, k)
	}
	id, err := g.applyLocked(in)
	// Every grant the intent ended: the one named, and the pre-allowances
	// a revoked connection takes with it (L3 S1 on #169).
	var ended []string
	if err == nil && unpauses(in) {
		ended = append(ended, id)
		for _, k := range before {
			if _, live := g.grants[k]; !live && k != id {
				ended = append(ended, k)
			}
		}
		sort.Strings(ended[1:])
	}
	g.mu.Unlock()
	if err != nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: err.Error()}
	}
	for _, k := range ended {
		g.unpaused(k)
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: id}
}

// unpauses reports an intent that ends a grant's pause: the owner resumed
// or revoked it.
func unpauses(in journal.Intent) bool {
	if in.Action == journal.ActionGrantRevoke {
		return true
	}
	s, err := parseSpec(in)
	return in.Action == journal.ActionGrantChange && err == nil && s.Resume != ""
}

// unpaused calls Config.Unpaused outside the gate's lock; a panic in it is
// logged and changes nothing.
func (g *Gate) unpaused(id string) {
	if g.cfg.Unpaused == nil {
		return
	}
	defer func() {
		if recover() != nil && g.cfg.Logf != nil {
			g.cfg.Logf("grants: unpause hook failed")
		}
	}()
	g.cfg.Unpaused(id)
}

// Reconcile: grant state is rebuilt only from succeeded records, so an
// attempt a crash interrupted left nothing behind.
func (g *Gate) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "broker state is rebuilt from succeeded records only"}
}

// applyLocked applies a grant intent to the live grants. Live execution
// and replay share it.
func (g *Gate) applyLocked(in journal.Intent) (string, error) {
	switch in.Action {
	case journal.ActionGrantChange:
		s, err := parseSpec(in)
		if err != nil {
			return "", err
		}
		if err := g.validateLocked(s); err != nil {
			return "", err
		}
		if s.Resume != "" {
			g.grants[s.Resume].Paused = false
			return s.Resume, nil
		}
		id := g.grantIDLocked(in.ID)
		g.grants[id] = &Grant{ID: id, Spec: s}
		return id, nil
	case journal.ActionGrantPause, journal.ActionGrantRevoke:
		gr := g.grants[in.GrantRef]
		if gr == nil {
			return "", errors.New("no grant " + clip(in.GrantRef))
		}
		if in.Action == journal.ActionGrantPause {
			gr.Paused = true
			return gr.ID, nil
		}
		delete(g.grants, gr.ID)
		if gr.Spec.Rule == nil {
			// A revoked connection takes its pre-allowances with it, so
			// a later grant cannot silently revive them.
			for k, x := range g.grants {
				if x.Spec.Rule != nil && x.Spec.Account == gr.Spec.Account {
					delete(g.grants, k)
				}
			}
		}
		return gr.ID, nil
	case journal.ActionEvidence:
		d, err := parseDestination(in)
		if err != nil {
			return "", err
		}
		g.evidence = d
		return "evidence", nil
	}
	return "", errors.New("not a grant action")
}

// grantIDLocked numbers grants by their intent's place among all grant
// intents ever submitted, so replay assigns the IDs live execution did
// whatever order attempts finished in.
func (g *Gate) grantIDLocked(intentID string) string {
	n := 0
	for _, st := range g.eng.List() {
		if st.Intent.Account == journal.BrokerAccount && st.Intent.Action == journal.ActionGrantChange {
			n++
		}
		if st.Intent.ID == intentID {
			break
		}
	}
	return fmt.Sprintf("G%d", n)
}

// sameItem compares everything the owner saw or the tier was judged on.
func sameItem(a, b owner.Item) bool {
	fa, fb := a.Facts, b.Facts
	return a.Object == b.Object && a.Recipient == b.Recipient && a.Amount == b.Amount &&
		a.UndoWindow == b.UndoWindow && a.Detail == b.Detail && a.UndoBy == b.UndoBy && a.Unverified == b.Unverified &&
		fa.Kind == fb.Kind && fa.Verb == fb.Verb && fa.RecipientChecked == fb.RecipientChecked &&
		fa.NoRecipient == fb.NoRecipient && fa.RecipientExists == fb.RecipientExists &&
		fa.RecipientByOwner == fb.RecipientByOwner && fa.RecipientSince.Equal(fb.RecipientSince) &&
		fa.RecipientAutoAdded == fb.RecipientAutoAdded && fa.HasAmount == fb.HasAmount && fa.Amount == fb.Amount
}

// stricter returns the verb of the stricter class; the declared verb
// (b) wins a tie. An unknown verb is strictest, so it fails closed.
func stricter(a, b string) string {
	ca, oka := verb.ClassOf(a)
	cb, okb := verb.ClassOf(b)
	switch {
	case !oka:
		return a
	case !okb:
		return b
	case ca > cb:
		return a
	}
	return b
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
