package grants

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
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
	Tier(owner.Facts) owner.Tier
	Active(within time.Duration) bool
	QueueAutoReply(owner.AutoReply) (owner.QueueResult, error)
	DueAutoReplies() []owner.Queued
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
	// Changes decides meta.change.* intents. Nil: they are denied.
	Changes Changes
	// Loops decides meta.loops.* intents. Nil: they are denied.
	Loops Loops
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

	mu        sync.Mutex
	eng       *journal.Engine
	own       Owner
	grants    map[string]*Grant
	waiting   map[string]*wait
	batch     []string
	first     time.Time // when the batch's first item arrived
	last      time.Time // when its latest item arrived
	sent      []time.Time
	decided   map[string]decision
	confirmed map[string]bool
	failed    map[string]string
	// carried holds the intents a restart left pending until the owner
	// channel's Boot hands back what it can re-issue (Reissue); reissue
	// is what waits for STOP to end before it is asked again.
	carried map[string]bool
	reissue []owner.Carried
	wg      sync.WaitGroup
}

// wait is an intent waiting on the owner.
type wait struct {
	item    owner.Item
	local   bool   // also needs local confirmation
	onlyUI  bool   // approvable only on the local page (owner.SMSApprovable)
	request string // owner request ID, "" while batched
	reply   string // queued auto-reply ID
	sendAt  time.Time
	expires time.Time // a re-issued item's original expiry; zero otherwise
}

// decision is the owner's answer on one intent.
type decision struct {
	approved bool
	why      string
	at       time.Time
	item     owner.Item
	local    bool
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
		carried: map[string]bool{}}
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
	if in.Account == journal.BrokerAccount {
		return g.evaluateBroker(ctx, phase, in)
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
	if cls == verb.Reversible {
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
			Facts: owner.Facts{Kind: owner.Ordinary, Verb: "reset", NoRecipient: true}}}
	case journal.ActionGrantPause, journal.ActionGrantRevoke:
		if in.Origin != OriginOwner {
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
	return nil
}

func (g *Gate) isConfirmed(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.confirmed[id]
}

// Submit, Dispatch, and Get pass through to the engine; with Authorize
// they are the guest plane's Effects.
func (g *Gate) Submit(in journal.Intent) (journal.Status, error) { return g.eng.Submit(in) }

func (g *Gate) Dispatch(ctx context.Context, id string) (journal.Status, error) {
	return g.eng.Dispatch(ctx, id)
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
		onlyUI := !owner.SMSApprovable(v.item) || v.hold
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
		own := g.own
		g.mu.Unlock()
		if fresh && v.hold && own != nil {
			// Arbitrator Q1 on #48: one fixed line, no code.
			_ = own.Inform("Waiting for your confirmation on the box's local page, or your recovery key.")
		}
		if fresh && onlyUI && !v.hold && own != nil {
			// Recipients that cannot be shown in full are never approved
			// by text (CH-10, CH-12).
			n := len(strings.Split(v.item.Recipient, ","))
			_ = own.Inform(fmt.Sprintf("An action for %d recipients needs your approval on the box's Wi-Fi page.", n))
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
	} else if w != nil && w.reply != "" {
		st.Permission.Reason = "auto-reply queued; it sends at " + w.sendAt.UTC().Format("15:04") + " UTC unless the owner cancels it"
	} else if w != nil {
		st.Permission.Reason = "waiting for the owner's approval"
	} else if f := g.failed[id]; f != "" {
		st.Permission.Reason = "could not ask the owner (" + f + "); retry later"
	}
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
		g.failed[id] = err.Error()
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
// and within RequestsPerHour.
func (g *Gate) flushDue() {
	now := g.cfg.Now()
	g.mu.Lock()
	if len(g.batch) == 0 {
		g.mu.Unlock()
		return
	}
	urgent := false
	if g.cfg.Urgent != nil {
		for _, id := range g.batch {
			if w := g.waiting[id]; w != nil && g.cfg.Urgent(w.item) {
				urgent = true
			}
		}
	}
	own := g.own
	keep := g.sent[:0]
	for _, t := range g.sent {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	g.sent = keep
	budget := len(g.sent) < g.cfg.RequestsPerHour
	ripe := now.Sub(g.first) >= g.cfg.Coalesce || now.Sub(g.last) >= g.cfg.CoalesceIdle
	g.mu.Unlock()
	active := own != nil && own.Active(activeFor)
	quiet := g.cfg.Quiet != nil && g.cfg.Quiet(now)
	if urgent || (!quiet && (active || (ripe && budget))) {
		g.Flush()
	}
}

// Flush sends batched items now: one request per tier, at most MaxBatch
// items each, so a high-risk item does not raise the code needed for
// low-risk ones (CH-10). Each request text counts toward RequestsPerHour.
func (g *Gate) Flush() {
	now := g.cfg.Now()
	g.mu.Lock()
	ids, own := g.batch, g.own
	stopped := g.eng != nil && g.eng.Stopped()
	g.batch = nil
	var low, high, again []owner.Item
	var ttls []time.Duration
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
			default:
				again = append(again, w.item)
				ttls = append(ttls, w.expires.Sub(now))
			}
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
	if len(again) > 0 {
		reqs := make([]string, len(again))
		err := errors.New("no owner channel")
		if own != nil {
			reqs, err = own.RequestEach(again, ttls)
		}
		g.mu.Lock()
		if slices.ContainsFunc(reqs, func(r string) bool { return r != "" }) {
			g.sent = append(g.sent, g.cfg.Now())
		}
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
				g.failed[it.Ref] = err.Error()
			}
		}
		g.mu.Unlock()
	}
	for _, items := range [][]owner.Item{low, high} {
		for len(items) > 0 {
			n := min(len(items), MaxBatch)
			chunk := items[:n]
			items = items[n:]
			req := ""
			err := errors.New("no owner channel")
			if own != nil {
				req, err = own.Request(chunk, 0)
			}
			g.mu.Lock()
			if err == nil {
				g.sent = append(g.sent, g.cfg.Now())
			}
			for _, it := range chunk {
				w := g.waiting[it.Ref]
				if w == nil {
					continue
				}
				if err != nil {
					// Retrying the request_id asks again.
					delete(g.waiting, it.Ref)
					g.failed[it.Ref] = err.Error()
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
	g.decided[d.Ref] = decision{approved: d.Approved, why: why, at: g.cfg.Now(), item: item, local: local}
	wait := d.Approved && local && !g.confirmed[d.Ref]
	g.mu.Unlock()
	if !wait {
		g.settle(d.Ref)
	}
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
		(st.Intent.Action != journal.ActionGrantChange && !(changeAction(st.Intent.Action) &&
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
		if g.cfg.Changes != nil && changeAction(st.Intent.Action) && st.Intent.Account == journal.BrokerAccount &&
			(st.State == journal.Denied || st.State == journal.Succeeded || st.State == journal.NotApplied) {
			// Only the owner's NO is a decline; a refusal at the recheck
			// (stale approval, changed state) is not (change C7).
			g.cfg.Changes.Decided(ctx, st.Intent, !d.approved && d.why == "owner")
		}
		if st.State == journal.Succeeded && st.Intent.Executor == ExecutorName && own != nil && len(st.Attempts) > 0 {
			if gid := st.Attempts[len(st.Attempts)-1].Evidence; gid != "" {
				_ = own.Inform(fmt.Sprintf("Added %s. Text PAUSE %s or REVOKE %s to stop it.", gid, gid, gid))
			}
		}
	}()
}

// Tick sends batched requests and releases auto-replies whose undo window
// has passed (ADP-11). The owner channel holds them while STOPped.
func (g *Gate) Tick() {
	g.reissueDue()
	g.flushDue()
	g.mu.Lock()
	own := g.own
	g.mu.Unlock()
	if own == nil {
		return
	}
	for _, q := range own.DueAutoReplies() {
		g.Decide(owner.Decision{Request: q.ID, Item: 1, Ref: q.Reply.Ref, Approved: true, Why: "undo window passed"})
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
	defer g.mu.Unlock()
	id, err := g.applyLocked(in)
	if err != nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: err.Error()}
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: id}
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
