package grants

import (
	"context"
	"errors"
	"fmt"
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
	// DefaultTick is how often Run sends batched requests and releases
	// auto-replies whose undo window has passed. Items asked within one
	// tick share one request and one code (CH-10).
	DefaultTick = 10 * time.Second
	// MaxBatch is the owner channel's limit on items per request.
	MaxBatch = 20
	// window is the period scope bounds count over (ADP-9: a daily rate).
	window = 24 * time.Hour
)

// Owner is the owner channel (owner.Channel) as the gate uses it.
type Owner interface {
	Request(items []owner.Item, ttl time.Duration) (string, error)
	Tier(owner.Facts) owner.Tier
	QueueAutoReply(owner.AutoReply) (owner.QueueResult, error)
	DueAutoReplies() []owner.Queued
	Notify(text string) error
}

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
	// Executors are the adapter executors registered with the engine. A
	// grant may name only these.
	Executors []string
	// Verifiers read source fields, by account. An account without one
	// gets unverified approval items, which are always high risk, and no
	// pre-allowance can match on it.
	Verifiers map[string]Verifier
	// LocalUI says a local confirmation page exists (P2-2). New or wider
	// grants need it (CH-3); without it they are refused outright rather
	// than asking the owner for a code that could not complete them.
	LocalUI bool
	// Isolated reports whether origin is a reply-composer machine built
	// as ADP-11 requires (fresh, thread messages only, no recall, no
	// egress). Nil: none is, so reply rules never match.
	Isolated func(origin string) bool
	Fresh    time.Duration
	Now      func() time.Time
	Logf     func(format string, args ...any)
}

// Gate is the approval policy. It is the engine's journal.Policy, the
// executor of grant intents, the guest plane's Effects, and the owner
// channel's Decide and Narrow hooks.
type Gate struct {
	cfg       Config
	executors map[string]bool

	mu        sync.Mutex
	eng       *journal.Engine
	own       Owner
	grants    map[string]*Grant
	waiting   map[string]*wait
	batch     []string
	decided   map[string]decision
	confirmed map[string]bool
	failed    map[string]string
	wg        sync.WaitGroup
}

// wait is an intent waiting on the owner.
type wait struct {
	item    owner.Item
	local   bool   // also needs local confirmation
	request string // owner request ID, "" while batched
	reply   string // queued auto-reply ID
	sendAt  time.Time
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
	g := &Gate{cfg: cfg, executors: map[string]bool{}, grants: map[string]*Grant{},
		waiting: map[string]*wait{}, decided: map[string]decision{}, confirmed: map[string]bool{}, failed: map[string]string{}}
	for _, e := range cfg.Executors {
		g.executors[e] = true
	}
	return g
}

// Attach connects the engine and the owner channel (nil if there is
// none), rebuilds grants from the journal, and closes every intent a
// restart left pending. No approval request survives a restart (owner
// O7), so an intent still pending has no live request; it is denied
// with the reason, and the agent asks again under a new request_id.
// Call it after journal.Open and before anything submits.
func (g *Gate) Attach(eng *journal.Engine, own Owner) {
	g.mu.Lock()
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
	var stale []string
	for _, st := range eng.List() {
		if st.State == journal.Pending {
			stale = append(stale, st.Intent.ID)
			g.decided[st.Intent.ID] = decision{why: "the box restarted before it was approved; ask again with a new request_id", at: g.cfg.Now()}
		}
	}
	g.mu.Unlock()
	for _, id := range stale {
		if _, err := eng.Authorize(context.Background(), id); err != nil {
			g.cfg.Logf("grants: closing %s after restart: %v", id, err)
		}
		g.mu.Lock()
		delete(g.decided, id)
		g.mu.Unlock()
	}
}

// Route names the executor for effects on account: the live adapter
// grant's, or this package's for the broker account. False: no grant.
func (g *Gate) Route(account string) (string, bool) {
	if account == journal.BrokerAccount {
		return ExecutorName, true
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
	reply *owner.AutoReply
}

// evaluate decides what in needs. Only structural faults deny: no grant,
// an undeclared operation, a malformed grant, or narrowing from anyone
// but the owner. Every irreversible effect that no pre-allowance covers
// is asked of the owner (REV-2).
func (g *Gate) evaluate(ctx context.Context, in journal.Intent) verdict {
	if in.Account == journal.BrokerAccount {
		return g.evaluateBroker(in)
	}
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
		return verdict{kind: deny, why: "no grant connects account " + clip(in.Account)}
	}
	if in.Executor != spec.Executor {
		return verdict{kind: deny, why: "the executor is not the one the grant connects"}
	}
	v, ok := spec.Ops[in.Action]
	if !ok {
		return verdict{kind: deny, why: fmt.Sprintf("operation %s is not declared for %s (ADP-1)", clip(in.Action), clip(in.Account))}
	}
	cls, _ := verb.ClassOf(v)
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
	if cls == verb.Irreversible && verified {
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

// approvalItem is the line the owner approves (CH-12): source fields when
// verified, otherwise the intent's own operation and recipients, which are
// what will run, marked unverified and high risk (CH-10).
func approvalItem(in journal.Intent, v string, cls verb.Class, ver Verified, verified bool) owner.Item {
	it := owner.Item{Object: in.Action + " on " + in.Account + ", unverified", Recipient: strings.Join(in.Recipients, ", ")}
	if verified {
		it = ver.Item
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
		if g.cfg.Isolated == nil || !g.cfg.Isolated(in.Origin) || !v.ThreadVerified || v.Attachments || f.HasAmount || strings.TrimSpace(body) == "" {
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
func (g *Gate) evaluateBroker(in journal.Intent) verdict {
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
	case journal.ActionGrantPause, journal.ActionGrantRevoke:
		if in.Origin != OriginOwner {
			return verdict{kind: deny, why: "only the owner pauses or revokes a grant"}
		}
		g.mu.Lock()
		gr := g.grants[in.GrantRef]
		g.mu.Unlock()
		if gr == nil {
			return verdict{kind: deny, why: "no grant " + clip(in.GrantRef)}
		}
		return verdict{kind: allow}
	}
	return verdict{kind: deny, why: "broker action " + clip(in.Action) + " is not handled here"}
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
	v := g.evaluate(ctx, in)
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
	g.mu.Unlock()
	switch {
	case held, waiting:
		g.annotate(&st)
		return st, nil
	case decided:
		return g.eng.Authorize(ctx, id)
	}
	v := g.evaluate(ctx, st.Intent)
	switch v.kind {
	case deny, allow:
		return g.eng.Authorize(ctx, id)
	case ask:
		g.mu.Lock()
		if g.waiting[id] == nil {
			g.waiting[id] = &wait{item: v.item, local: v.local}
			g.batch = append(g.batch, id)
		}
		delete(g.failed, id)
		g.mu.Unlock()
	case autoReply:
		g.queueReply(id, v)
	}
	g.annotate(&st)
	return st, nil
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
	if d, ok := g.decided[id]; ok && d.approved && d.local && !g.confirmed[id] {
		st.Permission.Reason = "approved by code; waiting for the owner to confirm on the box's local page"
	} else if w := g.waiting[id]; w != nil && w.reply != "" {
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

// Flush sends batched items: one request per tier, at most MaxBatch
// items each, so a high-risk item does not raise the code needed for
// low-risk ones (CH-10). Run calls it every tick.
func (g *Gate) Flush() {
	g.mu.Lock()
	ids, own := g.batch, g.own
	g.batch = nil
	var low, high []owner.Item
	for _, id := range ids {
		w := g.waiting[id]
		if w == nil {
			continue
		}
		if own != nil && own.Tier(w.item.Facts) == owner.Low {
			low = append(low, w.item)
		} else {
			high = append(high, w.item)
		}
	}
	g.mu.Unlock()
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
	g.mu.Lock()
	w := g.waiting[d.Ref]
	if w == nil && (d.Approved || g.eng == nil) {
		g.mu.Unlock()
		return
	}
	if w != nil && d.Request != w.request && d.Request != w.reply {
		g.mu.Unlock()
		return
	}
	var item owner.Item
	local := false
	if w != nil {
		item, local = w.item, w.local
	}
	delete(g.waiting, d.Ref)
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

// ConfirmLocal records the owner's confirmation on the local page for a
// grant intent (CH-3). The local UI (P2-2) calls it after showing
// Describe; the code and the confirmation may come in either order.
func (g *Gate) ConfirmLocal(id string) error {
	st, err := g.eng.Get(id)
	if err != nil {
		return err
	}
	if st.State != journal.Pending || st.Intent.Account != journal.BrokerAccount || st.Intent.Action != journal.ActionGrantChange {
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
		if st.State == journal.Succeeded && st.Intent.Executor == ExecutorName && own != nil && len(st.Attempts) > 0 {
			if gid := st.Attempts[len(st.Attempts)-1].Evidence; gid != "" {
				_ = own.Notify(fmt.Sprintf("Added %s. Text PAUSE %s or REVOKE %s to stop it.", gid, gid, gid))
			}
		}
	}()
}

// Tick sends batched requests and releases auto-replies whose undo window
// has passed (ADP-11). The owner channel holds them while STOPped.
func (g *Gate) Tick() {
	g.Flush()
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

func sameItem(a, b owner.Item) bool {
	return a.Object == b.Object && a.Recipient == b.Recipient && a.Amount == b.Amount &&
		a.UndoWindow == b.UndoWindow && a.Facts.Verb == b.Facts.Verb && a.Facts.Kind == b.Facts.Kind
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
