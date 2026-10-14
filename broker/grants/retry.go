package grants

import (
	"context"
	"errors"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/verb"
)

// RetryLine is what the owner is asked when they text RETRY for a parked
// intent (OP-2).
type RetryLine struct {
	// Shown is the item the owner approves: the effect's verified line,
	// as the gate would ask it now, marked as a retry. Its tier is the
	// one its facts give, except that money is always high (MoneyRetry).
	Shown owner.Item
	// Base is the line the dispatch recheck compares (sameItem).
	Base owner.Item
	// Local: the line is approved only on the local page.
	Local bool
}

// RetryItem is the line for an owner retry of parked intent p. It is
// built as the gate builds an ask (evaluate), from the account's verifier
// and never from the intent's own claims: an effect the gate would refuse
// now, or that its verifier cannot read, is shown unverified and so high
// risk. object names, in fixed words, a broker-account effect, which has
// no recipient and no verifier.
func (g *Gate) RetryItem(ctx context.Context, p journal.ParkedIntent, object string) RetryLine {
	in := p.Intent
	var l RetryLine
	v := g.evaluate(ctx, journal.PhaseDispatch, in)
	switch {
	case v.kind == ask || v.kind == autoReply:
		l = RetryLine{Shown: v.shown(), Base: v.item, Local: v.local}
	case v.kind == allow && in.Account == journal.BrokerAccount:
		it := owner.Item{Ref: in.ID, Object: object, Facts: owner.Facts{Verb: "Retry", NoRecipient: true}}
		l = RetryLine{Shown: it, Base: it}
	case v.kind == allow:
		it := g.verifiedLine(ctx, in)
		l = RetryLine{Shown: it, Base: it}
	default:
		it := approvalItem(in, in.Action, verb.Irreversible, Verified{}, false)
		l = RetryLine{Shown: it, Base: it}
	}
	l.Shown.Retried = p.Dispatched
	if l.Shown.Facts.HasAmount || l.Shown.Amount != "" {
		l.Shown.Facts.Kind = owner.MoneyRetry
	}
	return l
}

// verifiedLine is the line of an effect the gate allows without asking
// (a reversible verb or a pre-allowance): the granted verb and what the
// account's verifier reads, unverified if it cannot.
func (g *Gate) verifiedLine(ctx context.Context, in journal.Intent) owner.Item {
	g.mu.Lock()
	var spec Spec
	if ag := g.adapterLocked(in.Account); ag != nil {
		spec = ag.Spec
	}
	g.mu.Unlock()
	v := stricter(spec.Ops[in.Action], g.cfg.Declared[spec.Executor][in.Action])
	cls, ok := verb.ClassOf(v)
	if !ok {
		v, cls = in.Action, verb.Irreversible
	}
	var ver Verified
	verified := false
	if vf := g.cfg.Verifiers[in.Account]; vf != nil {
		var err error
		if ver, err = vf.Verify(ctx, in); err == nil {
			verified = true
		} else {
			g.cfg.Logf("grants: verifying %s for a retry: %v", in.ID, err)
		}
	}
	it := approvalItem(in, v, cls, ver, verified)
	it.UndoWindow = 0
	if f, ok := g.forms[in.Executor][in.Action]; ok && cls == verb.Irreversible {
		it.UndoWindow = f.Window
	}
	return it
}

// ErrRetryNotConfirmed refuses a retry of a local-page line that was not
// approved on the page showing it.
var ErrRetryNotConfirmed = errors.New("grants: the retry was not approved on the Wi-Fi page")

// Retry runs parked attempt parked of intent id again on the owner's
// approval of l (OP-2). The approval is recorded as Decide records an
// answered ask, so the engine's dispatch recheck passes only while the
// line is unchanged and the approval fresh, and only for the next
// attempt; it is spent once the retry ends. page reports that a local
// line was approved on the page showing it.
func (g *Gate) Retry(ctx context.Context, id string, parked int, l RetryLine, page bool) (journal.Status, error) {
	if l.Local && !page {
		return journal.Status{}, ErrRetryNotConfirmed
	}
	tries, err := g.tries(id)
	if err != nil {
		return journal.Status{}, err
	}
	g.mu.Lock()
	eng := g.eng
	g.decided[id] = decision{approved: true, why: "owner", asked: true, at: g.cfg.Now(), item: l.Base, local: l.Local, tries: tries}
	if l.Local {
		g.confirmed[id] = true
	}
	g.mu.Unlock()
	defer g.spend(id)
	return eng.Retry(ctx, id, parked)
}
