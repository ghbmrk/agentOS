package grants

import (
	"context"
	"errors"
	"strings"

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
	// rep is what Shown says of the same send under other requests:
	// the approval covers only those (decision.covers, Security B10).
	rep repeat
}

// RetryItem is the line for an owner retry of parked intent p. It is
// built as the gate builds an ask (evaluate), from the account's verifier
// and never from the intent's own claims: an effect the gate would refuse
// now, or that its verifier cannot read, is shown unverified and so high
// risk. object names, in fixed words, a broker-account effect, which has
// no recipient and no verifier.
//
// For an effect a check proved was not done (p.NotDone) the line is the
// effect's ordinary ask at the tier its facts give: it cannot go twice,
// so it carries no "may go twice" warning and money is not raised to
// MoneyRetry beyond what CH-10 gives it. The exception is a near
// resubmission the engine cannot match (sentSince): then the line warns
// as a parked one does.
func (g *Gate) RetryItem(ctx context.Context, p journal.ParkedIntent, object string) RetryLine {
	in := p.Intent
	var l RetryLine
	v := g.evaluate(ctx, journal.PhaseDispatch, in)
	switch {
	case v.kind == ask || v.kind == autoReply:
		l = RetryLine{Shown: v.shown(), Base: v.item, Local: v.local, rep: v.rep}
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
	if p.NotDone && !g.sentSince(ctx, p) {
		return l
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
	return g.approved(id, l, page, func(eng *journal.Engine) (journal.Status, error) { return eng.Retry(ctx, id, parked) })
}

// Resend sends intent id again on the owner's approval of l, after a
// check proved its attempt n was not done and the engine's own resend
// was refused (journal.Engine.NotResent, OP-2). The approval is recorded
// and spent as for Retry.
func (g *Gate) Resend(ctx context.Context, id string, n int, l RetryLine, page bool) (journal.Status, error) {
	return g.approved(id, l, page, func(eng *journal.Engine) (journal.Status, error) { return eng.Resend(ctx, id, n) })
}

// approved runs run with the owner's approval of l recorded for id, as
// Decide records an answered ask, and spends it after.
func (g *Gate) approved(id string, l RetryLine, page bool, run func(*journal.Engine) (journal.Status, error)) (journal.Status, error) {
	if l.Local && !page {
		return journal.Status{}, ErrRetryNotConfirmed
	}
	tries, err := g.tries(id)
	if err != nil {
		return journal.Status{}, err
	}
	g.mu.Lock()
	eng := g.eng
	g.decided[id] = decision{approved: true, why: "owner", asked: true, at: g.cfg.Now(), item: l.Base, rep: l.rep, local: l.Local, tries: tries}
	if l.Local {
		g.confirmed[id] = true
	}
	g.mu.Unlock()
	defer g.spend(id)
	return run(eng)
}

// sentSince reports, for an effect a check proved was not done, another
// send on its account and action that went or may have gone since its
// not-done attempt was dispatched, or that is requested and waiting for
// approval or dispatch (journal Queued, R9b), of the same record to the same
// recipients: a resubmission whose params or recipients differ from p's
// in some byte, which the engine's exact effect fingerprint does not
// match (journal A19), so resending p may send the effect twice. Records
// and recipients are compared as the account's verifier reads them, or,
// without one, as the intents name them with recipients' case folded.
// An erased send names no record and counts. An effect that names no
// record matches nothing.
func (g *Gate) sentSince(ctx context.Context, p journal.ParkedIntent) bool {
	g.mu.Lock()
	eng := g.eng
	g.mu.Unlock()
	if eng == nil {
		return false
	}
	in := p.Intent
	rec, rcpt := g.sendKey(ctx, in)
	if rec == "" {
		return false
	}
	for _, u := range eng.InUse(in.Account, in.Action, p.Dispatched) {
		if !u.Started || u.Intent.ID == in.ID {
			continue
		}
		if u.Erased {
			return true
		}
		if r2, c2 := g.sendKey(ctx, u.Intent); r2 == rec && sameSet(c2, rcpt) {
			return true
		}
	}
	for _, q := range eng.Queued(in.Account, in.Action) {
		if q.ID == in.ID {
			continue
		}
		if r2, c2 := g.sendKey(ctx, q); r2 == rec && sameSet(c2, rcpt) {
			return true
		}
	}
	return false
}

// sendKey is the record an intent acts on and its recipients, as the
// account's verifier reads them, or as the intent names them (case
// folded) when the verifier is missing or cannot read it.
func (g *Gate) sendKey(ctx context.Context, in journal.Intent) (string, []string) {
	k := g.sendID(ctx, in)
	return k.rec, k.rcpt
}

// sendKeyed is sendKey with the record's thread (Verified.Thread), which
// only a verifier gives.
type sendKeyed struct {
	rec    string
	rcpt   []string
	thread []string
}

func (g *Gate) sendID(ctx context.Context, in journal.Intent) sendKeyed {
	if vf := g.cfg.Verifiers[in.Account]; vf != nil {
		if v, err := vf.Verify(ctx, in); err == nil && v.Record != "" {
			return sendKeyed{v.Record, fold(v.Recipients), v.Thread}
		}
	}
	rec, _ := in.Params[ParamRecord].(string)
	return sendKeyed{rec: rec, rcpt: fold(in.Recipients)}
}

func fold(rs []string) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = strings.ToLower(strings.TrimSpace(r))
	}
	return out
}
