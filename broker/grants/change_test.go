package grants

// The gate delegates meta.change.* to the change pipeline (change C8) and
// never turns an unanswered owner request into a decline (change C7).
// REQ: OP-3, OP-5, CHG-2, CHG-3, CHG-6, CH-10, CH-12

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/update"
)

// The pipeline is what the gate expects.
var _ Changes = (*change.Pipeline)(nil)

// refuser answers every security probe as the fixture expects.
type refuser struct{}

func (refuser) Run(context.Context, change.Tree, change.Probe) ([]byte, error) {
	return []byte("refused"), nil
}

// changeRig is a rig whose gate fronts a real change pipeline.
func changeRig(t *testing.T) (*rig, *change.Pipeline) {
	t.Helper()
	p, err := change.New(change.Config{Store: &change.MemStore{}, Evaluator: refuser{},
		Initial: change.Tree{"skills/greet": []byte("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddSecurityCase(change.Case{ID: "sec-1", Class: change.ClassSkill, Input: []byte("probe"), Expect: []byte("refused")}); err != nil {
		t.Fatal(err)
	}
	r := newRigExecs(t, func(c *Config) { c.Changes = p }, map[string]journal.Executor{change.Executor: p})
	p.Attach(r.g)
	return r, p
}

func signed(t *testing.T, version string, images map[string][]byte) update.Verified {
	t.Helper()
	root := update.Root{Keys: map[string]ed25519.PublicKey{}, Threshold: 2}
	var pks []ed25519.PrivateKey
	for _, id := range []string{"k1", "k2"} {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		root.Keys[id] = pub
		pks = append(pks, pk)
	}
	dg := map[string]string{}
	for p, b := range images {
		dg[p] = update.Digest(b)
	}
	meta, _ := json.Marshal(update.Release{Version: version, Security: true, Images: dg})
	v, err := update.Verify(root, meta, []update.Signature{{KeyID: "k1", Sig: ed25519.Sign(pks[0], meta)},
		{KeyID: "k2", Sig: ed25519.Sign(pks[1], meta)}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// C8: a change only the owner may allow becomes a high-tier owner request
// with a broker-rendered line; once approved it adopts. What the pipeline
// allows on its own runs at once, and what it refuses is denied.
func TestChangeIntentsGoThroughThePipeline(t *testing.T) {
	r, p := changeRig(t)
	ctx := context.Background()
	rep, err := p.Propose(ctx, change.Candidate{Source: change.Local, Files: change.Tree{"skills/new": []byte("x")}, Claim: "approve me"})
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	want := owner.Item{Ref: "chg:" + rep.ID + ":adopt", Object: "a learned skill, not tested yet", Undoable: true,
		Facts: owner.Facts{Kind: owner.GrantChange, Verb: "adopt", NoRecipient: true}}
	if len(items) != 1 || !sameItem(items[0], want) || items[0].Ref != want.Ref {
		t.Fatalf("owner item: %+v", items)
	}
	if r.own.Tier(items[0].Facts) != owner.High {
		t.Fatal("a change request is not high tier")
	}
	r.decide(true, "owner")
	if got := string(p.Files("skills")["skills/new"]); got != "x" {
		t.Fatalf("approved change not adopted: %q", got)
	}
	as := p.Adoptions()
	if len(as) != 1 {
		t.Fatal(as)
	}

	// The owner's UNDO and turning learning off need no code.
	if err := p.Revert(ctx, as[0].Short, change.OriginOwner); err != nil {
		t.Fatal(err)
	}
	if err := p.SetAutoAdopt(ctx, false); err != nil {
		t.Fatal(err)
	}
	// Turning it on asks.
	n := r.own.count()
	if err := p.SetAutoAdopt(ctx, true); !errors.Is(err, change.ErrPending) {
		t.Fatal(err)
	}
	r.g.Flush()
	if _, items := r.own.last(t); r.own.count() != n+1 || items[0].Object != "learning without asking" || items[0].Facts.Verb != "turn on" {
		t.Fatalf("%+v", items)
	}
	// A refusal from the pipeline is a denial: no such adoption.
	st := r.submit(journal.Intent{ID: "chg:c77:revert:n1:owner", Origin: change.OriginOwner, Account: journal.BrokerAccount,
		Action: change.ActionRevert, Executor: change.Executor, Params: map[string]any{"adoption": "c77", "why": "owner"}})
	if st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "no active adoption") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
}

// C14(e), GR14: a guest never reaches a change intent, whatever it names.
func TestGuestCannotSubmitChangeIntents(t *testing.T) {
	r, _ := changeRig(t)
	st := r.submit(journal.Intent{ID: "chg:policy:n1:auto_adopt:off", Origin: "guest:agent", Account: journal.BrokerAccount,
		Action: change.ActionPolicyOff, Executor: change.Executor, Params: map[string]any{"setting": "auto_adopt", "value": "off"}})
	if st.State != journal.Denied || st.Permission.Reason != "broker actions are not available to agents" {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
}

// Without a pipeline the gate denies change intents rather than guessing.
func TestChangeIntentsDeniedWithoutPipeline(t *testing.T) {
	exec := &fakeExec{ran: map[string]int{}}
	r := newRigExecs(t, nil, map[string]journal.Executor{change.Executor: exec})
	st := r.submit(journal.Intent{ID: "chg:policy:n1:auto_adopt:off", Origin: "owner", Account: journal.BrokerAccount,
		Action: change.ActionPolicyOff, Executor: change.Executor, Params: map[string]any{"setting": "auto_adopt", "value": "off"}})
	if st.State != journal.Denied || exec.runs("chg:policy:n1:auto_adopt:off") != 0 {
		t.Fatal(st.State)
	}
}

// C7: an owner request for a change that expires (or is voided, or is
// dropped by a restart) leaves the intent pending and records no decline;
// the owner's NO is a decline and is repeated in the digest.
func TestUnansweredChangeIsNotADecline(t *testing.T) {
	r, p := changeRig(t)
	ctx := context.Background()
	rep, err := p.ProposeRelease(ctx, signed(t, "3.0", map[string][]byte{"host-image/release": []byte("h")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	id := "chg:" + rep.ID + ":adopt"
	r.g.Flush()
	if _, items := r.own.last(t); items[0].Object != "security update 3.0" || items[0].Facts.Verb != "install" || items[0].Undoable {
		t.Fatalf("%+v", items[0])
	}
	r.decide(false, "expired")
	if st := r.state(id); st.State != journal.Pending {
		t.Fatalf("an expired request was closed: %s %q", st.State, st.Permission.Reason)
	}
	if d := p.Digest(); len(d) != 0 {
		t.Fatalf("an expired request reads as a decline: %q", d)
	}
	// A restart's drop of an intent this run never asked about is not a
	// decline either.
	r.g.Decide(owner.Decision{Request: "old", Item: 1, Ref: id, Why: "restart"})
	r.g.Wait()
	if st := r.state(id); st.State != journal.Pending {
		t.Fatal(st.State)
	}

	rep, err = p.ProposeRelease(ctx, signed(t, "3.1", map[string][]byte{"host-image/release": []byte("i")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	r.g.Flush()
	r.decide(false, "owner")
	if st := r.state("chg:" + rep.ID + ":adopt"); st.State != journal.Denied {
		t.Fatal(st.State)
	}
	if d := p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "You declined security update 3.1;") {
		t.Fatalf("%q", d)
	}
}
