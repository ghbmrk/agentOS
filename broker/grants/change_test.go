package grants

// The gate delegates meta.change.* to the change pipeline (change C8) and
// never turns an unanswered owner request into a decline (change C7).
// REQ: OP-3, OP-5, CHG-2, CHG-3, CHG-6, CH-10, CH-12

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
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

func signed(t *testing.T, version int64, images map[string][]byte) *update.Verified {
	return updatetest.Release(t, version, true, images)
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
	want := owner.Item{Ref: "chg:" + rep.ID + ":adopt", Object: "a learned skill", Detail: "not tested on past tasks yet", UndoBy: "can be undone later",
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
	rep, err := p.ProposeRelease(ctx, signed(t, 30, map[string][]byte{"host-image/release": []byte("h")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	id := "chg:" + rep.ID + ":adopt"
	r.g.Flush()
	if _, items := r.own.last(t); items[0].Object != "security update 30" || items[0].Facts.Verb != "install" || items[0].UndoBy != "" {
		t.Fatalf("%+v", items[0])
	}
	r.decide(false, "expired")
	if st := r.state(id); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "lapsed, not declined") {
		t.Fatalf("an expired request: %s %q", st.State, st.Permission.Reason)
	}
	if d := p.Digest(); len(d) != 0 {
		t.Fatalf("an expired request reads as a decline: %q", d)
	}
	// A restart's drop of an intent this run never asked about is not a
	// decline either.
	rep2, err := p.ProposeRelease(ctx, signed(t, 301, map[string][]byte{"host-image/release": []byte("g")}))
	if err != nil {
		t.Fatal(err)
	}
	id2 := "chg:" + rep2.ID + ":adopt"
	r.g.Decide(owner.Decision{Request: "old", Item: 1, Ref: id2, Why: "restart"})
	r.g.Wait()
	if st := r.state(id2); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "lapsed, not declined") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	if d := p.Digest(); len(d) != 0 {
		t.Fatalf("a restart drop reads as a decline: %q", d)
	}

	rep, err = p.ProposeRelease(ctx, signed(t, 31, map[string][]byte{"host-image/release": []byte("i")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	r.g.Flush()
	r.decide(false, "owner")
	if st := r.state("chg:" + rep.ID + ":adopt"); st.State != journal.Denied {
		t.Fatal(st.State)
	}
	if d := p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "You declined security update 31;") {
		t.Fatalf("%q", d)
	}
}

// CHG-4, CHG-5 (security lens R1 on #48): turning sharing on changes what
// leaves the box, so like a grant it needs the local page as well as the
// owner's code; without that page it is refused at once. Other settings
// need only the code.
func TestSharingOnNeedsTheLocalPage(t *testing.T) {
	r, p := changeRig(t)
	ctx := context.Background()
	if err := p.SetSharing(ctx, true); !errors.Is(err, change.ErrPending) {
		t.Fatal(err)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	id := items[0].Ref
	r.decide(true, "owner")
	if st := r.state(id); st.State != journal.Pending {
		t.Fatalf("sharing turned on without the local page: %s", st.State)
	}
	if err := r.g.ConfirmLocal(id); err != nil {
		t.Fatal(err)
	}
	r.g.Wait()
	if st := r.state(id); st.State != journal.Succeeded {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}

	noUI, q := changeRig(t)
	noUI.g.cfg.LocalUI = false
	if err := q.SetSharing(ctx, true); err == nil || !strings.Contains(err.Error(), NoPageSharing) {
		t.Fatalf("sharing on without a local page: %v", err)
	}
	// A setting that only needs the code cannot be confirmed locally.
	if err := q.SetAutoAdopt(ctx, true); !errors.Is(err, change.ErrPending) {
		t.Fatal(err)
	}
	noUI.g.Flush()
	_, items = noUI.own.last(t)
	if err := noUI.g.ConfirmLocal(items[0].Ref); err == nil {
		t.Fatal("confirmed a change that needs no local page")
	}
}

// Arbitrator ruling on #48: a tested, undoable, local learned skill is a
// low-tier request (the request's texted code, CH-10); the same change
// untested stays high tier.
func TestTestedLearnedChangeIsLowTier(t *testing.T) {
	r, p := changeRig(t)
	ctx := context.Background()
	if err := p.SetAutoAdopt(ctx, false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		id := "task-" + string(rune('a'+i))
		if _, err := r.eng.Submit(journal.Intent{ID: id, Origin: "guest:agent", Account: "mail", Action: "draft.save", Executor: "mail"}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.eng.RecordQuality(id, journal.Quality{Verdict: journal.VerdictGood, Source: "owner"}); err != nil {
			t.Fatal(err)
		}
		if err := p.AddTaskCase(change.Case{ID: "case-" + id, Task: id, Class: change.ClassSkill, Input: []byte("skills/greet"),
			Expect: []byte("refused"), Outcome: change.Accepted}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := p.Propose(ctx, change.Candidate{Source: change.Local, Files: change.Tree{"skills/new": []byte("x")}})
	if err != nil || rep.State != change.StateAwaitingOwner || rep.HeldOut == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Facts.Kind != owner.Ordinary || r.own.Tier(items[0].Facts) != owner.Low ||
		!strings.HasPrefix(items[0].Detail, "tested on ") {
		t.Fatalf("%+v", items)
	}
	r.decide(true, "owner")
	if got := string(p.Files("skills")["skills/new"]); got != "x" {
		t.Fatalf("approved change not adopted: %q", got)
	}
}

// CH-3 (L3 B1 on #48): adopting a release needs the code and the local
// page; without a local page the request is held pending, never texted for
// a code it cannot complete, and never denied.
func TestReleaseNeedsTheLocalPage(t *testing.T) {
	r, p := changeRig(t)
	ctx := context.Background()
	rep, err := p.ProposeRelease(ctx, signed(t, 40, map[string][]byte{"host-image/release": []byte("h")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	id := "chg:" + rep.ID + ":adopt"
	r.g.Flush()
	r.decide(true, "owner")
	if st := r.state(id); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "Wi-Fi page") {
		t.Fatalf("release installed on the code alone: %s %q", st.State, st.Permission.Reason)
	}
	if err := r.g.ConfirmLocal(id); err != nil {
		t.Fatal(err)
	}
	r.g.Wait()
	if st := r.state(id); st.State != journal.Succeeded {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}

	noUI, q := changeRig(t)
	noUI.g.cfg.LocalUI = false
	rep, err = q.ProposeRelease(ctx, signed(t, 41, map[string][]byte{"host-image/release": []byte("i")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	n := noUI.own.count()
	noUI.g.Flush()
	if noUI.own.count() != n {
		t.Fatal("texted a code that cannot complete without the local page")
	}
	if notes := noUI.own.notes; len(notes) != 1 || notes[0] != "Waiting for your confirmation on my Wi-Fi page, or your recovery key." {
		t.Fatalf("%q", notes)
	}
	if st := noUI.state("chg:" + rep.ID + ":adopt"); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "Wi-Fi page") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
}

// C7 (L3 R1 on #48): an approval refused at dispatch for being older than
// Fresh is not the owner's no, so no decline is recorded.
func TestStaleApprovalIsNotADecline(t *testing.T) {
	r, p := changeRig(t)
	ctx := context.Background()
	rep, err := p.ProposeRelease(ctx, signed(t, 50, map[string][]byte{"host-image/release": []byte("h")}))
	if err != nil {
		t.Fatal(err)
	}
	r.g.Flush()
	r.decide(true, "owner")
	r.advance(2 * DefaultFresh)
	if err := r.g.ConfirmLocal("chg:" + rep.ID + ":adopt"); err != nil {
		t.Fatal(err)
	}
	r.g.Wait()
	if st := r.state("chg:" + rep.ID + ":adopt"); st.State == journal.Succeeded {
		t.Fatal("a stale approval installed")
	}
	if d := p.Digest(); len(d) != 0 {
		t.Fatalf("a stale approval reads as a decline: %q", d)
	}
}

// fakeChanges answers Check with a fixed error.
type fakeChanges struct{ err error }

func (f fakeChanges) Check(context.Context, journal.Phase, journal.Intent) error { return f.err }
func (fakeChanges) Line(journal.Intent) (owner.Item, error) {
	return owner.Item{Object: "x", Facts: owner.Facts{Verb: "adopt"}}, nil
}
func (fakeChanges) Decided(context.Context, journal.Intent, bool) {}

// L3 R2 on #48: only ErrNeedsOwner itself asks; an error that merely wraps
// or joins it with a refusal denies.
func TestOnlyNeedsOwnerItselfAsks(t *testing.T) {
	for _, err := range []error{
		errors.Join(errors.New("change: no active adoption"), change.ErrNeedsOwner),
		wrapErr(change.ErrNeedsOwner),
	} {
		g := New(Config{Changes: fakeChanges{err}})
		v := g.evaluateChange(context.Background(), journal.PhaseAuthorize, journal.Intent{ID: "chg:c1:adopt", Action: change.ActionAdopt})
		if v.kind != deny {
			t.Fatalf("%v: %v", err, v.kind)
		}
	}
	g := New(Config{Changes: fakeChanges{change.ErrNeedsOwner}})
	if v := g.evaluateChange(context.Background(), journal.PhaseAuthorize, journal.Intent{ID: "chg:c1:adopt", Action: change.ActionAdopt}); v.kind != ask {
		t.Fatal(v.kind)
	}
}

func wrapErr(err error) error { return &wrapped{err} }

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }
