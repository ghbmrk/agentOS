package loops

// REQ: LOOP-9, LOOP-10, CHG-2, LOOP-2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// capPipe records every candidate Loop 2 proposes.
type capPipe struct {
	logPipe
	mu  *sync.Mutex
	got *[]change.Candidate
}

func (p capPipe) Propose(ctx context.Context, c change.Candidate) (change.Report, error) {
	p.mu.Lock()
	*p.got = append(*p.got, c)
	p.mu.Unlock()
	return p.logPipe.Propose(ctx, c)
}

// unreadyFixer is a scriptFixer that can say it cannot build now.
type unreadyFixer struct {
	*scriptFixer
	why string
}

func (f *unreadyFixer) Unready() string { return f.why }

// fixRig is a reportRig whose Guard has fixer fx and records what it
// proposes.
func fixRig(t *testing.T, fx Fixer) (*reportRig, *[]change.Candidate) {
	t.Helper()
	r := newReportRig(t, nil)
	got := &[]change.Candidate{}
	g, err := NewGuard(GuardConfig{Box: cleanBox().Box(), Pipeline: capPipe{logPipe{r.p, r.ev, &r.refuse}, &sync.Mutex{}, got},
		Store: r.store, Contain: r.c, FixturesLiveFor: map[Check]bool{CheckSeeded: true}, Fixer: fx,
		Notify: func(s string, u bool) { r.texts, r.urgent = append(r.texts, s), append(r.urgent, u) },
		Now:    func() time.Time { return r.now }})
	if err != nil {
		t.Fatal(err)
	}
	r.g = g
	return r, got
}

func (r *reportRig) again(t *testing.T) {
	t.Helper()
	r.g.Trigger()
	r.pass(t)
}

// CHG-2 (Security 4 on #464): Loop 2 stamps a fix's source, origin and
// finding and clears what a fixer may have set, its goals and claim
// included, so a fix's adoption never hangs on an owner goal that
// ForgetGoal would undo.
func TestLoop2StampsAndClearsWhatAFixerSets(t *testing.T) {
	c := fixCand(reference)
	c.Source, c.Origin, c.Public, c.Finding, c.Goals, c.Claim = change.Upstream, "loop1", true, "other", []string{"owner:g1"}, "trust me"
	fx := &scriptFixer{cands: []change.Candidate{c}}
	r, got := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	r.pass(t)
	if len(*got) != 1 {
		t.Fatalf("%d proposals", len(*got))
	}
	p := (*got)[0]
	if p.Source != change.Local || p.Origin != "loop2" || p.Public || p.Finding != id || p.Goals != nil || p.Claim != "" {
		t.Fatalf("proposed %+v", p)
	}
	if e := r.evidenceFor(t, id); e.Fix != string(change.StateAdopted) {
		t.Fatalf("fix %q (%s)", e.Fix, e.FixReason)
	}
}

// LOOP-9, CHG-2: the fixer is handed the finding with its minimized
// regression, never the padded test, another case or a held-back variant.
func TestTheFixerSeesOnlyTheMinimizedRegression(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}}
	r, _ := fixRig(t, fx)
	rec := r.report(t, seedFinding())
	h := heldSeed(rec.Finding.ID)
	if err := r.p.AddSecurityCase(h); err != nil {
		t.Fatal(err)
	}
	r.pass(t)
	if fx.calls() != 1 {
		t.Fatalf("%d fixer calls", fx.calls())
	}
	in := fx.got[0]
	if string(in.Rule) != string(rec.Regression) || string(in.Rule) == string(seedFinding().Rule) {
		t.Fatalf("fixer saw rule %s, regression %s", in.Rule, rec.Regression)
	}
	if strings.Contains(fmt.Sprintf("%+v", in), "/fallback") || in.Subject != rec.Finding.Subject || in.Detail != rec.Finding.Detail {
		t.Fatalf("fixer saw %+v", in)
	}
}

// LOOP-10: a fix that writes authority or the suites is rejected by the
// pipeline with its LOOP-10 reason, whatever else it carries.
func TestAFixWritingAuthorityIsRejected(t *testing.T) {
	for ns, why := range map[string]string{
		"grants": "changes grants, which no candidate may change (LOOP-10)",
		"checks": "changes checks, which no candidate may change (LOOP-10)",
		"suites": "changes suites, which only an owner-approved intent changes (CHG-2)",
	} {
		c := fixCand(reference)
		c.Files[ns+"/x.json"] = []byte(`{}`)
		r, _ := fixRig(t, &scriptFixer{cands: []change.Candidate{c}})
		id := r.report(t, seedFinding()).Finding.ID
		r.pass(t)
		if rec, open := r.open(id); !open || rec.Fix != string(change.StateRejected) || rec.FixReason != why {
			t.Errorf("%s: open %v, %q (%s)", ns, open, rec.Fix, rec.FixReason)
		}
	}
}

// LOOP-9 (P3-4b-5): a fixer that cannot build (no builder, no model
// grant) is not asked; the request stays open and STATUS names the cause.
// Once it can, the next pass asks it.
func TestAnUnreadyFixerIsNotAsked(t *testing.T) {
	fx := &unreadyFixer{&scriptFixer{cands: []change.Candidate{fixCand(reference)}}, "this box has no builder machines"}
	r, _ := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	r.pass(t)
	if rec, open := r.open(id); !open || rec.Fix != FixPending || fx.calls() != 0 {
		t.Fatalf("open %v, %+v, %d calls", open, rec, fx.calls())
	}
	if s := r.g.Status(); !strings.Contains(s, "waits for a fix: I cannot build one yet, because this box has no builder machines.") {
		t.Fatalf("status %q", s)
	}
	fx.why = ""
	r.again(t)
	if e := r.evidenceFor(t, id); e.Fix != string(change.StateAdopted) || fx.calls() != 1 {
		t.Fatalf("fix %q, %d calls", e.Fix, fx.calls())
	}
}

// gamedN is a fix that passes the visible regression but not the held-back
// case, different each time.
func gamedN(n int) change.Candidate {
	return fixCand(fmt.Sprintf(`{"private":["local"],"fallback":"cloud","name":"r","n":%d}`, n))
}

// addProbe adds a security case every tree passes, so the suite changes.
func (r *reportRig) addProbe(t *testing.T, i int) {
	t.Helper()
	extra := change.TreeRule{Clauses: []change.Clause{{Path: "config/x.json", Pointer: fmt.Sprintf("/k%d", i), Op: change.OpAbsent}}}
	if err := r.p.AddSecurityCase(change.Case{ID: fmt.Sprintf("extra/%d", i), Class: change.ClassConfig, Input: extra.Encode(), Expect: []byte(change.TreeRuleOK)}); err != nil {
		t.Fatal(err)
	}
}

// Potency 1 on #464, #493 (S22): two rejections in a row graded the same
// stop the asking until the suite or the tree changes, even days later;
// after maxFixTries the box stops for good and STATUS says so.
func TestFixRetriesAreBounded(t *testing.T) {
	var cands []change.Candidate
	for i := range 2 * maxFixTries {
		cands = append(cands, gamedN(i))
	}
	fx := &scriptFixer{cands: cands}
	r, _ := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	if err := r.p.AddSecurityCase(heldSeed(id)); err != nil {
		t.Fatal(err)
	}
	r.pass(t)
	r.again(t)
	if fx.calls() != 2 {
		t.Fatalf("%d calls after two checks", fx.calls())
	}
	r.again(t)
	r.now = r.now.Add(25 * time.Hour)
	r.again(t)
	if fx.calls() != 2 {
		t.Fatalf("%d calls with nothing changed", fx.calls())
	}
	if s := r.g.Status(); !strings.Contains(s, waitUnchanged) {
		t.Fatalf("status %q", s)
	}
	// Each change to the suite buys one more try, the same verdict holds
	// it again.
	for i := 3; i <= maxFixTries; i++ {
		r.addProbe(t, i)
		r.again(t)
		r.again(t)
		if fx.calls() != i {
			t.Fatalf("after change %d: %d calls", i, fx.calls())
		}
	}
	r.addProbe(t, 0)
	r.now = r.now.Add(30 * 24 * time.Hour)
	r.again(t)
	if fx.calls() != maxFixTries {
		t.Fatalf("%d calls after stopping", fx.calls())
	}
	if rec, open := r.open(id); !open || rec.Fix != string(change.StateRejected) {
		t.Fatalf("open %v, %+v", open, rec)
	}
	if s := r.g.Status(); !strings.Contains(s, waitStopped) {
		t.Fatalf("status %q", s)
	}
}

// heldTwice is a fixRig whose finding's request is held as unchanged after
// two rejections for the same reason (L3 1 on #575).
func heldTwice(t *testing.T) (*reportRig, *scriptFixer, string) {
	t.Helper()
	var cands []change.Candidate
	for i := range 2 * maxFixTries {
		cands = append(cands, gamedN(i))
	}
	fx := &scriptFixer{cands: cands}
	r, _ := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	if err := r.p.AddSecurityCase(heldSeed(id)); err != nil {
		t.Fatal(err)
	}
	r.addProbe(t, 99) // a plain config fixture, so a config change can qualify
	r.pass(t)
	r.again(t)
	r.again(t)
	if rec, _ := r.open(id); fx.calls() != 2 || rec.FixHold != holdUnchanged {
		t.Fatalf("%d calls, hold %q", fx.calls(), rec.FixHold)
	}
	return r, fx, id
}

// L3 1 on #575: a change to the active tree in the regression's namespace
// buys exactly one more ask of a request held as unchanged.
func TestAHeldRequestIsAskedOnceMoreWhenTheTreeChanges(t *testing.T) {
	r, fx, _ := heldTwice(t)
	rep, err := r.p.Propose(context.Background(), change.Candidate{Source: change.Local, Origin: "test",
		Files: change.Tree{"config/other.json": []byte(`{"v":1}`)}})
	if err != nil || rep.State != change.StateAdopted {
		t.Fatalf("tree change: %+v, %v", rep, err)
	}
	r.again(t)
	r.again(t)
	if fx.calls() != 3 {
		t.Fatalf("%d calls after a tree change, want 3", fx.calls())
	}
}

// L3 1 on #575: a new case linked to the finding buys exactly one more ask
// of a request held as unchanged.
func TestAHeldRequestIsAskedOnceMoreWhenALinkedCaseIsAdded(t *testing.T) {
	r, fx, id := heldTwice(t)
	c := heldSeed(id)
	c.ID = "held/" + id + "/v2"
	if err := r.p.AddSecurityCase(c); err != nil {
		t.Fatal(err)
	}
	r.again(t)
	r.again(t)
	if fx.calls() != 3 {
		t.Fatalf("%d calls after a linked case, want 3", fx.calls())
	}
}

// Security release 1, L3 later 3 on #575: a finding no fix can be built
// for (the fixer says ErrNotFixable) is not a failed build. Loop 2 counts
// no try, never asks again, and STATUS says it cannot repair it.
func TestAnUnfixableFindingIsNotAFailedBuild(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}, err: fmt.Errorf("no namespace: %w", ErrNotFixable)}
	r, _ := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	r.pass(t)
	for range 3 {
		r.now = r.now.Add(25 * time.Hour)
		r.again(t)
	}
	if rec, open := r.open(id); !open || fx.calls() != 1 || rec.FixTries != 0 || rec.FixHold != holdUnfixable {
		t.Fatalf("open %v, %d calls, %+v", open, fx.calls(), rec)
	}
	if s := r.g.Status(); !strings.Contains(s, waitUnfixable) {
		t.Fatalf("status %q", s)
	}
}

// UX release 2 on #575: the stopped line names the real cap.
func TestTheStoppedLineNamesTheCap(t *testing.T) {
	if !strings.Contains(waitStopped, fmt.Sprintf(" %d ", maxFixTries)) {
		t.Fatalf("%q does not name %d", waitStopped, maxFixTries)
	}
}

// Potency 1 on #464: a rejection for a new reason is asked again at the
// next check, as the A11 harness's scripted set is.
func TestANewRejectionIsAskedAgain(t *testing.T) {
	grants := fixCand(reference)
	grants.Files["grants/x.json"] = []byte(`{}`)
	fx := &scriptFixer{cands: []change.Candidate{gamedN(1), grants, fixCand(reference)}}
	r, _ := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	if err := r.p.AddSecurityCase(heldSeed(id)); err != nil {
		t.Fatal(err)
	}
	r.pass(t)
	r.again(t)
	r.again(t)
	if e := r.evidenceFor(t, id); e.Fix != string(change.StateAdopted) || fx.calls() != 3 {
		t.Fatalf("fix %q, %d calls", e.Fix, fx.calls())
	}
}

// Potency 1 on #464: a fixer that keeps failing to build is asked at the
// next two checks, then once a day.
func TestAFailingFixerIsAskedOnceADay(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}, err: errors.New("the job timed out")}
	r, _ := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	for range 3 {
		r.g.Trigger()
		r.g.Pass(context.Background())
	}
	if fx.calls() != 2 {
		t.Fatalf("%d calls", fx.calls())
	}
	if s := r.g.Status(); !strings.Contains(s, waitLater) {
		t.Fatalf("status %q", s)
	}
	fx.err = nil
	r.now = r.now.Add(25 * time.Hour)
	r.again(t)
	if e := r.evidenceFor(t, id); e.Fix != string(change.StateAdopted) || fx.calls() != 3 {
		t.Fatalf("fix %q, %d calls", e.Fix, fx.calls())
	}
}

// Potency 1 on #464: a candidate the same as one already rejected for this
// finding is not proposed again; it counts as a try.
func TestARejectedFixIsNotProposedAgain(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{gamedN(1)}}
	r, got := fixRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	if err := r.p.AddSecurityCase(heldSeed(id)); err != nil {
		t.Fatal(err)
	}
	r.pass(t)
	r.again(t)
	if fx.calls() != 2 || len(*got) != 1 {
		t.Fatalf("%d calls, %d proposals", fx.calls(), len(*got))
	}
	if rec, _ := r.open(id); rec.Fix != string(change.StateRejected) || rec.FixReason != change.ReasonLinked || rec.FixTries != 2 {
		t.Fatalf("%+v", rec)
	}
}
