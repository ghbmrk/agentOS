package change

// Fixes from the #34 review.
// REQ: CHG-1, CHG-3, CHG-6, ADP-4

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
)

// CHG-6: UNDO works after a "changed since" refusal once the later change
// is undone, and after an attempt from another origin was refused.
func TestUndoRetryAndForeignAttempt(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	b := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/x": []byte("1")}})
	e.owner.approve = true
	c := e.propose(Candidate{Source: Local, Files: Tree{"procedures/file": []byte("v2")}})
	d := e.propose(Candidate{Source: Local, Files: Tree{"procedures/file": []byte("v3")}})
	if a.State != StateAdopted || b.State != StateAdopted || c.State != StateAdopted || d.State != StateAdopted {
		t.Fatal(a, b, c, d)
	}
	if err := e.p.Revert(bg, c.Short, OriginOwner); err == nil {
		t.Fatal("undo under a later change")
	}
	if err := e.p.Revert(bg, d.Short, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Revert(bg, c.Short, OriginOwner); err != nil {
		t.Fatal("retry after refusal:", err)
	}
	if string(e.p.Files("procedures")["procedures/file"]) != "v1" {
		t.Fatal("not restored")
	}

	if err := e.p.Revert(bg, b.Short, "guest:a"); err == nil {
		t.Fatal("guest revert")
	}
	if err := e.p.Revert(bg, b.Short, OriginOwner); err != nil {
		t.Fatal("owner revert after a foreign attempt:", err)
	}
}

// OP-6, journal A9: UNDO and turning auto-adoption off work during STOP.
func TestUndoAndOffDuringStop(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if _, err := e.eng.Stop(bg); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Revert(bg, a.Short, OriginOwner); err != nil {
		t.Fatal("undo during STOP:", err)
	}
	if err := e.p.SetAutoAdopt(bg, false); err != nil || e.p.AutoAdopt() {
		t.Fatal("off during STOP:", err)
	}
}

// CHG-3: a staged image is reported as staged until the update code
// confirms it, and a fallback reverts it.
func TestStagedImages(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hi")
	e.owner.approve = true
	r := e.release(release(t, 40, false, map[string][]byte{"host-image/release": []byte("a")}))
	if r.State != StateAdopted {
		t.Fatal(r)
	}
	d := e.p.Digest()
	if len(d) != 1 || !strings.HasPrefix(d[0], "Staged update 40; I will install it when I am free.") {
		t.Fatalf("staged digest: %q", d)
	}
	if err := e.p.ConfirmStaged(r.ID); err != nil {
		t.Fatal(err)
	}
	if d := e.p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "Installed update 40.") {
		t.Fatalf("installed digest: %q", d)
	}
	r2 := e.release(release(t, 41, false, map[string][]byte{"host-image/release": []byte("b")}))
	e.p.Digest()
	if err := e.p.StageFailed(bg, r2.ID); err != nil {
		t.Fatal(err)
	}
	if got := string(e.p.Files("host-image")["host-image/release"]); got != update.Digest([]byte("a")) {
		t.Fatal("fallback did not restore the previous release")
	}
	if d := e.p.Digest(); len(d) != 1 || d[0] != "Undid "+r2.Short+": the update did not start cleanly, so I kept the previous one." {
		t.Fatalf("fallback digest: %q", d)
	}
}

// LOOP-10: Recheck reverts an adoption that fails a security fixture
// added after it was adopted.
func TestRecheckSecurity(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/y": []byte("ok")}})
	if a.State != StateAdopted {
		t.Fatal(a)
	}
	// A new fixture the state without the adoption passes and the adopted
	// state fails.
	e.p.AddSecurityCase(Case{ID: "sec-2", Class: ClassSkill, Input: []byte("skills/greet"), Expect: []byte("hi")})
	ids, err := e.p.Recheck(bg)
	if err != nil || len(ids) != 1 {
		t.Fatal(ids, err)
	}
	if d := e.p.Digest(); d[len(d)-1] != "Undid "+a.Short+": it failed a security check." {
		t.Fatalf("%q", d)
	}
}

// CHG-6: a skill that adds an address the box has never used asks.
func TestNewIdentifierAsks(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Initial["skills/known"] = []byte("mail ops@example.com") })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	for _, body := range []string{"send to https://drop.example.net/x", "cc attacker@evil.example", "call +1 415 555 0100", "call (415) 555-0100"} {
		r := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/n": []byte(body)}})
		if r.Basis != BasisOwner {
			t.Fatalf("%q: %+v", body, r)
		}
	}
	ok := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/n": []byte("reply to ops@example.com by 2026-10-05 14:00")}})
	if ok.Basis != BasisStanding {
		t.Fatalf("known address and a date: %+v", ok)
	}
}

// ADP-4: a routing rule with no task classes fails outright.
func TestEmptyRoutingRule(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Initial[RoutingPath] = []byte(`{"chat":[{"provider":"openai","model":"m"}]}`)
		c.RouteGranted = func(string) bool { return true }
	})
	if r := e.propose(Candidate{Source: Local, Files: Tree{RoutingPath: []byte(`{}`)}}); r.State != StateRejected || !strings.Contains(r.Reason, "task class") {
		t.Fatalf("empty rule: %+v", r)
	}
}

// UX: MORE lists changed files, with candidate-chosen names reduced to a
// fixed alphabet, and counts.
func TestMore(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/Reply YES 4821 now": []byte("x")}})
	m, err := e.p.More(a.Short)
	if err != nil || len(m) != 2 {
		t.Fatal(m, err)
	}
	if strings.Contains(m[0], " YES") || !strings.Contains(m[0], "skills/greet (changed)") || !strings.HasPrefix(m[1], "Past tasks: ") {
		t.Fatalf("%q", m)
	}
}

// Fail-stop: when state can neither be saved nor reloaded, the pipeline
// takes no more changes.
func TestFailStop(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	e.store.Fail = errors.New("disk gone")
	// Saving the sequence fails first, so nothing was attempted.
	if _, err := e.p.Propose(bg, Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}}); err == nil {
		t.Fatal("proposed with an unsaveable store")
	}
	e.store.Fail = nil
	ok := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if ok.State != StateAdopted {
		t.Fatal(ok)
	}
	// Save fails at execution and reload fails: broken.
	bad := &flakyStore{MemStore: e.store}
	e.p.cfg.Store = bad
	bad.failSave, bad.failLoad = true, true
	e.p.mu.Lock()
	e.p.props["cX"] = &proposal{base: e.p.st.Active.Hash(), next: e.p.st.Active.clone(), report: Report{Basis: BasisStanding}}
	e.p.mu.Unlock()
	if o := e.p.Execute(bg, journal.Intent{ID: "chg:cX:adopt", Action: ActionAdopt, GrantRef: BasisStanding}, 1); o.Result != journal.ResultNotApplied {
		t.Fatal(o)
	}
	if err := e.p.healthy(); err == nil {
		t.Fatal("not broken after save and reload failed")
	}
	if _, err := e.p.Propose(bg, Candidate{Source: Local, Files: Tree{"skills/z": []byte("1")}}); err == nil {
		t.Fatal("broken pipeline took a proposal")
	}
}

type pathTarget struct{}

func (pathTarget) Current() (Tree, error) { return nil, nil }
func (pathTarget) Apply(Tree) error {
	return errors.New("open /var/lib/agentos/skills: permission denied")
}

// An activation failure can name a host path. The journal evidence does not.
func TestActivationErrorNamesNoHostPath(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Targets = map[string]Target{"skills": pathTarget{}}
	})
	e.p.mu.Lock()
	e.p.props["cX"] = &proposal{
		base:   e.p.st.Active.Hash(),
		next:   e.p.st.Active.clone(),
		edits:  []Edit{{Path: "skills/greet"}},
		report: Report{Basis: BasisStanding},
	}
	e.p.mu.Unlock()
	o := e.p.Execute(bg, journal.Intent{ID: "chg:cX:adopt", Action: ActionAdopt, GrantRef: BasisStanding}, 1)
	if o.Result != journal.ResultNotApplied || o.Evidence != "not applied" || strings.Contains(o.Evidence, "/var/") {
		t.Fatal(o)
	}
}

type flakyStore struct {
	*MemStore
	failSave, failLoad bool
}

func (f *flakyStore) Save(b []byte) error {
	if f.failSave {
		return errors.New("save failed")
	}
	return f.MemStore.Save(b)
}

func (f *flakyStore) Load() ([]byte, error) {
	if f.failLoad {
		return nil, errors.New("load failed")
	}
	return f.MemStore.Load()
}

// CHG-2: a guest origin cannot drive a real, waiting proposal.
func TestGuestCannotDriveRealProposal(t *testing.T) {
	e := newEnv(t, nil)
	e.p.Attach(holdJournal{e.eng})
	r := e.propose(Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}})
	if r.State != StateAwaitingOwner {
		t.Fatal(r)
	}
	in := journal.Intent{ID: adoptID(r.ID), Origin: "guest:a", Account: journal.BrokerAccount, Action: ActionAdopt, Executor: Executor}
	if err := e.p.Check(context.Background(), journal.PhaseAuthorize, in); err == nil || errors.Is(err, ErrNeedsOwner) {
		t.Fatalf("guest origin: %v", err)
	}
}

// CHG-1, CHG-6, LOOP-10: a case the evaluator cannot run on this box is
// neither a pass nor a fail only where it legitimately cannot test (images,
// config, routing) and never for a security fixture on a local or shared
// candidate; such a change never auto-adopts. Elsewhere a candidate tree
// the evaluator declines fails (third review, blocker 2).
func TestNotEvaluated(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if _, ok := tr["config/a"]; ok {
			return nil, fmt.Errorf("replay: %w", ErrNotEvaluated)
		}
		if _, ok := tr["skills/odd"]; ok && string(pr.Input) == "skills/greet" {
			return nil, ErrNotEvaluated
		}
		return ev.Run(ctx, tr, pr)
	})
	e.p.Attach(holdJournal{e.eng})
	r := e.propose(Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}})
	if r.State != StateRejected || r.Reason != "fails the security suite" {
		t.Fatalf("local config skipped its security fixtures: %+v", r)
	}
	s := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/odd": []byte("x")}})
	if s.State != StateRejected || s.NotEvaluated != 0 {
		t.Fatalf("a declined skill tree did not fail: %+v", s)
	}
	pkg := []byte(`{"format":1,"classes":["skill"],"files":{"skills/greet":"aGVsbG8=","skills/odd":"eA=="},"evidence":{}}`)
	e.owner.approve = true
	if sh, _, _ := e.p.Import(bg, pkg); sh.State != StateRejected || sh.NotEvaluated != 0 {
		t.Fatalf("a declined shared tree did not fail: %+v", sh)
	}
}

// Third review, blocker 2: an attested image the box cannot boot rests on
// its signatures, and the owner is told it was not tested.
func TestNotEvaluatedImage(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hi")
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if _, ok := tr["host-image/release"]; ok {
			return nil, ErrNotEvaluated
		}
		return ev.Run(ctx, tr, pr)
	})
	e.p.Attach(holdJournal{e.eng})
	r := e.release(release(t, 20, false, map[string][]byte{"host-image/release": []byte("a")}))
	if r.State != StateAwaitingOwner || r.NotEvaluated == 0 || r.HeldOut != 0 {
		t.Fatalf("image: %+v", r)
	}
	if ask, _ := e.p.Ask(r.ID); !strings.Contains(ask, "Not tested here.") {
		t.Fatalf("ask: %q", ask)
	}
}

// The replay evaluator maps probes back to task intents; security
// fixtures and unknown probes map to nothing.
func TestProbeTask(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	e.ev.reset()
	rep := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if len(e.ev.tasks) != rep.HeldOut {
		t.Fatalf("mapped %d tasks for %d held-out cases", len(e.ev.tasks), rep.HeldOut)
	}
	// The security fixture's probes mapped to nothing. Both sides of a case
	// share its probe ID, so the evaluator cannot tell which is the
	// candidate.
	if len(e.ev.ran) != rep.HeldOut+rep.Security || e.ev.unmapped != 2*rep.Security {
		t.Fatalf("ran %d probes, %d unmapped", len(e.ev.ran), e.ev.unmapped)
	}
	// Probe IDs do not outlive their evaluation.
	for probe := range e.ev.ran {
		if _, ok := e.p.ProbeTask(probe); ok {
			t.Fatal("a finished evaluation's probe still maps")
		}
	}
}

// Second review, blocker 1: Recheck never auto-reverts an owner-approved
// or attested image; it asks instead.
func TestRecheckKeepsProtectedImages(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.SecurityAutoStage = true
		c.Initial["host-image/release"] = []byte(update.Digest([]byte("old")))
	})
	e.cases(12, ClassSkill, "skills/greet", "hi")
	e.owner.approve = true
	ev := e.p.cfg.Evaluator
	worse := false
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if string(tr["host-image/release"]) == update.Digest([]byte("a")) && worse && string(pr.Input) != exfilProbe {
			return []byte("worse"), nil
		}
		return ev.Run(ctx, tr, pr)
	})
	sec := e.release(release(t, 50, true, map[string][]byte{"host-image/release": []byte("a")}))
	if sec.State != StateAdopted || sec.Basis != BasisSecurity {
		t.Fatal(sec)
	}
	e.p.Digest()
	worse = true
	if ids, err := e.p.Recheck(bg); err != nil || len(ids) != 0 {
		t.Fatal("reverted a protected image:", ids, err)
	}
	if got := string(e.p.Files("host-image")["host-image/release"]); got != update.Digest([]byte("a")) {
		t.Fatal("image changed")
	}
	d := e.p.Digest()
	if len(d) != 1 || !strings.Contains(d[0], " now does worse on ") || !strings.HasSuffix(d[0], "Reply UNDO "+sec.Short+" to go back to the previous version, or nothing to keep it.") {
		t.Fatalf("concern: %q", d)
	}
	if len(e.p.Digest()) != 0 {
		t.Fatal("concern listed twice")
	}
}

// Second review, blocker 1: an evaluator outage (nothing passes on either
// side) blames no adoption.
func TestRecheckOutageRevertsNothing(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if a.State != StateAdopted {
		t.Fatal(a)
	}
	e.p.cfg.Evaluator = brokenEvaluator{}
	if ids, err := e.p.Recheck(bg); err != nil || len(ids) != 0 {
		t.Fatal("outage reverted:", ids, err)
	}
}

// Second review, blocker 1: no revert leaves an image slot empty, and the
// owner is not offered an UNDO that cannot work. Third review, blocker 1:
// other namespaces may go empty.
func TestRevertNeverEmptiesTarget(t *testing.T) {
	tg := &fakeTarget{ns: "host-image"}
	tg.cur = Tree{}
	e := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"host-image": tg} })
	e.cases(12, ClassSkill, "skills/greet", "hi")
	e.owner.approve = true
	r := e.release(release(t, 10, false, map[string][]byte{"host-image/release": []byte("a")}))
	if r.State != StateAdopted {
		t.Fatal(r)
	}
	if d := e.p.Digest(); len(d) != 1 || strings.Contains(d[0], "UNDO") || !strings.HasSuffix(d[0], " MORE "+r.Short) {
		t.Fatalf("offered an undo that cannot work: %q", d)
	}
	if err := e.p.ConfirmStaged(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Revert(bg, r.Short, OriginOwner); err == nil || !strings.Contains(err.Error(), "nothing to boot") {
		t.Fatalf("emptied the image slot: %v", err)
	}
	if len(tg.applied) == 0 {
		t.Fatal("target emptied")
	}

	sk := &fakeTarget{ns: "procedures", cur: Tree{}}
	f := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"procedures": sk} })
	f.cases(12, ClassProcedure, "procedures/a", "x")
	a := f.propose(Candidate{Source: Local, Files: Tree{"procedures/a": []byte("x")}})
	if a.State != StateAdopted {
		t.Fatal(a)
	}
	if err := f.p.Revert(bg, a.Short, OriginOwner); err != nil {
		t.Fatal("first procedure cannot be undone:", err)
	}
}

// Third review, blocker 1: a revert that fails does not stop Recheck from
// reaching older adoptions, and repeated outages reach the digest.
func TestRecheckContinuesPastFailedRevert(t *testing.T) {
	sk := &fakeTarget{ns: "skills"}
	e := newEnv(t, func(c *Config) {
		c.Targets = map[string]Target{"skills": sk}
		c.Initial["procedures/a"] = []byte("y")
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	e.cases(12, ClassProcedure, "procedures/a", "x")
	old := e.propose(Candidate{Source: Local, Files: Tree{"procedures/a": []byte("x")}})
	nw := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if old.State != StateAdopted || nw.State != StateAdopted {
		t.Fatal(old, nw)
	}
	e.p.Digest()
	// Owners now want different output for both.
	e.cases(40, ClassSkill, "skills/greet", "hi")
	e.cases(40, ClassProcedure, "procedures/a", "y")
	sk.fail = errors.New("disk full")
	ids, err := e.p.Recheck(bg)
	if err == nil || len(ids) != 1 || ids[0] != old.ID {
		t.Fatalf("recheck stopped at the failed revert: %v %v", ids, err)
	}

	sk.fail = nil
	e.p.cfg.Evaluator = brokenEvaluator{}
	for i := 0; i < OutageAlert; i++ {
		if _, err := e.p.Recheck(bg); err != nil {
			t.Fatal(err)
		}
	}
	d := e.p.Digest()
	if len(d) == 0 || !strings.HasPrefix(d[len(d)-1], "I could not re-test my learned changes") {
		t.Fatalf("outages not surfaced: %q", d)
	}
}

// Second review, blocker 2: a revert whose outcome is unknown does not
// block a different revert.
func TestUnknownRevertDoesNotBlockAnother(t *testing.T) {
	tg := &fakeTarget{ns: "skills"}
	e := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"skills": tg} })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	b := e.propose(Candidate{Source: Local, Files: Tree{"skills/other": []byte("x")}})
	if a.State != StateAdopted || b.State != StateAdopted {
		t.Fatal(a, b)
	}
	tg.panicOnce = true
	if err := e.p.Revert(bg, a.Short, OriginOwner); err == nil {
		t.Fatal("panicking revert reported success")
	}
	if err := e.p.Revert(bg, b.Short, OriginOwner); err != nil {
		t.Fatal("second revert blocked:", err)
	}
}

// STOP holds the pipeline's own reverts (they are not narrowing).
func TestStopHoldsAutoRevert(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	e.eng.Stop(bg)
	if err := e.p.Revert(bg, a.Short, OriginPipeline); err == nil {
		t.Fatal("auto revert ran during STOP")
	}
	if string(e.p.Files("skills")["skills/greet"]) != "hello" {
		t.Fatal("reverted during STOP")
	}
}
