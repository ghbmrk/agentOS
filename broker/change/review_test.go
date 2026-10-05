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
	r := e.release(release(t, "4.0", false, map[string][]byte{"host-image/release": []byte("a")}))
	if r.State != StateAdopted {
		t.Fatal(r)
	}
	d := e.p.Digest()
	if len(d) != 1 || !strings.HasPrefix(d[0], "Staged update 4.0; it starts at the next restart.") {
		t.Fatalf("staged digest: %q", d)
	}
	if err := e.p.ConfirmStaged(r.Short); err != nil {
		t.Fatal(err)
	}
	if d := e.p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "Installed update 4.0.") {
		t.Fatalf("installed digest: %q", d)
	}
	r2 := e.release(release(t, "4.1", false, map[string][]byte{"host-image/release": []byte("b")}))
	e.p.Digest()
	if err := e.p.StageFailed(bg, r2.Short); err != nil {
		t.Fatal(err)
	}
	if got := string(e.p.Files("host-image")["host-image/release"]); got != update.Digest([]byte("a")) {
		t.Fatal("fallback did not restore the previous release")
	}
	if d := e.p.Digest(); len(d) != 1 || d[0] != "Undid "+r2.Short+": the update did not start cleanly, so the box kept the previous one." {
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
	e.p.AddSecurityCase(Case{ID: "sec-2", Class: ClassSkill, Input: []byte("skills/y"), Expect: []byte("refused")})
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

// CHG-1, CHG-6: a case the evaluator cannot run on this box is neither a
// pass nor a fail; such a change never auto-adopts, and the owner is told
// it was not tested.
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
	if r.State != StateAwaitingOwner || r.HeldOut != 0 || r.NotEvaluated == 0 {
		t.Fatalf("config: %+v", r)
	}
	if ask, _ := e.p.Ask(r.ID); ask != "Changed a setting. Not tested on this box. Approve or decline?" {
		t.Fatalf("ask: %q", ask)
	}
	s := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/odd": []byte("x")}})
	if s.Basis != BasisOwner || s.NotEvaluated == 0 {
		t.Fatalf("partly evaluated skill auto-adopted: %+v", s)
	}
}

// The replay evaluator maps probes back to task intents; security
// fixtures and unknown probes map to nothing.
func TestProbeTask(t *testing.T) {
	e := newEnv(t, nil)
	c := e.taskCase(ClassSkill, "skills/greet", "hello", Accepted)
	if task, ok := e.p.ProbeTask(e.p.probeID(c.ID)); !ok || task != c.Task {
		t.Fatal(task, ok)
	}
	if _, ok := e.p.ProbeTask(e.p.probeID("sec-1")); ok {
		t.Fatal("security fixture mapped to a task")
	}
	if _, ok := e.p.ProbeTask("nope"); ok {
		t.Fatal("unknown probe")
	}
}
