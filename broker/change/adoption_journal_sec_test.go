package change

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CAP-3, C23, CHG-2, AJS-1, AJS-2, AJS-3

// CHG-adoption-journal-sec: a settled proposal leaves no bytes behind, and
// a proposal read back from Content is the one its intent was submitted
// for.

// delFailContent is Content whose deletes fail while fail is set.
type delFailContent struct {
	*MemContent
	mu   sync.Mutex
	fail bool
}

func (c *delFailContent) Delete(n string) error {
	c.mu.Lock()
	fail := c.fail
	c.mu.Unlock()
	if fail {
		return errors.New("disk says no")
	}
	return c.MemContent.Delete(n)
}

func (c *delFailContent) set(fail bool) {
	c.mu.Lock()
	c.fail = fail
	c.mu.Unlock()
}

// holding: the Content keys that hold b, as is or as JSON encodes bytes.
func (c *delFailContent) holding(b []byte) []string {
	enc := []byte(base64.StdEncoding.EncodeToString(b))
	c.MemContent.mu.Lock()
	defer c.MemContent.mu.Unlock()
	var keys []string
	for k, v := range c.m {
		if bytes.Contains(v, b) || bytes.Contains(v, enc) {
			keys = append(keys, k)
		}
	}
	return keys
}

var learned = []byte("g1 learned note")

// deniedGoalProposal: a proposal learned from owner:g1 waits for the
// owner, the pipeline restarts, and the owner denies it while Content's
// deletes fail.
func deniedGoalProposal(t *testing.T) (*env, *delFailContent) {
	t.Helper()
	fc := &delFailContent{MemContent: &MemContent{}}
	e := newEnv(t, func(c *Config) { c.Content = fc })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if err := e.p.SetAutoAdopt(bg, false); err != nil {
		t.Fatal(err)
	}
	e.p.Attach(holdJournal{e.eng})
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": learned}})
	if a.State != StateAwaitingOwner {
		t.Fatalf("setup: %+v", a)
	}
	e.reopen()
	fc.set(true)
	e.owner.approve = false
	if st, err := e.eng.Authorize(bg, adoptID(a.ID)); st.State != journal.Denied {
		t.Fatalf("deny: %+v %v", st, err)
	}
	if r, _ := e.p.Settle(bg, a.ID); r.State == StateAdopted {
		t.Fatal("a denied proposal adopted")
	}
	if len(fc.holding(learned)) == 0 {
		t.Fatal("setup: the failed delete left nothing behind")
	}
	return e, fc
}

// AJS-1: the delete failed at settle; the next forget removes the bytes.
func TestForgetRemovesStrayProposal(t *testing.T) {
	e, fc := deniedGoalProposal(t)
	fc.set(false)
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if keys := fc.holding(learned); len(keys) != 0 {
		t.Fatalf("goal bytes left after forget: %q", keys)
	}
}

// AJS-1: the delete still fails at the restart's replay; the forget after
// it removes the bytes.
func TestForgetAfterRestartRemovesStrayProposal(t *testing.T) {
	e, fc := deniedGoalProposal(t)
	e.reopen()
	if len(fc.holding(learned)) == 0 {
		t.Fatal("setup: replay deleted through a failing Content")
	}
	fc.set(false)
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if keys := fc.holding(learned); len(keys) != 0 {
		t.Fatalf("goal bytes left after restart and forget: %q", keys)
	}
}

// AJS-1: the process stopped before the delete; the next start removes
// the bytes of a proposal whose intent no longer waits.
func TestReplayRemovesSettledProposal(t *testing.T) {
	e, fc := deniedGoalProposal(t)
	fc.set(false)
	e.reopen()
	if keys := fc.holding(learned); len(keys) != 0 {
		t.Fatalf("goal bytes left after restart: %q", keys)
	}
}

// waitingProposal: a config change waits for the owner. The journal
// redacts every param, as the daemon's does, so only the saved
// proposal's MAC binds the candidate.
func waitingProposal(t *testing.T) (*env, Report) {
	t.Helper()
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	eng, err := journal.Open(e.jstore, e.owner, map[string]journal.Executor{Executor: e.p, "task": noop{}},
		func(s string) string {
			if s == "" {
				return ""
			}
			return redacted
		})
	if err != nil {
		t.Fatal(err)
	}
	e.eng = eng
	e.p.Attach(holdJournal{e.eng})
	a := e.propose(Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}})
	if a.State != StateAwaitingOwner {
		t.Fatalf("setup: %+v", a)
	}
	return e, a
}

// approveRefused: after a restart the owner approves id, and the adopt is
// refused with Active unchanged.
func approveRefused(t *testing.T, e *env, id, what string) {
	t.Helper()
	before := e.p.Files("config")
	e.reopen()
	e.owner.approve = true
	st, _ := e.eng.Authorize(bg, adoptID(id))
	r, err := e.p.Settle(bg, id)
	if st.State == journal.Succeeded || r.State == StateAdopted || err == nil {
		t.Fatalf("%s: adopted: %+v %+v %v", what, st, r, err)
	}
	if got := e.p.Files("config"); len(got) != len(before) || got["config/a"] != nil {
		t.Fatalf("%s: Active changed: %q", what, got)
	}
}

// AJS-2: Content rewritten between submit and approve.
func TestRewrittenProposalIsRefused(t *testing.T) {
	e, a := waitingProposal(t)
	raw, err := e.p.content.Get(proposalKey(a.ID))
	if err != nil || raw == nil {
		t.Fatalf("no proposal blob: %v", err)
	}
	var env struct {
		Body json.RawMessage `json:"body"`
		MAC  string          `json:"mac"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.MAC == "" {
		t.Fatalf("blob carries no MAC: %v", err)
	}
	var sp savedProposal
	if err := json.Unmarshal(env.Body, &sp); err != nil {
		t.Fatal(err)
	}
	sp.Next["config/a"] = []byte("evil")
	env.Body, _ = json.Marshal(sp)
	forged, _ := json.Marshal(env)
	if err := e.p.content.Put(proposalKey(a.ID), forged); err != nil {
		t.Fatal(err)
	}
	approveRefused(t, e, a.ID, "rewritten")
}

// AJS-2: a blob without a MAC, as an attacker or an earlier build writes
// it, is not trusted.
func TestUnauthenticatedProposalIsRefused(t *testing.T) {
	e, a := waitingProposal(t)
	e.p.mu.Lock()
	pr := e.p.props[a.ID]
	e.p.mu.Unlock()
	next := Tree{"config/a": []byte("evil")}
	plain, _ := json.Marshal(savedProposal{Cand: pr.cand, Base: pr.base, Next: next, Edits: pr.edits,
		Report: pr.report, Classes: pr.classes})
	if err := e.p.content.Put(proposalKey(a.ID), plain); err != nil {
		t.Fatal(err)
	}
	approveRefused(t, e, a.ID, "unauthenticated")
}

// AJS-2: another proposal's authentic blob filed under this id.
func TestMisfiledProposalIsRefused(t *testing.T) {
	e, a := waitingProposal(t)
	e.p.mu.Lock()
	pr := *e.p.props[a.ID]
	pr.next = Tree{"config/a": []byte("evil")}
	err := e.p.putProposalLocked("c999", &pr)
	e.p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := e.p.content.Get(proposalKey("c999"))
	if err := e.p.content.Put(proposalKey(a.ID), other); err != nil {
		t.Fatal(err)
	}
	approveRefused(t, e, a.ID, "misfiled")
}

// AJS-2: the round trip still works.
func TestAuthenticProposalLoads(t *testing.T) {
	e, a := waitingProposal(t)
	e.p.mu.Lock()
	pr := e.p.loadProposalLocked(a.ID)
	e.p.mu.Unlock()
	if pr == nil || string(pr.next["config/a"]) != "1" {
		t.Fatalf("authentic proposal not loaded: %+v", pr)
	}
}

// AJS-3: unredacted to/from that do not match the candidate are refused;
// redacted ones pass to the other rules.
func TestAdoptParamsBindCandidate(t *testing.T) {
	e, a := waitingProposal(t)
	e.p.mu.Lock()
	pr := e.p.props[a.ID]
	to, from := pr.next.Hash(), pr.base
	e.p.mu.Unlock()
	other := strings.Repeat("0", 64)
	mk := func(params map[string]any) journal.Intent {
		return journal.Intent{ID: adoptID(a.ID), Origin: OriginPipeline, Account: journal.BrokerAccount,
			Action: ActionAdopt, Executor: Executor, GrantRef: a.Basis, Params: params}
	}
	for name, params := range map[string]map[string]any{
		"to differs":   {"from": from, "to": other},
		"from differs": {"from": other, "to": to},
		"to missing":   {"from": from},
		"from missing": {"to": to},
		"to uppercase": {"from": from, "to": strings.ToUpper(other)},
		"to prefixed":  {"from": from, "to": "sha256:" + other},
		"to not text":  {"from": from, "to": 7},
	} {
		err := e.p.Check(bg, journal.PhaseAuthorize, mk(params))
		if err == nil || errors.Is(err, ErrNeedsOwner) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, params := range map[string]map[string]any{
		"matching": {"from": from, "to": to},
		"redacted": {"from": "[redacted]", "to": "[redacted]"},
	} {
		if err := e.p.Check(bg, journal.PhaseAuthorize, mk(params)); !errors.Is(err, ErrNeedsOwner) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// AJS-1: a goal-learned proposal still waits, but its blob lost its seal
// (an earlier build's, or rewritten); after a restart and a forget of the
// goal, no Content key holds the goal's bytes.
func TestForgetRemovesUnsealedWaitingProposal(t *testing.T) {
	fc := &delFailContent{MemContent: &MemContent{}}
	e := newEnv(t, func(c *Config) { c.Content = fc })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if err := e.p.SetAutoAdopt(bg, false); err != nil {
		t.Fatal(err)
	}
	e.p.Attach(holdJournal{e.eng})
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": learned}})
	if a.State != StateAwaitingOwner {
		t.Fatalf("setup: %+v", a)
	}
	e.p.mu.Lock()
	pr := e.p.props[a.ID]
	plain, _ := json.Marshal(savedProposal{Cand: pr.cand, Base: pr.base, Next: pr.next, Edits: pr.edits,
		Report: pr.report, Classes: pr.classes})
	e.p.mu.Unlock()
	if err := fc.Put(proposalKey(a.ID), plain); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if keys := fc.holding(learned); len(keys) != 0 {
		t.Fatalf("goal bytes left after restart and forget: %q", keys)
	}
}
