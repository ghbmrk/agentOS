package clerk_test

// REQ: CLK-2, KEY-1, KEY-3

import (
	"crypto/ed25519"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func gen(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

type fix struct {
	k     *kernel.Kernel
	mail  *clerk.Mail
	root  key.Key
	req   kernel.Request
	now   int64 // the mail clerk's own clock
	plans map[string]kernel.Plan
}

// inFlight is the kernel's state with the plans a test built reported in
// flight, first dispatched after every entry so far: what a clerk sees when
// the kernel dispatches one. Tests that call a clerk directly read it; the
// clerk's refusal of a step the log does not have in flight is tested on
// the real state (TestClerkRefusesAStepTheLogDoesNotHaveInFlight).
type inFlight struct {
	*kernel.State
	plans map[string]kernel.Plan
}

func (v inFlight) Dispatched(plan string, i int) (kernel.Dispatch, bool) {
	if d, ok := v.State.Dispatched(plan, i); ok {
		return d, true
	}
	p, ok := v.plans[plan]
	if !ok || i < 0 || i >= len(p.Steps) {
		return kernel.Dispatch{}, false
	}
	return kernel.Dispatch{Sig: p.Sig, Seq: v.State.Seq + 1}, true
}

func (f *fix) view() kernel.View { return inFlight{f.k.State(), f.plans} }

func setup(t *testing.T, verb key.Verb) *fix {
	t.Helper()
	opub, opriv := gen(1)
	hpub, _ := gen(2)
	kpub, kpriv := gen(3)
	mail := clerk.NewMail("mail", opub)
	f := &fix{mail: mail, now: 1, plans: map[string]kernel.Plan{}}
	mail.Clock = func() int64 { return f.now }
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: kpub,
		Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, opub, map[string]kernel.Clerk{"mail": mail}, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := key.Issue(opriv, key.Root{Holder: hpub, Clerk: "mail", Verbs: []key.Verb{verb}, Serial: "r1"})
	if err := k.Issue(0, root); err != nil {
		t.Fatal(err)
	}
	f.k, f.root = k, root
	f.req = f.request("i1", root, stepOf(verb))
	return f
}

func stepOf(verb key.Verb) kernel.PlanStep {
	ps := kernel.PlanStep{Verb: verb, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(verb) {
		ps.Args[n] = "x"
	}
	return ps
}

// request is plan id, of the one step ps under k, signed by the holder of
// every key here and dispatched (view).
func (f *fix) request(id string, k key.Key, ps kernel.PlanStep) kernel.Request {
	p := kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{ps}}, hpubPriv())
	f.plans[id] = p
	return kernel.Request{Plan: p}
}

func TestClerkRechecksAndIsIdempotent(t *testing.T) {
	f := setup(t, key.Trash)
	if r := f.mail.Do(f.req, f.view()); r.Outcome != "ok" {
		t.Fatalf("valid step refused: %+v", r)
	}
	if r := f.mail.Do(f.req, f.view()); r.Outcome != "ok" || len(f.mail.Effects()) != 1 {
		t.Fatal("same idempotency key must not act twice")
	}
	if f.mail.Probe(f.req, f.view()) != "done" {
		t.Fatal("probe must report done")
	}
}

func TestClerkRefusesWhatKernelWouldNot(t *testing.T) {
	f := setup(t, key.Trash)
	send := stepOf(key.Send)
	bad := f.request("i2", f.root, send)
	if r := f.mail.Do(bad, f.view()); r.Outcome != "failed" {
		t.Fatal("verb outside the key must be refused at the clerk")
	}
	bank := stepOf(key.Trash)
	bank.Clerk = "bank"
	other := f.request("i3", f.root, bank)
	if r := f.mail.Do(other, f.view()); r.Outcome != "failed" {
		t.Fatal("step for another clerk must be refused")
	}
	if err := f.k.Revoke(2, f.root.Tip()); err != nil {
		t.Fatal(err)
	}
	rev := f.request("i4", f.root, stepOf(key.Trash))
	f.now = 3
	if r := f.mail.Do(rev, f.view()); r.Outcome != "failed" {
		t.Fatal("revoked key must be refused at the clerk")
	}
	if len(f.mail.Effects()) != 0 {
		t.Fatal("a refused step had an effect")
	}
}

func TestClerkRefusesUnknownRootAndUnheldIrreversible(t *testing.T) {
	f := setup(t, key.Trash)
	opub, opriv := gen(1)
	hpub, _ := gen(2)
	_ = opub
	ghost := key.Issue(opriv, key.Root{Holder: hpub, Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "unlogged"})
	r := f.request("i5", ghost, stepOf(key.Trash))
	if res := f.mail.Do(r, f.view()); res.Outcome != "failed" {
		t.Fatal("a root absent from the log must be refused")
	}
	g := setup(t, key.Unsubscribe)
	d, err := key.Derive(g.root, hpubPriv(), hpub, key.LimitHold(3600000, 4*3600000))
	if err != nil {
		t.Fatal(err)
	}
	u := g.request("i6", d, stepOf(key.Unsubscribe))
	g.now = 10 * 3600000
	if res := g.mail.Do(u, g.view()); res.Outcome != "failed" || len(g.mail.Effects()) != 0 {
		t.Fatal("an irreversible step that was never held must be refused")
	}
}

func hpubPriv() ed25519.PrivateKey { _, p := gen(2); return p }

func opubOf() ed25519.PublicKey { p, _ := gen(1); return p }

// The clerk takes the step from the plan the key's holder signed, so neither a
// kernel nor a transport can change what runs, and a key's bytes alone run
// nothing (KEY-1, KEY-3).
func TestClerkRunsOnlyWhatTheHolderSigned(t *testing.T) {
	f := setup(t, key.Trash)
	swapped := f.req
	swapped.Plan.Steps = []kernel.PlanStep{stepOf(key.Trash)}
	swapped.Plan.Steps[0].Args["target"] = "y"
	stranger := f.req
	_, spriv := gen(9)
	stranger.Plan = kernel.SignPlan(kernel.Plan{ID: "i1", Key: f.root, Steps: f.req.Plan.Steps}, spriv)
	unsigned := f.req
	unsigned.Plan.Sig = nil
	outside := f.req
	outside.Index = 1
	for name, r := range map[string]kernel.Request{"swapped step": swapped, "stranger": stranger, "unsigned": unsigned, "index outside the plan": outside} {
		if rf := clerk.Check(opubOf(), "mail", f.mail.Facts, 1, r, f.view()); rf == nil {
			t.Errorf("%s: accepted", name)
		}
		if res := f.mail.Do(r, f.view()); res.Outcome != "failed" {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if len(f.mail.Effects()) != 0 {
		t.Fatal("a refused request had an effect")
	}
}

// The clerk acts only on a step the log has in flight now, from the very plan
// the log admitted: a request for a step never dispatched, one already
// settled, or another plan the holder signed under a logged id is refused, on
// the real log's view (CLK-2, KRN-8).
func TestClerkRefusesAStepTheLogDoesNotHaveInFlight(t *testing.T) {
	f := setup(t, key.Trash)
	admitted := kernel.SignPlan(kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{stepOf(key.Trash)}}, hpubPriv())
	other := stepOf(key.Trash)
	other.Args["target"] = "y"
	twin := kernel.SignPlan(kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{other}}, hpubPriv())
	check := func(r kernel.Request) *key.Refusal {
		return clerk.Check(opubOf(), "mail", f.mail.Facts, f.now, r, f.k.State())
	}
	var during [2]*key.Refusal
	f.mail.Fault = func(op string, _ kernel.Request) string {
		if op == "do" { // the kernel has the step in flight now
			during = [2]*key.Refusal{check(kernel.Request{Plan: admitted}), check(kernel.Request{Plan: twin})}
		}
		return clerk.FaultNone
	}
	if err := f.k.Submit(1, admitted); err != nil {
		t.Fatal(err)
	}
	if rf := check(kernel.Request{Plan: admitted}); rf == nil || rf.Code != clerk.RDispatch {
		t.Fatalf("an admitted step not yet dispatched: %v", rf)
	}
	if err := f.k.Tick(1); err != nil {
		t.Fatal(err)
	}
	if during[0] != nil {
		t.Fatalf("the step in flight was refused: %v", during[0])
	}
	if during[1] == nil || during[1].Code != clerk.RDispatch {
		t.Fatalf("another plan under the logged id passed: %v", during[1])
	}
	if rf := check(kernel.Request{Plan: admitted}); rf == nil || rf.Code != clerk.RDispatch {
		t.Fatalf("a settled step redelivered: %v", rf)
	}
	if n := len(f.mail.Effects()); n != 1 {
		t.Fatalf("%d effects, want 1", n)
	}
}

// Every clerk judges claims with its own facts; one without facts refuses
// every step rather than take the planner's word (KEY-2, CLK-2).
func TestClerkWithoutFactsRefuses(t *testing.T) {
	f := setup(t, key.Trash)
	if rf := clerk.Check(opubOf(), "mail", nil, f.now, f.req, f.view()); rf == nil || rf.Code != clerk.RClaim {
		t.Fatalf("a clerk with no facts passed a step: %v", rf)
	}
	claim := stepOf(key.Trash)
	claim.Content = "invoice"
	if r := f.mail.Do(f.request("i2", f.root, claim), f.view()); r.Outcome != "failed" || r.Detail != clerk.RClaim || len(f.mail.Effects()) != 0 {
		t.Fatalf("a claim the mailbox does not read was taken as given: %+v", r)
	}
}
