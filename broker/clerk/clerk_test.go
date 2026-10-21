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
	k    *kernel.Kernel
	mail *clerk.Mail
	root key.Key
	req  kernel.Request
}

func setup(t *testing.T, verb key.Verb) *fix {
	t.Helper()
	opub, opriv := gen(1)
	hpub, _ := gen(2)
	kpub, kpriv := gen(3)
	mail := clerk.NewMail("mail", opub)
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
	f := &fix{k: k, mail: mail, root: root}
	f.req = f.request(root, stepOf(verb))
	return f
}

func stepOf(verb key.Verb) kernel.PlanStep {
	ps := kernel.PlanStep{Verb: verb, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(verb) {
		ps.Args[n] = "x"
	}
	return ps
}

// request is ps under k, signed by the holder of every key here.
func (f *fix) request(k key.Key, ps kernel.PlanStep) kernel.Request {
	p := kernel.SignPlan(kernel.Plan{ID: "p", Key: k, Steps: []kernel.PlanStep{ps}}, hpubPriv())
	return kernel.Request{Plan: p, Idem: "i1", Now: 1}
}

func TestClerkRechecksAndIsIdempotent(t *testing.T) {
	f := setup(t, key.Trash)
	if r := f.mail.Do(f.req, f.k.State()); r.Outcome != "ok" {
		t.Fatalf("valid step refused: %+v", r)
	}
	if r := f.mail.Do(f.req, f.k.State()); r.Outcome != "ok" || len(f.mail.Effects()) != 1 {
		t.Fatal("same idempotency key must not act twice")
	}
	if f.mail.Probe(f.req, f.k.State()) != "done" {
		t.Fatal("probe must report done")
	}
}

func TestClerkRefusesWhatKernelWouldNot(t *testing.T) {
	f := setup(t, key.Trash)
	send := stepOf(key.Send)
	bad := f.request(f.root, send)
	bad.Idem = "i2"
	if r := f.mail.Do(bad, f.k.State()); r.Outcome != "failed" {
		t.Fatal("verb outside the key must be refused at the clerk")
	}
	bank := stepOf(key.Trash)
	bank.Clerk = "bank"
	other := f.request(f.root, bank)
	other.Idem = "i3"
	if r := f.mail.Do(other, f.k.State()); r.Outcome != "failed" {
		t.Fatal("step for another clerk must be refused")
	}
	if err := f.k.Revoke(2, f.root.Tip()); err != nil {
		t.Fatal(err)
	}
	rev := f.req
	rev.Idem, rev.Now = "i4", 3
	if r := f.mail.Do(rev, f.k.State()); r.Outcome != "failed" {
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
	r := f.request(ghost, stepOf(key.Trash))
	r.Idem = "i5"
	if res := f.mail.Do(r, f.k.State()); res.Outcome != "failed" {
		t.Fatal("a root absent from the log must be refused")
	}
	g := setup(t, key.Unsubscribe)
	d, err := key.Derive(g.root, hpubPriv(), hpub, key.LimitHold(3600000, 4*3600000))
	if err != nil {
		t.Fatal(err)
	}
	u := g.request(d, stepOf(key.Unsubscribe))
	u.Idem, u.Now = "i6", 10*3600000
	if res := g.mail.Do(u, g.k.State()); res.Outcome != "failed" || len(g.mail.Effects()) != 0 {
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
	stranger.Plan = kernel.SignPlan(kernel.Plan{ID: "p", Key: f.root, Steps: f.req.Plan.Steps}, spriv)
	unsigned := f.req
	unsigned.Plan.Sig = nil
	outside := f.req
	outside.Index = 1
	for name, r := range map[string]kernel.Request{"swapped step": swapped, "stranger": stranger, "unsigned": unsigned, "index outside the plan": outside} {
		if rf := clerk.Check(opubOf(), "mail", nil, r, f.k.State()); rf == nil {
			t.Errorf("%s: accepted", name)
		}
		if res := f.mail.Do(r, f.k.State()); res.Outcome != "failed" {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if len(f.mail.Effects()) != 0 {
		t.Fatal("a refused request had an effect")
	}
}
