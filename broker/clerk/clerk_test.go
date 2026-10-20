package clerk_test

// REQ: CLK-2

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
	step := key.Step{Verb: verb, Clerk: "mail", Recipient: "x", Task: "t",
		Args: map[string]key.Arg{"msg": {Value: "x", Source: key.SrcClerk}}}
	return &fix{k, mail, root, kernel.Request{Plan: "p", Step: step, Key: root, Idem: "i1", Now: 1}}
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
	bad := f.req
	bad.Idem, bad.Step.Verb = "i2", key.Send
	if r := f.mail.Do(bad, f.k.State()); r.Outcome != "failed" {
		t.Fatal("verb outside the key must be refused at the clerk")
	}
	other := f.req
	other.Idem, other.Step.Clerk = "i3", "bank"
	if r := f.mail.Do(other, f.k.State()); r.Outcome != "failed" {
		t.Fatal("step for another clerk must be refused")
	}
	v, _ := key.Verify(f.root, opubOf())
	if err := f.k.Revoke(2, v.ID()); err != nil {
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
	r := f.req
	r.Key, r.Idem = ghost, "i5"
	if res := f.mail.Do(r, f.k.State()); res.Outcome != "failed" {
		t.Fatal("a root absent from the log must be refused")
	}
	g := setup(t, key.Unsubscribe)
	d, err := key.Derive(g.root, hpubPriv(), hpub, key.LimitHold(3600000, 4*3600000))
	if err != nil {
		t.Fatal(err)
	}
	u := g.req
	u.Key, u.Idem, u.Now = d, "i6", 10*3600000
	if res := g.mail.Do(u, g.k.State()); res.Outcome != "failed" || len(g.mail.Effects()) != 0 {
		t.Fatal("an irreversible step that was never held must be refused")
	}
}

func hpubPriv() ed25519.PrivateKey { _, p := gen(2); return p }

func opubOf() ed25519.PublicKey { p, _ := gen(1); return p }
