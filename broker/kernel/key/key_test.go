package key

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// REQ: KEY-1, KEY-2, KEY-3, KEY-4, KEY-6, KEY-7, KEY-8

type kp struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func gen(seed byte) kp {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return kp{p.Public().(ed25519.PublicKey), p}
}

type ledger map[ID][]Use

func (l ledger) Uses(id ID) []Use { return l[id] }

func ctx(now int64, l ledger) Context {
	return Context{Now: now, Changes: &Changes{Revoked: map[ID]bool{}, Paused: map[ID]bool{}}, Ledger: l}
}

func root(t *testing.T) (kp, kp, Key) {
	owner, holder := gen(1), gen(2)
	k := Issue(owner.priv, Root{Holder: holder.pub, Clerk: "mail", Verbs: []Verb{Organize, Trash, Unsubscribe}, Serial: "r1"})
	return owner, holder, k
}

// verified is a use of k by its holder: the only way to a Verified.
func verified(t *testing.T, k Key, owner, holder kp) *Verified {
	use := []byte("use")
	v, err := Verify(k, owner.pub, use, Sign(k, holder.priv, use))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func step(v Verb) Step {
	s := Step{Verb: v, Clerk: "mail", Args: map[string]Arg{}}
	for _, n := range ArgNames(v) {
		s.Args[n] = Arg{Value: "x"}
	}
	return s
}

func TestRootAuthorizesItsVerbsOnly(t *testing.T) {
	o, _, k := root(t)
	v := verified(t, k, o, gen(2))
	if r := v.Authorize(step(Trash), ctx(1, nil)); r != nil {
		t.Fatal(r)
	}
	if r := v.Authorize(step(Send), ctx(1, nil)); r == nil || r.Code != RVerb {
		t.Fatalf("send: %v", r)
	}
	s := step(Trash)
	s.Clerk = "bank"
	if r := v.Authorize(s, ctx(1, nil)); r == nil || r.Code != RClerk {
		t.Fatalf("clerk: %v", r)
	}
}

func TestWrongOwnerAndBadSig(t *testing.T) {
	o, h, k := root(t)
	if err := CheckChain(k, gen(9).pub); !errors.Is(err, ErrWrongOwner) {
		t.Fatal(err)
	}
	bad := k
	bad.Root.Clerk = "bank"
	if err := CheckChain(bad, o.pub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("tampered root: %v", err)
	}
	d, err := Derive(k, h.priv, gen(3).pub, LimitVerbs(Trash))
	if err != nil {
		t.Fatal(err)
	}
	d.Links[0].Caveats[0] = LimitVerbs(Trash, Organize)
	if err := CheckChain(d, o.pub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("tampered link: %v", err)
	}
}

func TestDomainsDoNotCross(t *testing.T) {
	o, _, k := root(t)
	// A root signature must not verify as a link, nor the reverse.
	if DomainRoot == DomainLink {
		t.Fatal("domains equal")
	}
	sig := ed25519.Sign(o.priv, append([]byte(DomainLink), rootBody(k.Root)...))
	k.Root.Sig = sig
	if err := CheckChain(k, o.pub); !errors.Is(err, ErrBadSig) {
		t.Fatal(err)
	}
}

func TestDeriveNarrowsAndNeverLoosens(t *testing.T) {
	o, h, k := root(t)
	h2 := gen(3)
	d, err := Derive(k, h.priv, h2.pub, LimitVerbs(Trash, Organize))
	if err != nil {
		t.Fatal(err)
	}
	if r := verified(t, d, o, gen(3)).Authorize(step(Unsubscribe), ctx(1, nil)); r == nil || r.Code != RVerb {
		t.Fatalf("narrowed verb: %v", r)
	}
	if _, err := Derive(d, h2.priv, gen(4).pub, LimitVerbs(Trash, Send)); !errors.Is(err, ErrLoosens) {
		t.Fatalf("widen verbs: %v", err)
	}
	if _, err := Derive(k, gen(9).priv, gen(4).pub); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("not holder: %v", err)
	}
	// A hostile holder signs a loosening link directly; Verify rejects it.
	e := Extend(d, h2.priv, Link{Caveats: []Caveat{LimitVerbs(Trash, Organize, Unsubscribe)}, Holder: gen(4).pub})
	if err := CheckChain(e, o.pub); !errors.Is(err, ErrLoosens) {
		t.Fatalf("hostile widen: %v", err)
	}
	// Dropping a limit by omission is not a loosening, but a later larger cap is.
	c1, _ := Derive(k, h.priv, h2.pub, LimitSpendDay(100), LimitExpires(1000), LimitHold(10, 20))
	for _, bad := range []Caveat{LimitSpendDay(101), LimitExpires(1001), LimitHold(5, 20), LimitHold(10, 19)} {
		e := Extend(c1, h2.priv, Link{Caveats: []Caveat{bad}, Holder: gen(4).pub})
		if err := CheckChain(e, o.pub); !errors.Is(err, ErrLoosens) {
			t.Fatalf("%v: %v", bad.Kind, err)
		}
	}
}

func TestUnknownKindAndNonCanonicalRejected(t *testing.T) {
	o, h, k := root(t)
	e := Extend(k, h.priv, Link{Caveats: []Caveat{{Kind: "anything"}}, Holder: gen(4).pub})
	if err := CheckChain(e, o.pub); !errors.Is(err, ErrUnknownKind) {
		t.Fatal(err)
	}
	e = Extend(k, h.priv, Link{Caveats: []Caveat{{Kind: KVerbs, Set: []string{"trash", "organize"}}}, Holder: gen(4).pub})
	if err := CheckChain(e, o.pub); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unsorted: %v", err)
	}
}

func TestExpiryRevokePauseStop(t *testing.T) {
	o, h, k := root(t)
	d, _ := Derive(k, h.priv, gen(3).pub, LimitExpires(100))
	v := verified(t, d, o, gen(3))
	if r := v.Authorize(step(Trash), ctx(99, nil)); r != nil {
		t.Fatal(r)
	}
	if r := v.Authorize(step(Trash), ctx(100, nil)); r == nil || r.Code != RExpired {
		t.Fatalf("expiry: %v", r)
	}
	c := ctx(1, nil)
	c.Changes.Revoked[v.Root()] = true // revoking a prefix revokes the derived key
	if r := v.Authorize(step(Trash), c); r == nil || r.Code != RRevoked {
		t.Fatalf("revoked: %v", r)
	}
	c = ctx(1, nil)
	c.Changes.Paused[v.ID()] = true
	if r := v.Authorize(step(Trash), c); r == nil || r.Code != RPaused {
		t.Fatalf("paused: %v", r)
	}
	c = ctx(1, nil)
	c.Changes.Stopped = true
	if r := v.Authorize(step(Trash), c); r == nil || r.Code != RStopped {
		t.Fatalf("stopped: %v", r)
	}
	if r := v.Authorize(step(Trash), Context{Now: 1}); r == nil {
		t.Fatal("nil view must fail closed")
	}
}

func TestArgBoundsNeedNonPlannerSource(t *testing.T) {
	o, h, k := root(t)
	lo, hi := int64(1), int64(5)
	d, _ := Derive(k, h.priv, gen(3).pub,
		LimitArg(ArgBound{Name: "target", OneOf: []string{"b", "a"}}),
		LimitArg(ArgBound{Name: "label", Min: &lo, Max: &hi}))
	v := verified(t, d, o, gen(3))
	mk := func(to, n string, src Source) Step {
		s := step(Organize)
		s.Args = map[string]Arg{"target": {to, src}, "label": {n, src}}
		return s
	}
	if r := v.Authorize(mk("a", "3", SrcClerk), ctx(1, nil)); r != nil {
		t.Fatal(r)
	}
	for name, s := range map[string]Step{
		"planner": mk("a", "3", SrcPlanner), "set": mk("c", "3", SrcOwner), "low": mk("a", "0", SrcOwner),
		"high": mk("a", "6", SrcOwner), "nan": mk("a", "x", SrcOwner), "missing": step(Organize),
	} {
		if r := v.Authorize(s, ctx(1, nil)); r == nil || r.Code != RArg {
			t.Fatalf("%s: %v", name, r)
		}
	}
}

func TestContentAndLabels(t *testing.T) {
	o, h, k := root(t)
	d, _ := Derive(k, h.priv, gen(3).pub, LimitContent("text"), LimitLabels("public"))
	v := verified(t, d, o, gen(3))
	s := step(Trash)
	s.Content, s.Labels = "text", []string{"public"}
	if r := v.Authorize(s, ctx(1, nil)); r != nil {
		t.Fatal(r)
	}
	s.Content = "file"
	if r := v.Authorize(s, ctx(1, nil)); r == nil || r.Code != RContent {
		t.Fatal(r)
	}
	s.Content, s.Labels = "text", []string{"public", "medical"}
	if r := v.Authorize(s, ctx(1, nil)); r == nil || r.Code != RLabels {
		t.Fatal(r)
	}
}

func TestCapsChargeEveryPrefix(t *testing.T) {
	o, h, k := root(t)
	h2 := gen(3)
	parent, _ := Derive(k, h.priv, h2.pub, LimitUses(2), LimitSpendDay(50), LimitRate(5), LimitRateRecipient(1))
	child, _ := Derive(parent, h2.priv, gen(4).pub, LimitSpendTask(10))
	v := verified(t, child, o, gen(4))
	pid := v.IDs[1]
	s := step(Trash)
	s.Amount, s.Task, s.Recipient = 10, "t1", "r"
	if r := v.Authorize(s, ctx(1000, ledger{})); r != nil {
		t.Fatal(r)
	}
	s.Amount = 11
	if r := v.Authorize(s, ctx(1000, ledger{})); r == nil || r.Code != RSpendTask {
		t.Fatalf("task: %v", r)
	}
	// A sibling's uses, charged to the parent, count against the child.
	l := ledger{pid: {{At: 900, Amount: 45, Recipient: "x", Task: "other"}}}
	s.Amount = 6
	if r := v.Authorize(s, ctx(1000, l)); r == nil || r.Code != RSpendDay {
		t.Fatalf("day: %v", r)
	}
	l = ledger{pid: {{At: 900, Recipient: "r"}}}
	s.Amount = 1
	if r := v.Authorize(s, ctx(1000, l)); r == nil || r.Code != RRate {
		t.Fatalf("recipient: %v", r)
	}
	l = ledger{pid: {{At: 1, Recipient: "a"}, {At: 2, Recipient: "b"}}}
	s.Amount = 0
	if r := v.Authorize(s, ctx(1000, l)); r == nil || r.Code != RUses {
		t.Fatalf("uses: %v", r)
	}
	// Rolling window: old uses fall out of day-scoped caps.
	l = ledger{pid: {{At: 1, Amount: 50, Recipient: "r"}}}
	s.Amount = 1
	if r := v.Authorize(s, ctx(DayMS+2, l)); r != nil {
		t.Fatalf("rolled: %v", r)
	}
	nl := ctx(1000, nil)
	nl.Ledger = nil
	if r := v.Authorize(s, nl); r == nil || r.Code != RMalformed {
		t.Fatal("caps without a ledger must fail closed")
	}
}

func TestHoldIsLongestAndNoveltyLonger(t *testing.T) {
	o, h, k := root(t)
	h2 := gen(3)
	a, _ := Derive(k, h.priv, h2.pub, LimitHold(10, 30))
	b, _ := Derive(a, h2.priv, gen(4).pub, LimitHold(20, 30))
	l := verified(t, b, o, gen(4)).Limits
	if l.Window(false) != 20 || l.Window(true) != 30 {
		t.Fatalf("%d %d", l.Window(false), l.Window(true))
	}
}

func TestVerbClasses(t *testing.T) {
	if c, ok := ClassOf(Trash); !ok || c.Irreversible() {
		t.Fatal("trash is reversible")
	}
	if c, ok := ClassOf(Buy); !ok || !c.Irreversible() {
		t.Fatal("buy is irreversible")
	}
	if _, ok := ClassOf("nuke"); ok {
		t.Fatal("unknown verb")
	}
}

// A key is not a bearer token: holding its bytes confers nothing without the
// last holder's signature over the use. Dropping links leaves a key whose
// holder is someone the submitter cannot sign for, and a link forged or
// re-derived off a key the forger does not hold breaks the chain (KEY-1, KEY-3).
func TestUseNeedsTheLastHolder(t *testing.T) {
	o, h, k := root(t)
	planner := gen(3)
	d, err := Derive(k, h.priv, planner.pub, LimitRate(2))
	if err != nil {
		t.Fatal(err)
	}
	use := []byte("plan")
	if _, err := Verify(d, o.pub, use, Sign(d, planner.priv, use)); err != nil {
		t.Fatalf("holder's own use: %v", err)
	}
	stripped := Key{Root: d.Root}
	if _, err := Verify(stripped, o.pub, use, Sign(stripped, planner.priv, use)); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("stripped key: %v", err)
	}
	if _, err := Verify(d, o.pub, use, nil); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("unsigned use: %v", err)
	}
	sig := Sign(d, planner.priv, use)
	if _, err := Verify(d, o.pub, []byte("other plan"), sig); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("signature moved to another use: %v", err)
	}
	// The signature binds the tip: the same use under a sibling key fails.
	sib, _ := Derive(k, h.priv, planner.pub, LimitRate(3))
	if _, err := Verify(sib, o.pub, use, sig); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("signature moved to another key: %v", err)
	}
	// Re-derived off the root, or a wider link forged in place, by the planner.
	for name, f := range map[string]Key{
		"re-derived": Extend(k, planner.priv, Link{Caveats: []Caveat{LimitRate(1000)}, Holder: planner.pub}),
		"rewritten":  Extend(stripped, planner.priv, Link{Holder: planner.pub}),
	} {
		if _, err := Verify(f, o.pub, use, Sign(f, planner.priv, use)); !errors.Is(err, ErrBadSig) {
			t.Fatalf("%s link: %v", name, err)
		}
	}
	if _, err := Derive(stripped, planner.priv, planner.pub); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("derive from a stripped key: %v", err)
	}
	// Domains: a use signature is not a link signature, nor the reverse.
	if DomainUse == DomainLink || DomainUse == DomainRoot {
		t.Fatal("domains equal")
	}
}

// A key checked as a chain alone can be charged for spend, which moves no
// step, and never authorizes one: nobody has signed as its holder.
func TestChainAloneNeverAuthorizes(t *testing.T) {
	o, h, k := root(t)
	d, err := Derive(k, h.priv, gen(3).pub, LimitSpendTask(10))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Chain(d, o.pub)
	if err != nil {
		t.Fatal(err)
	}
	if r := v.Spend("t", 5, ctx(1, ledger{})); r != nil {
		t.Fatalf("a chained key funds spend: %v", r)
	}
	if r := v.Authorize(step(Trash), ctx(1, ledger{})); r == nil || r.Code != RMalformed {
		t.Fatalf("a chained key authorizes a step: %v", r)
	}
	if _, err := Chain(d, gen(9).pub); !errors.Is(err, ErrWrongOwner) {
		t.Fatalf("wrong owner: %v", err)
	}
}
