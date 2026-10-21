package key

import (
	"bytes"
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

// root is the passkey (owner), the home clerk (holder) and the passkey's
// clerk key to it, which no step's spend or time here reaches (D-146).
func root(t *testing.T) (kp, kp, Key) {
	owner, holder := gen(1), gen(2)
	k, err := ClerkKey(bare(owner), owner.priv, holder.pub, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	return owner, holder, k
}

func bare(owner kp) Key {
	return Issue(owner.priv, Root{Clerk: "mail", Verbs: []Verb{Organize, Trash, Unsubscribe}, Serial: "r1"})
}

// verified is a use of k by its holder: the only way to a Verified.
func verified(t *testing.T, k Key, owner, holder kp) *Verified {
	use := []byte("use")
	v, err := Verify(k, []ed25519.PublicKey{owner.pub}, use, Sign(k, holder.priv, use))
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
	if _, err := Chain(k, []ed25519.PublicKey{gen(9).pub}); !errors.Is(err, ErrWrongOwner) {
		t.Fatal(err)
	}
	bad := k
	bad.Root.Clerk = "bank"
	if _, err := Chain(bad, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrBadSig) {
		t.Fatalf("tampered root: %v", err)
	}
	d, err := Derive(k, h.priv, gen(3).pub, LimitVerbs(Trash))
	if err != nil {
		t.Fatal(err)
	}
	d.Links[0].Caveats[0] = LimitVerbs(Trash, Organize)
	if _, err := Chain(d, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrBadSig) {
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
	if _, err := Chain(k, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrBadSig) {
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
	if _, err := Chain(e, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrLoosens) {
		t.Fatalf("hostile widen: %v", err)
	}
	// Dropping a limit by omission is not a loosening, but a later larger cap is.
	c1, _ := Derive(k, h.priv, h2.pub, LimitSpendDay(100), LimitExpires(1000), LimitHold(10, 20))
	for _, bad := range []Caveat{LimitSpendDay(101), LimitExpires(1001), LimitHold(5, 20), LimitHold(10, 19)} {
		e := Extend(c1, h2.priv, Link{Caveats: []Caveat{bad}, Holder: gen(4).pub})
		if _, err := Chain(e, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrLoosens) {
			t.Fatalf("%v: %v", bad.Kind, err)
		}
	}
}

func TestUnknownKindAndNonCanonicalRejected(t *testing.T) {
	o, h, k := root(t)
	e := Extend(k, h.priv, Link{Caveats: []Caveat{{Kind: "anything"}}, Holder: gen(4).pub})
	if _, err := Chain(e, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrUnknownKind) {
		t.Fatal(err)
	}
	e = Extend(k, h.priv, Link{Caveats: []Caveat{{Kind: KVerbs, Set: []string{"trash", "organize"}}}, Holder: gen(4).pub})
	if _, err := Chain(e, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrMalformed) {
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
	pid := v.IDs[2]
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
	if _, err := Verify(d, []ed25519.PublicKey{o.pub}, use, Sign(d, planner.priv, use)); err != nil {
		t.Fatalf("holder's own use: %v", err)
	}
	stripped := Key{Root: d.Root}
	if _, err := Verify(stripped, []ed25519.PublicKey{o.pub}, use, Sign(stripped, planner.priv, use)); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("stripped key: %v", err)
	}
	if _, err := Verify(d, []ed25519.PublicKey{o.pub}, use, nil); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("unsigned use: %v", err)
	}
	sig := Sign(d, planner.priv, use)
	if _, err := Verify(d, []ed25519.PublicKey{o.pub}, []byte("other plan"), sig); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("signature moved to another use: %v", err)
	}
	// The signature binds the tip: the same use under a sibling key fails.
	sib, _ := Derive(k, h.priv, planner.pub, LimitRate(3))
	if _, err := Verify(sib, []ed25519.PublicKey{o.pub}, use, sig); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("signature moved to another key: %v", err)
	}
	// Re-derived off the root, or a wider link forged in place, by the planner.
	for name, f := range map[string]Key{
		"re-derived": Extend(k, planner.priv, Link{Caveats: []Caveat{LimitRate(1000)}, Holder: planner.pub}),
		"rewritten":  Extend(stripped, planner.priv, Link{Holder: planner.pub}),
	} {
		if _, err := Verify(f, []ed25519.PublicKey{o.pub}, use, Sign(f, planner.priv, use)); !errors.Is(err, ErrBadSig) {
			t.Fatalf("%s link: %v", name, err)
		}
	}
	// A link the planner derives off the bare root is not a passkey's.
	if d, err := Derive(stripped, planner.priv, planner.pub, LimitExpires(1000), LimitSpendDay(1)); err != nil {
		t.Fatalf("derive from a stripped key: %v", err)
	} else if _, err := Chain(d, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrBadSig) {
		t.Fatalf("a link off a stripped key: %v", err)
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
	v, err := Chain(d, []ed25519.PublicKey{o.pub})
	if err != nil {
		t.Fatal(err)
	}
	if r := v.Spend("t", 5, ctx(1, ledger{})); r != nil {
		t.Fatalf("a chained key funds spend: %v", r)
	}
	if r := v.Authorize(step(Trash), ctx(1, ledger{})); r == nil || r.Code != RMalformed {
		t.Fatalf("a chained key authorizes a step: %v", r)
	}
	if _, err := Chain(d, []ed25519.PublicKey{gen(9).pub}); !errors.Is(err, ErrWrongOwner) {
		t.Fatalf("wrong owner: %v", err)
	}
}

// Full power stays with the owner's root: a key derived from it carries at
// least one caveat, so a leaked child is always capped (D-145). Derive refuses
// one without, and a link the root's holder signs by hand is refused by
// Verify and Chain alike; a key below a caveated one need add none.
func TestKeyOffTheRootLapsesAndIsCapped(t *testing.T) {
	o, h := gen(1), gen(2)
	r := bare(o)
	cases := map[string][]Caveat{
		"no caveat":    nil,
		"verbs only":   {LimitVerbs(Trash)},
		"no spend cap": {LimitExpires(1000), LimitSpendTask(5)},
		"no expiry":    {LimitSpendDay(5), LimitUses(3)},
	}
	use := []byte("plan")
	for name, cav := range cases {
		if _, err := Derive(r, o.priv, h.pub, cav...); !errors.Is(err, ErrUncaveated) {
			t.Fatalf("%s: derive: %v", name, err)
		}
		k := Extend(r, o.priv, Link{Caveats: cav, Holder: h.pub})
		if _, err := Verify(k, []ed25519.PublicKey{o.pub}, use, Sign(k, h.priv, use)); !errors.Is(err, ErrUncaveated) {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if _, err := Chain(k, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrUncaveated) {
			t.Fatalf("%s: chain: %v", name, err)
		}
	}
	d, err := ClerkKey(r, o.priv, h.pub, 500, 7)
	if err != nil {
		t.Fatal(err)
	}
	v := verified(t, d, o, h)
	if *v.Limits.NotAfter != 500+ClerkLife {
		t.Fatalf("clerk key lives %d", *v.Limits.NotAfter-500)
	}
	if rf := v.Authorize(step(Trash), ctx(500+ClerkLife+1, nil)); rf == nil || rf.Code != RExpired {
		t.Fatalf("a lapsed clerk key: %v", rf)
	}
	g, err := Derive(d, h.priv, gen(4).pub)
	if err != nil {
		t.Fatalf("a key below the clerk key inherits its limits: %v", err)
	}
	if _, err := Verify(g, []ed25519.PublicKey{o.pub}, use, Sign(g, gen(4).priv, use)); err != nil {
		t.Fatalf("verify the grandchild: %v", err)
	}
}

// The bare root is the passkey's: the home clerk, or anyone but the passkey,
// can neither use it nor sign a link off it (D-146).
func TestBareRootIsThePasskeysAlone(t *testing.T) {
	o, h := gen(1), gen(2)
	r := bare(o)
	use := []byte("plan")
	if _, err := Verify(r, []ed25519.PublicKey{o.pub}, use, Sign(r, h.priv, use)); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("the home clerk signs under the bare root: %v", err)
	}
	if _, err := Verify(r, []ed25519.PublicKey{o.pub}, use, Sign(r, o.priv, use)); err != nil {
		t.Fatalf("the passkey signs under the bare root: %v", err)
	}
	k := Extend(r, h.priv, Link{Caveats: []Caveat{LimitExpires(1000), LimitSpendDay(1)}, Holder: h.pub})
	if _, err := Chain(k, []ed25519.PublicKey{o.pub}); !errors.Is(err, ErrBadSig) {
		t.Fatalf("a link off the root not signed by the passkey: %v", err)
	}
}

func TestPasskeysAreTheAnchorsAndWhatTheyEnroll(t *testing.T) {
	hw1, hw2, phone, old, stranger := gen(1), gen(5), gen(6), gen(8), gen(7)
	anchors := []ed25519.PublicKey{hw1.pub, hw2.pub}
	es := []Enrollment{
		Enroll(stranger.priv, stranger.pub), // signed by no anchor
		Enroll(hw1.priv, old.pub),
		Enroll(hw2.priv, phone.pub),
		Enroll(phone.priv, gen(9).pub), // a phone enrolls nothing
		{Passkey: stranger.pub, By: hw1.pub, Sig: Enroll(stranger.priv, stranger.pub).Sig}, // forged
	}
	set := Passkeys(anchors, es, nil)
	if len(set) != 4 || !In(set, phone.pub) || !In(set, old.pub) || In(set, stranger.pub) || In(set, gen(9).pub) {
		t.Fatalf("set: %d keys", len(set))
	}
	// The lost phone is revoked; its enrollment, replayed, does not bring it back.
	set = Passkeys(anchors, append(es, Enroll(hw1.priv, old.pub)), []ed25519.PublicKey{old.pub})
	if In(set, old.pub) || !In(set, phone.pub) {
		t.Fatal("a revoked passkey stays out")
	}
	// A list that names an anchor cuts nothing: only recovery replaces one.
	if set := Passkeys(anchors, es, []ed25519.PublicKey{hw2.pub}); !In(set, phone.pub) || !In(set, hw2.pub) {
		t.Fatal("an anchor and what it enrolled stay in")
	}
	r := Issue(phone.priv, Root{Clerk: "mail", Verbs: []Verb{Trash}, Serial: "b"})
	if _, err := Chain(r, set); err != nil {
		t.Fatalf("a root the enrolled phone issued: %v", err)
	}
	for _, by := range []kp{old, stranger} {
		s := Issue(by.priv, Root{Clerk: "mail", Verbs: []Verb{Trash}, Serial: "s"})
		if _, err := Chain(s, set); !errors.Is(err, ErrWrongOwner) {
			t.Fatalf("a root no passkey in the set issued: %v", err)
		}
	}
}

func TestNarrowKeepsTheHolderAndNeverLoosens(t *testing.T) {
	o, h, k := root(t)
	if _, err := Narrow(bare(o), o.priv, LimitUses(1)); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("a passkey's link off a bare root is a grant: %v", err)
	}
	if _, err := Narrow(k, o.priv, LimitVerbs(Trash, Send)); !errors.Is(err, ErrLoosens) {
		t.Fatalf("widen verbs: %v", err)
	}
	n, err := Narrow(k, o.priv, LimitVerbs(Trash))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(n, []ed25519.PublicKey{o.pub}, []byte("use"), Sign(n, h.priv, []byte("use")))
	if err != nil || !v.ByOwner || !bytes.Equal(v.Narrowers[0], o.pub) || !bytes.Equal(n.Links[1].Holder, h.pub) {
		t.Fatalf("the holder uses the owner's narrowing: %v", err)
	}
	d, err := Derive(n, h.priv, gen(4).pub, LimitUses(1))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := Chain(d, []ed25519.PublicKey{o.pub}); err != nil || v.ByOwner || len(v.Narrowers) != 1 {
		t.Fatalf("a narrowing below it is the holder's, and the passkey still counts: %v", err)
	}
}

// Within holds when every limit the old link sets, the new one sets at least
// as tightly (#2670 item 5).
func TestWithin(t *testing.T) {
	lo, hi := int64(2), int64(9)
	old := []Caveat{LimitVerbs(Send, Trash), LimitContent("text"), LimitUses(3), LimitHold(10, 20), LimitTask("t1"),
		{Kind: KArg, Arg: &ArgBound{Name: "to", OneOf: []string{"a", "b"}, Min: &lo, Max: &hi}}}
	arg := func(oneOf []string, min, max *int64) Caveat {
		return Caveat{Kind: KArg, Arg: &ArgBound{Name: "to", OneOf: oneOf, Min: min, Max: max}}
	}
	one, three, ten := int64(1), int64(3), int64(10)
	b, err := Fold(old)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		cs     []Caveat
		within bool
	}{
		"same":            {old, true},
		"fewer verbs":     {replace(old, 0, LimitVerbs(Trash)), true},
		"another verb":    {replace(old, 0, LimitVerbs(Buy)), false},
		"no verbs":        {old[1:], false},
		"no content":      {append([]Caveat{old[0]}, old[2:]...), false},
		"fewer uses":      {replace(old, 2, LimitUses(1)), true},
		"more uses":       {replace(old, 2, LimitUses(4)), false},
		"shorter hold":    {replace(old, 3, LimitHold(5, 20)), false},
		"shorter novelty": {replace(old, 3, LimitHold(10, 15)), false},
		"no arg max":      {replace(old, 5, arg([]string{"a", "b"}, &lo, nil)), false},
		"another task":    {replace(old, 4, LimitTask("t2")), false},
		"narrower arg":    {replace(old, 5, arg([]string{"a"}, &three, &hi)), true},
		"no arg":          {old[:5], false},
		"wider arg set":   {replace(old, 5, arg([]string{"a", "b", "c"}, &lo, &hi)), false},
		"lower arg min":   {replace(old, 5, arg([]string{"a", "b"}, nil, &hi)), false},
		"a min below":     {replace(old, 5, arg([]string{"a", "b"}, &one, &hi)), false},
		"higher arg max":  {replace(old, 5, arg([]string{"a", "b"}, &lo, &ten)), false},
		"open arg values": {replace(old, 5, arg(nil, &lo, &hi)), false},
	} {
		l, err := Fold(c.cs)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if l.Within(b) != c.within {
			t.Errorf("%s: within %v, want %v", name, !c.within, c.within)
		}
	}
	// A bare bound is a limit too: the arg may not come from the planner
	// (KEY-2), so dropping it widens.
	bare, err := Fold([]Caveat{LimitVerbs(Trash), {Kind: KArg, Arg: &ArgBound{Name: "target"}}})
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := Fold([]Caveat{LimitVerbs(Trash)}); l.Within(bare) {
		t.Error("dropped bare bound: within")
	}
}

func replace(cs []Caveat, i int, c Caveat) []Caveat {
	out := append([]Caveat(nil), cs...)
	out[i] = c
	return out
}
