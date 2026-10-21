package kernel_test

// REQ: KEY-4, KEY-6, ID-1

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func approve(by pair, keys ...key.Key) []key.Cosign {
	return []key.Cosign{key.Approve(by.priv, kernel.BatchHash(keys...))}
}

// A grant of new power needs two passkeys, one an anchor: the one that signs
// it and a co-signer. The same passkey twice, a key that is no passkey, or
// two phones with no hardware key count as one or none (D-146).
func TestABigGrantNeedsASecondPasskey(t *testing.T) {
	r := newRig(t)
	phone, phone2 := gen(8), gen(9)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone.pub)))
	must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone2.pub)))
	batch := func(serial string, by pair) []key.Key {
		root := key.Issue(by.priv, key.Root{Clerk: "bank", Verbs: []key.Verb{key.Buy}, Serial: serial})
		ck, err := key.ClerkKey(root, by.priv, r.holder.pub, 0, 10)
		must(t, err)
		return []key.Key{root, ck}
	}
	refused := map[string]struct {
		by  pair
		cos func([]key.Key) []key.Cosign
	}{
		"none":                {r.owner, func([]key.Key) []key.Cosign { return nil }},
		"the signer itself":   {r.owner, func(ks []key.Key) []key.Cosign { return approve(r.owner, ks...) }},
		"the home clerk":      {r.owner, func(ks []key.Key) []key.Cosign { return approve(r.holder, ks...) }},
		"two phones":          {phone, func(ks []key.Key) []key.Cosign { return approve(phone2, ks...) }},
		"another batch's sig": {r.owner, func(ks []key.Key) []key.Cosign { return approve(r.spare, ks[0]) }},
	}
	for name, c := range refused {
		ks := batch("x-"+name, c.by)
		if err := r.k.Issue(0, c.cos(ks), ks...); !errors.Is(err, kernel.ErrNeedsCosign) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct{ by, co pair }{
		"phone and hardware key": {phone, r.spare},
		"hardware key and phone": {r.owner, phone},
	} {
		ks := batch("ok-"+name, c.by)
		if err := r.k.Issue(0, approve(c.co, ks...), ks...); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// The fold agrees: a big batch logged without its co-signer grants nothing.
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if len(re.Grants) != len(r.k.State().Grants) {
		t.Fatalf("replay grants %d, kernel %d", len(re.Grants), len(r.k.State().Grants))
	}
}

// Big is past the line: by default more than double the clerk's daily cap,
// or a verb it lacked. Grants still in their hold count, so two raises in
// one hold cannot each pass as small.
func TestTheLineDecidesWhatIsBig(t *testing.T) {
	r := newRig(t)
	at := 10 * hour
	ck := func(spendDay int64, c ...key.Caveat) key.Key {
		k, err := key.ClerkKey(key.Key{Root: r.ck.Root}, r.owner.priv, r.holder.pub, at, spendDay, c...)
		must(t, err)
		return k
	}
	const day = int64(1 << 40) // the rig's clerk key
	if err := r.k.Issue(at, nil, ck(2*day)); err != nil {
		t.Fatalf("double the cap is not big: %v", err)
	}
	if err := r.k.Issue(at, nil, ck(2*day, key.LimitUses(5))); err != nil {
		t.Fatalf("a raise in the same hold to the same cap: %v", err)
	}
	if err := r.k.Issue(at, nil, ck(2*day+1)); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("past double the live cap: %v", err)
	}
	wide := key.Issue(r.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash, key.Send}, Serial: "w"})
	if err := r.k.Issue(at, nil, wide); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a verb the passkeys' one-offs lacked: %v", err)
	}
	narrow := key.Issue(r.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "n"})
	if err := r.k.Issue(at, nil, narrow); err != nil {
		t.Fatalf("a root with verbs already granted: %v", err)
	}
	nk, err := key.ClerkKey(narrow, r.owner.priv, gen(7).pub, at, 1)
	must(t, err)
	if err := r.k.Issue(at, nil, nk); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a first key to a new holder: %v", err)
	}
	// Power that lapsed or was revoked is none: the same cap again is new.
	for name, f := range map[string]func(r *rig) int64{
		"lapsed":  func(*rig) int64 { return key.ClerkLife + hour },
		"revoked": func(r *rig) int64 { must(t, r.k.Revoke(at, r.ck.Tip())); return at },
	} {
		r := newRig(t)
		now := f(r)
		k, err := key.ClerkKey(key.Key{Root: r.ck.Root}, r.owner.priv, r.holder.pub, now, day)
		must(t, err)
		if err := r.k.Issue(now, nil, k); !errors.Is(err, kernel.ErrNeedsCosign) {
			t.Fatalf("the cap of a %s key again: %v", name, err)
		}
	}
}

// Raising the line is itself big; lowering it narrows. A co-signature names
// the change and how many came before, so it cannot be replayed; the line
// survives a replay.
func TestRaisingTheLineNeedsTwoPasskeys(t *testing.T) {
	r := newRig(t)
	raise := func(n int, pct int64, by ...pair) []key.Cosign {
		var cos []key.Cosign
		for _, p := range by {
			cos = append(cos, key.Approve(p.priv, kernel.LineHash(n, pct)))
		}
		return cos
	}
	if err := r.k.SetLine(1, 300); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a raise with no passkey: %v", err)
	}
	if err := r.k.SetLine(1, 300, raise(0, 300, r.owner)...); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a raise with one passkey: %v", err)
	}
	old := raise(0, 300, r.owner, r.spare)
	must(t, r.k.SetLine(1, 300, old...))
	must(t, r.k.SetLine(2, 150))
	if err := r.k.SetLine(3, 300, old...); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("an old approval replayed: %v", err)
	}
	if err := r.k.SetLine(3, 99); !errors.Is(err, kernel.ErrLine) {
		t.Fatalf("a line under 100%%: %v", err)
	}
	must(t, r.k.SetLine(3, 250, raise(2, 250, r.spare, r.owner)...))
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if re.Line != 250 || r.k.State().Line != 250 {
		t.Fatalf("line after replay %d, kernel %d", re.Line, r.k.State().Line)
	}
	if !kernel.Widening(kernel.TLine) {
		t.Fatal("a line change anchors")
	}
}

// A one-off under the bare root spends up to the line times the clerk's
// daily cap alone; past it, a second passkey co-signs it (D-146).
func TestAVeryLargeOneOffNeedsASecondPasskey(t *testing.T) {
	r := newRig(t)
	buy := r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "b"}), 100)
	bare := key.Key{Root: buy.Root}
	plan := func(id, amount string, cos ...pair) kernel.Plan {
		s := st(key.Buy, "shop-"+id)
		s.Args[key.ArgAmount] = amount
		p := kernel.SignPlan(kernel.Plan{ID: id, Key: bare, Steps: []kernel.PlanStep{s}}, r.owner.priv)
		for _, c := range cos {
			p.Cosigns = append(p.Cosigns, key.Approve(c.priv, kernel.PlanHash(p)))
		}
		return p
	}
	if got := r.k.State().OneOffLine(bare.Tip(), 0); got != 200 {
		t.Fatalf("one-off line %d", got)
	}
	cases := []struct {
		p    kernel.Plan
		want string
	}{
		{plan("p1", "200"), ""},
		{plan("p2", "201"), kernel.CCosign},
		{plan("p3", "201", r.owner), kernel.CCosign},
		{plan("p4", "201", r.holder), kernel.CCosign},
		{plan("p5", "201", r.spare), ""},
	}
	for _, c := range cases {
		if got := admits(r, c.p, 0); got != c.want {
			t.Fatalf("%s: %q, want %q", c.p.ID, got, c.want)
		}
	}
	// A co-signature names the plan: moved to another, it counts for nothing.
	moved := plan("p6", "300")
	moved.Cosigns = plan("p5", "201", r.spare).Cosigns
	if got := admits(r, moved, 0); got != kernel.CCosign {
		t.Fatalf("a co-signature moved to another plan: %q", got)
	}
	// With no live clerk key under the root, lapsed or revoked, any spend
	// needs a second passkey.
	if got := admits(r, plan("p8", "1"), key.ClerkLife+hour); got != kernel.CCosign {
		t.Fatalf("a one-off once the clerk key lapsed: %q", got)
	}
	must(t, r.k.Revoke(1, buy.Tip()))
	if got := admits(r, plan("p7", "1"), 2); got != kernel.CCosign {
		t.Fatalf("a one-off with no clerk key under its root: %q", got)
	}
}
