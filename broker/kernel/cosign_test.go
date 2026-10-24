package kernel_test

// REQ: KEY-4, KEY-6, ID-1

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// approve is each passkey's co-signature over the batch keys.
func approve(keys []key.Key, by ...pair) []key.Cosign {
	var cos []key.Cosign
	for _, p := range by {
		cos = append(cos, key.Approve(p.priv, kernel.BatchHash(keys...)))
	}
	return cos
}

// A grant of new power needs two passkeys, one an anchor, each co-signing the
// whole batch. Signing the keys counts for nothing: a batch may carry a key
// a hardware key signed long ago. The same passkey twice, a key that is no
// passkey, or two phones with no hardware key count as one or none (D-146).
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
	// A phone's key to a new holder, beside the root or the clerk key a
	// hardware key granted.
	replayed := func(old key.Key) func(string, pair) []key.Key {
		return func(string, pair) []key.Key {
			ck, err := key.ClerkKey(key.Key{Root: r.ck.Root}, phone.priv, gen(7).pub, 0, 1<<50)
			must(t, err)
			return []key.Key{old, ck}
		}
	}
	refused := map[string]struct {
		by   pair
		keys func(string, pair) []key.Key
		cos  func([]key.Key) []key.Cosign
	}{
		"none":              {r.owner, batch, func([]key.Key) []key.Cosign { return nil }},
		"the signer alone":  {r.owner, batch, func(ks []key.Key) []key.Cosign { return approve(ks, r.owner) }},
		"one passkey twice": {r.owner, batch, func(ks []key.Key) []key.Cosign { return approve(ks, r.owner, r.owner) }},
		"the hardware key signed, a phone co-signed alone": {r.owner, batch, func(ks []key.Key) []key.Cosign { return approve(ks, phone) }},
		"the home clerk":            {r.owner, batch, func(ks []key.Key) []key.Cosign { return approve(ks, r.owner, r.holder) }},
		"two phones":                {phone, batch, func(ks []key.Key) []key.Cosign { return approve(ks, phone, phone2) }},
		"another batch's sig":       {r.owner, batch, func(ks []key.Key) []key.Cosign { return append(approve(ks, r.owner), approve(ks[:1], r.spare)...) }},
		"an old root replayed":      {phone, replayed(key.Key{Root: r.ck.Root}), func(ks []key.Key) []key.Cosign { return approve(ks, phone) }},
		"an old clerk key replayed": {phone, replayed(r.ck), func(ks []key.Key) []key.Cosign { return approve(ks, phone) }},
	}
	for name, c := range refused {
		ks := c.keys("x-"+name, c.by)
		if err := r.k.Issue(0, c.cos(ks), ks...); !errors.Is(err, kernel.ErrNeedsCosign) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct{ by, co pair }{
		"phone and hardware key": {phone, r.spare},
		"hardware key and phone": {r.owner, phone},
	} {
		ks := batch("ok-"+name, c.by)
		if err := r.k.Issue(0, approve(ks, c.by, c.co), ks...); err != nil {
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
// or a verb it lacked, against the live grants only: a grant still in its
// hold is not power yet, so two raises in one hold are each judged against
// the live cap, and power that lapsed, was revoked or is paused is none.
func TestTheLineDecidesWhatIsBig(t *testing.T) {
	r := newRig(t)
	at := 10 * hour
	ck := func(spendDay int64, c ...key.Caveat) key.Key {
		k, err := key.ClerkKey(key.Key{Root: r.ck.Root}, r.owner.priv, r.holder.pub, at, spendDay, c...)
		must(t, err)
		return k
	}
	ck2 := func(under key.Key, spendDay int64) key.Key {
		k, err := key.ClerkKey(key.Key{Root: under.Root}, r.owner.priv, r.holder.pub, at, spendDay)
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
	// A key narrowed to some of its root's verbs reaches only those.
	both := r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "shop", Verbs: []key.Verb{key.Buy, key.Read}, Serial: "s"}), 10, key.LimitVerbs(key.Read))
	if err := r.k.Issue(at, nil, ck2(both, 10)); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a verb the narrowed key lacked: %v", err)
	}
	nk, err := key.ClerkKey(narrow, r.owner.priv, gen(7).pub, at, 1)
	must(t, err)
	if err := r.k.Issue(at, nil, nk); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a first key to a new holder: %v", err)
	}
	// Power that lapsed, was revoked or is paused is none: the same cap
	// again is new.
	for name, f := range map[string]func(r *rig) int64{
		"lapsed":  func(*rig) int64 { return key.ClerkLife + hour },
		"revoked": func(r *rig) int64 { must(t, r.k.Revoke(at, r.ck.Tip())); return at },
		"paused":  func(r *rig) int64 { must(t, r.k.Pause(at, r.ck.Tip())); return at },
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
		var steps []kernel.PlanStep
		for i, a := range strings.Split(amount, ",") {
			s := st(key.Buy, fmt.Sprintf("shop-%s-%d", id, i))
			s.Args[key.ArgAmount] = a
			steps = append(steps, s)
		}
		p := kernel.SignPlan(kernel.Plan{ID: id, Key: bare, Steps: steps}, r.owner.priv)
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
		{plan("p9", "4611686018427387903,4611686018427387905,1000"), kernel.CCosign}, // no wrap
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

// Each root's budget is its own, so a new root adds its cap to the holder's
// budget at the clerk, and grants still in their hold count toward what it
// would have: two new roots in one hold cannot each pass as small (D-146).
func TestNewRootsAddToTheBudgetTheLineMeasures(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone.pub)))
	r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"}), 100)
	at := 10 * hour
	root := func(serial string) []key.Key {
		root := key.Issue(phone.priv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: serial})
		k, err := key.ClerkKey(root, phone.priv, r.holder.pub, at, 100)
		must(t, err)
		return []key.Key{root, k}
	}
	two := root("m2")
	if err := r.k.Issue(at, approve(two, phone), two...); err != nil {
		t.Fatalf("a second root doubles the budget, up to the line: %v", err)
	}
	renewal, err := key.ClerkKey(key.Key{Root: two[0].Root}, phone.priv, r.holder.pub, at+1, 100)
	must(t, err)
	if err := r.k.Issue(at+1, approve([]key.Key{renewal}, phone), renewal); err != nil {
		t.Fatalf("a renewal replaces its root's cap: %v", err)
	}
	three := root("m3")
	if err := r.k.Issue(at+2, approve(three, phone), three...); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a third root in the same hold passes the line: %v", err)
	}
	if err := r.issue(at+2, three...); err != nil {
		t.Fatalf("with the hardware key: %v", err)
	}
}

// A holder's daily budget sums its roots' caps without wrapping: a phone's
// new root with a cap near MaxInt64 beside a 100/day one is big, whatever
// order the roots are summed in (Defect: KEY, #2950). Each round is a fresh
// map, so the rounds cover both orders.
func TestAHugeRootCapNeedsACosignInAnyOrder(t *testing.T) {
	for i := 0; i < 40; i++ {
		r := newRig(t)
		phone := gen(8)
		must(t, r.k.Enroll(0, key.Enroll(r.owner.priv, phone.pub)))
		r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"}), 100)
		at := 10 * hour
		root := key.Issue(phone.priv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m2"})
		k, err := key.ClerkKey(root, phone.priv, r.holder.pub, at, math.MaxInt64)
		must(t, err)
		if err := r.k.Issue(at, approve([]key.Key{root, k}, phone), root, k); !errors.Is(err, kernel.ErrNeedsCosign) {
			t.Fatalf("round %d: a phone raised a 100/day holder to MaxInt64/day: %v", i, err)
		}
	}
}
