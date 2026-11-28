package kernel_test

// REQ: KEY-9, KEY-3, KEY-6, KRN-6

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// bankReset declares mail's mailbox as resetting a bank account: every verb
// of mail's keys reaching data now reaches identity and money too.
func bankReset() kernel.DeclReach {
	return kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "mail", Classes: []key.Asset{key.AssetData}},
			{ID: "bank", Classes: []key.Asset{key.AssetMoney, key.AssetIdentity}}},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox"}, To: "bank"}},
	}
}

// narrowed is the key.narrowed entries in r's log.
func narrowed(t *testing.T, r *rig) []kernel.KeyNarrowed {
	t.Helper()
	var out []kernel.KeyNarrowed
	for _, e := range r.k.Log().Entries() {
		if e.Type == kernel.TKeyNarrowed {
			var n kernel.KeyNarrowed
			must(t, json.Unmarshal(e.Body, &n))
			out = append(out, n)
		}
	}
	return out
}

// After an entry that grows a key's reach, a step under it is refused until
// the narrowing is logged, then judged under the narrowed key: a step that
// would run at the new worth never runs (KEY-9, KEY-3).
func TestAGrownKeyIsNarrowedBeforeItsNextStep(t *testing.T) {
	r := newRig(t)
	if rf := r.admits("before", r.ck, 0); rf != nil {
		t.Fatalf("before the growth: %v", rf)
	}
	r.plan("queued", r.ck, st(key.Trash, "m1"))
	// The declaration alone, as a log written before a crash holds it.
	must(t, kernel.Emit(r.k, 0, kernel.TDeclReach, bankReset()))
	for _, v := range []key.Verb{key.Organize, key.Trash} {
		p := r.sign(kernel.Plan{ID: "grown-" + string(v), Key: r.ck, Steps: []kernel.PlanStep{st(v, "m2")}})
		if _, _, rf := kernel.Admit(r.k.State(), p, 0); rf == nil || rf.Code != kernel.CGrown {
			t.Fatalf("%s before the narrowing: %v, want %s", v, rf, kernel.CGrown)
		}
	}
	if a := kernel.Next(r.k.State(), "queued", 0); a.Kind != kernel.ActCancel || a.Refusal.Code != kernel.CGrown {
		t.Fatalf("a queued step before the narrowing: %+v", a)
	}
	must(t, r.tick(0)) // logs the narrowing first, then runs the plans
	if got := narrowed(t, r); len(got) == 0 {
		t.Fatal("no narrowing logged")
	}
	if r.status("queued") != kernel.SCancelled || r.k.State().Plans["queued"].Cancel != kernel.CGrown {
		t.Fatalf("the queued trash ran at the new worth: %s", r.status("queued"))
	}
	if fx := r.mail.Effects(); len(fx) != 0 {
		t.Fatalf("the clerk acted at the new worth: %+v", fx)
	}
	org := r.sign(kernel.Plan{ID: "org", Key: r.ck, Steps: []kernel.PlanStep{st(key.Organize, "m3")}})
	if _, _, rf := kernel.Admit(r.k.State(), org, 0); rf != nil {
		t.Fatalf("organize reaches nothing, so the narrowing keeps it: %v", rf)
	}
	for _, v := range []key.Verb{key.Trash, key.Unsubscribe} {
		p := r.sign(kernel.Plan{ID: "after-" + string(v), Key: r.ck, Steps: []kernel.PlanStep{st(key.Organize, "m4"), st(v, "m4")}})
		_, _, rf := kernel.Admit(r.k.State(), p, 0)
		if rf == nil || rf.Code != kernel.CGrown || rf.Step == nil || *rf.Step != 1 {
			t.Fatalf("%s after the narrowing: %v, want %s at step 1", v, rf, kernel.CGrown)
		}
	}
	if n := len(kernel.Narrowings(r.k.State())); n != 0 {
		t.Fatalf("%d narrowings still owed after the tick", n)
	}
	r.replays()
}

// The declaration's own entry point narrows at once, before it returns.
func TestDeclaringNarrowsAtOnce(t *testing.T) {
	r := newRig(t)
	must(t, r.k.DeclareReach(0, bankReset()))
	es := r.k.Log().Entries()
	if es[len(es)-1].Type != kernel.TKeyNarrowed || len(kernel.Narrowings(r.k.State())) != 0 {
		t.Fatalf("the declaration's step ended at %s, narrowings owed %d", es[len(es)-1].Type, len(kernel.Narrowings(r.k.State())))
	}
	// A second growth of a key already narrowed: nothing it keeps grew, so
	// nothing more is logged.
	n := r.k.Log().Len()
	must(t, r.k.DeclareReach(0, kernel.DeclReach{Nodes: []kernel.ReachNode{{ID: "car", Classes: []key.Asset{key.AssetSafety}}},
		Edges: []kernel.ReachEdge{{Kind: "act", From: []string{"bank"}, To: "car"}}}))
	if got := r.k.Log().Len() - n; got != 1 {
		t.Fatalf("a growth past what the narrowing kept logged %d entries, want 1", got)
	}
	r.replays()
}

// The offer names the key, its old and new worth, and the proof the wider
// key asks: Price(ActGrant, new), the hardware key (P4) at rank 3 (KEY-6).
func TestTheOfferNamesTheNewProof(t *testing.T) {
	r := newRig(t)
	must(t, r.k.DeclareReach(0, bankReset()))
	got := narrowed(t, r)
	byKey := map[key.ID]kernel.KeyNarrowed{}
	for _, n := range got {
		byKey[n.Key] = n
	}
	for _, id := range []key.ID{rootOf(r.ck), r.ck.Tip()} {
		n, ok := byKey[id]
		if !ok {
			t.Fatalf("no offer for %v", id)
		}
		if n.Old != 1 || n.New != 3 || n.Proof != key.Price(key.ActGrant, 3) || n.Proof != key.P4 {
			t.Fatalf("offer %+v, want old 1, new 3, proof %v", n, key.P4)
		}
		if !slices.Equal(n.Verbs, []string{string(key.Organize)}) {
			t.Fatalf("kept %v, want only organize", n.Verbs)
		}
	}
	if len(got) != 2 {
		t.Fatalf("%d offers, want the root's and the clerk key's", len(got))
	}
	r.replays()
}

func rootOf(k key.Key) key.ID { return key.Key{Root: k.Root}.Tip() }

// A property over generated graphs and keys: the kernel's narrowing of a key
// is never worth more than the key before it, and at most its recorded old
// worth; after it, no key granted is worth more than its old worth.
func TestNarrowingNeverRaisesWorth(t *testing.T) {
	verbs := []key.Verb{key.Read, key.Draft, key.Organize, key.Trash, key.Send, key.Buy, key.Share, key.DeleteRemote}
	rng := rand.New(rand.NewPCG(9, 7))
	grew := 0
	for i := range 60 {
		r := newRig(t)
		var vs []key.Verb
		for _, v := range verbs {
			if rng.IntN(2) == 0 {
				vs = append(vs, v)
			}
		}
		if len(vs) == 0 {
			vs = verbs[:1]
		}
		root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: vs, Serial: "g"})
		ck, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, int64(1+rng.IntN(1<<20)))
		must(t, err)
		must(t, r.issue(0, root, ck))
		keys := []key.Key{root, ck, {Root: r.ck.Root}, r.ck}
		before := map[key.ID]key.Rank{}
		for _, k := range keys {
			w, err := key.Worth(k, kernel.GraphReach(r.k.State(), "mail")...)
			must(t, err)
			if at, ok := kernel.WorthAt(r.k.State(), k.Tip()); !ok || at != w {
				t.Fatalf("%d: worth at grant %v (%v), key.Worth %v", i, at, ok, w)
			}
			before[k.Tip()] = w
		}
		must(t, kernel.Emit(r.k, 0, kernel.TDeclReach, genDecl(rng)))
		owed := kernel.Narrowings(r.k.State())
		grew += len(owed)
		must(t, r.tick(0))
		for _, n := range owed {
			k := keys[slices.IndexFunc(keys, func(k key.Key) bool { return k.Tip() == n.Key })]
			var kept []key.Verb
			for _, v := range n.Verbs {
				kept = append(kept, key.Verb(v))
			}
			w := worthOf(t, r, k, kept)
			if w > before[n.Key] || w > n.Old || n.Old != before[n.Key] || n.New <= n.Old {
				t.Fatalf("%d: narrowing %+v worth %v, before %v", i, n, w, before[n.Key])
			}
		}
		for _, k := range keys {
			w, err := key.Worth(k, kernel.GraphReach(r.k.State(), "mail")...)
			must(t, err)
			grew := w > before[k.Tip()]
			has := slices.ContainsFunc(owed, func(n kernel.KeyNarrowed) bool { return n.Key == k.Tip() })
			if grew != has {
				t.Fatalf("%d: key grew %v, narrowed %v", i, grew, has)
			}
		}
		if len(kernel.Narrowings(r.k.State())) != 0 {
			t.Fatalf("%d: narrowings owed after the tick", i)
		}
		r.replays()
	}
	if grew < 20 {
		t.Fatalf("only %d keys grew over the draws", grew)
	}
}

// worthOf is k narrowed to verbs, as the key package prices it: the kernel's
// narrowing derived as a holder's link with a verbs caveat.
func worthOf(t *testing.T, r *rig, k key.Key, verbs []key.Verb) key.Rank {
	t.Helper()
	g := kernel.GraphReach(r.k.State(), "mail")
	if len(verbs) == 0 {
		return 0 // admits nothing
	}
	if len(k.Links) == 0 { // a root is uncapped: its verbs priced as a root of them alone
		w, err := key.Worth(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: canon(verbs), Serial: "n"}), g...)
		must(t, err)
		return w
	}
	n, err := key.Derive(k, r.holder.priv, r.holder.pub, key.LimitVerbs(verbs...))
	must(t, err)
	w, err := key.Worth(n, g...)
	must(t, err)
	return w
}

func canon(vs []key.Verb) []key.Verb {
	out := slices.Clone(vs)
	slices.Sort(out)
	return out
}

// A narrowing the kernel did not derive folds to nothing and is a
// divergence on rederive: one keeping a verb that grew, one narrower than
// the kernel's, and one whose offer names another proof.
func TestAForgedNarrowingIsDropped(t *testing.T) {
	for name, forge := range map[string]func(*kernel.KeyNarrowed){
		"keeps trash": func(n *kernel.KeyNarrowed) { n.Verbs = append(n.Verbs, string(key.Trash)) },
		"narrower":    func(n *kernel.KeyNarrowed) { n.Verbs = []string{} },
		"cheap offer": func(n *kernel.KeyNarrowed) { n.Proof = key.P0 },
	} {
		r := newRig(t)
		must(t, kernel.Emit(r.k, 0, kernel.TDeclReach, bankReset()))
		owed := kernel.Narrowings(r.k.State())
		forged := owed[0]
		forged.Verbs = slices.Clone(forged.Verbs)
		forge(&forged)
		must(t, kernel.Emit(r.k, 0, kernel.TKeyNarrowed, forged))
		if _, ok := kernel.Kept(r.k.State(), forged.Key); ok || len(kernel.Narrowings(r.k.State())) != len(owed) {
			t.Fatalf("%s: a forged narrowing folded", name)
		}
		if _, err := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries()); err == nil {
			t.Fatalf("%s: rederive passed a narrowing the kernel did not derive", name)
		}
	}
	if kernel.Widening(kernel.TKeyNarrowed) {
		t.Fatal("a narrowing grants nothing back")
	}
}

// A dispatch decided before the growth is not sent after it: the send
// check refuses it, unsent, and cancels its plan (KEY-9).
func TestASendAfterTheGrowthIsRefused(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	c := r.calls(1, 1)[0]
	must(t, r.k.DeclareReach(1, bankReset()))
	if ok, err := r.k.Send(1, c); ok || err != nil {
		t.Fatalf("sent a trash outside the narrowing: %v %v", ok, err)
	}
	if got := r.k.State().Plans["p1"].Cancel; got != kernel.CGrown {
		t.Fatalf("cancel %q, want %s", got, kernel.CGrown)
	}
	r.replays()
}

// A root at the top rank never grows; its clerk key, limited to cheaper
// verbs, does, and only the first link's narrowing refuses trash.
func TestAGrownFirstLinkIsNarrowedAlone(t *testing.T) {
	r := newRig(t)
	ck := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail",
		Verbs: []key.Verb{key.Buy, key.Organize, key.Trash}, Serial: "top"}), 1<<40, key.LimitVerbs(key.Organize, key.Trash))
	if rf := r.admits("before", ck, 0); rf != nil {
		t.Fatalf("before: %v", rf)
	}
	must(t, r.k.DeclareReach(0, bankReset()))
	got := narrowed(t, r)
	if !slices.ContainsFunc(got, func(n kernel.KeyNarrowed) bool { return n.Key == ck.Tip() }) ||
		slices.ContainsFunc(got, func(n kernel.KeyNarrowed) bool { return n.Key == rootOf(ck) }) {
		t.Fatalf("narrowings %+v, want the clerk key's and not its root's", got)
	}
	if rf := r.admits("after", ck, 0); rf == nil || rf.Code != kernel.CGrown {
		t.Fatalf("trash under a grown first link: %v", rf)
	}
	r.replays()
}

// Calls logs the narrowing owed before it decides a step, so after a crash
// between a declaration and its narrowing a step the narrowing keeps still
// runs, and a revoked grant is offered nothing.
func TestCallsNarrowsFirstAndSkipsRevoked(t *testing.T) {
	r := newRig(t)
	r.plan("org", r.ck, st(key.Organize, "m1"))
	must(t, r.k.Revoke(0, rootOf(r.ck)))
	must(t, kernel.Emit(r.k, 0, kernel.TDeclReach, bankReset())) // the declaration alone
	_, err := r.k.Calls(1)
	must(t, err)
	got := narrowed(t, r)
	if len(got) != 1 || got[0].Key != r.ck.Tip() {
		t.Fatalf("narrowings %+v, want the clerk key's only (its root is revoked)", got)
	}
	r2 := newRig(t)
	r2.plan("org", r2.ck, st(key.Organize, "m1"))
	must(t, kernel.Emit(r2.k, 0, kernel.TDeclReach, bankReset()))
	if cs := r2.calls(1, 1); cs[0].Kind != kernel.ActDispatch || r2.status("org") != kernel.SActive {
		t.Fatalf("a kept organize after the crash window: %+v, %s", cs, r2.status("org"))
	}
	r.replays()
	r2.replays()
}
