package kernel_test

// REQ: KEY-9, CLK-10, CLK-14, LOG-5, KRN-2

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/owner/graph"
)

// genDecl draws a declaration over n nodes, node 0 rooting clerk "mail".
func genDecl(rng *rand.Rand) kernel.DeclReach {
	n := 2 + rng.IntN(7)
	var d kernel.DeclReach
	for i := range n {
		nd := kernel.ReachNode{ID: "n" + strconv.Itoa(i)}
		for a := key.AssetData; a <= key.AssetSafety; a++ {
			if rng.IntN(4) == 0 {
				nd.Classes = append(nd.Classes, a)
			}
		}
		d.Nodes = append(d.Nodes, nd)
	}
	d.Nodes[0].Clerk = "mail"
	for range rng.IntN(2 * n) {
		d.Edges = append(d.Edges, genEdge(rng, n))
	}
	return d
}

// genEdge is an AND edge of one to three distinct From.
func genEdge(rng *rand.Rand, n int) kernel.ReachEdge {
	kinds := []string{"reset", "copy", "act"}
	e := kernel.ReachEdge{Kind: kinds[rng.IntN(3)], To: "n" + strconv.Itoa(rng.IntN(n))}
	for _, i := range rng.Perm(n)[:1+rng.IntN(min(3, n))] {
		e.From = append(e.From, "n"+strconv.Itoa(i))
	}
	return e
}

// declared folds ds, one decl.reach entry each, into a fresh state.
func declared(t *testing.T, ds ...kernel.DeclReach) *kernel.State {
	t.Helper()
	s := kernel.NewState(nil)
	for _, d := range ds {
		must(t, s.Apply(declEntry(t, s.Seq+1, d)))
	}
	return s
}

func declEntry(t *testing.T, seq uint64, d any) kernel.Entry {
	t.Helper()
	b, err := json.Marshal(d)
	must(t, err)
	return kernel.Entry{Seq: seq, Type: kernel.TDeclReach, V: 1, Body: b}
}

// worth is a key over verbs for clerk "mail", priced over s's graph reach.
func worth(t *testing.T, s *kernel.State, capped bool, verbs ...key.Verb) key.Rank {
	t.Helper()
	k := key.Issue(gen(1).pass, key.Root{Clerk: "mail", Verbs: verbs, Serial: "w"})
	if capped {
		var err error
		k, err = key.ClerkKey(k, gen(1).pass, gen(2).pub, 0, 10)
		must(t, err)
	}
	w, err := key.Worth(k, kernel.GraphReach(s, "mail")...)
	must(t, err)
	return w
}

// KEY-9: the log's reach only grows, so no declaration lowers a price.
func TestAddingAnEdgeNeverLowersWorth(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 9))
	verbs := [][]key.Verb{{key.Read}, {key.Draft}, {key.Buy}, {key.Read, key.Organize}}
	for range 500 {
		d := genDecl(rng)
		before := declared(t, d)
		more := kernel.DeclReach{Edges: []kernel.ReachEdge{genEdge(rng, len(d.Nodes))}}
		if rng.IntN(2) == 0 {
			n := d.Nodes[rng.IntN(len(d.Nodes))]
			more = kernel.DeclReach{Nodes: []kernel.ReachNode{{ID: n.ID, Classes: []key.Asset{key.Asset(1 + rng.IntN(4))}}}}
		}
		after := declared(t, d, more)
		for _, vs := range verbs {
			for _, capped := range []bool{false, true} {
				if b, a := worth(t, before, capped, vs...), worth(t, after, capped, vs...); a < b {
					t.Fatalf("%v capped=%v: worth %d fell to %d adding %+v to %+v", vs, capped, b, a, more, d)
				}
			}
		}
	}
}

// KEY-9 (Security on #5813): no appended entry lowers any key's worth. Each
// entry draws nodes and edges over a pool of IDs wider than what is
// declared, so a later entry may first declare a node an edge already named,
// and the fold must refuse it.
func TestNoEntryLowersWorth(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 8))
	verbs := [][]key.Verb{{key.Read}, {key.Draft}, {key.Buy}}
	for range 300 {
		s := declared(t, kernel.DeclReach{Nodes: []kernel.ReachNode{{ID: "n0", Clerk: "mail"}}})
		for range 6 {
			var d kernel.DeclReach
			for range rng.IntN(3) {
				nd := kernel.ReachNode{ID: "n" + strconv.Itoa(rng.IntN(6))}
				for a := key.AssetData; a <= key.AssetSafety; a++ {
					if rng.IntN(5) == 0 {
						nd.Classes = append(nd.Classes, a)
					}
				}
				if !slices.ContainsFunc(d.Nodes, func(n kernel.ReachNode) bool { return n.ID == nd.ID }) {
					d.Nodes = append(d.Nodes, nd)
				}
			}
			for range rng.IntN(3) {
				d.Edges = append(d.Edges, genEdge(rng, 6))
			}
			var before []key.Rank
			for _, vs := range verbs {
				before = append(before, worth(t, s, true, vs...))
			}
			must(t, s.Apply(declEntry(t, s.Seq+1, d)))
			for i, vs := range verbs {
				if a := worth(t, s, true, vs...); a < before[i] {
					t.Fatalf("%v: worth %d fell to %d appending %+v", vs, before[i], a, d)
				}
			}
		}
	}
}

// Security on #5813: an undeclared node an edge reached keeps every class;
// a later first declaration of it, with fewer classes, is refused.
func TestALaterDeclarationCannotNarrowAnUnknownNode(t *testing.T) {
	mbox := kernel.ReachNode{ID: "mbox", Clerk: "mail", Classes: []key.Asset{key.AssetData}}
	first := kernel.DeclReach{Nodes: []kernel.ReachNode{mbox}, Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox"}, To: "bank"}}}
	if w := worth(t, declared(t, first), true, key.Read); w != key.MaxRank {
		t.Fatalf("before: worth %d", w)
	}
	for _, later := range []kernel.DeclReach{
		{Nodes: []kernel.ReachNode{{ID: "bank"}}},
		{Nodes: []kernel.ReachNode{{ID: "bank", Classes: []key.Asset{key.AssetData}}}},
	} {
		if w := worth(t, declared(t, first, later), true, key.Read); w != key.MaxRank {
			t.Fatalf("after %+v: worth %d, want %d", later, w, key.MaxRank)
		}
	}
	// An undeclared From, reached later by a new edge, is covered the same way.
	s := declared(t, kernel.DeclReach{Nodes: []kernel.ReachNode{mbox}, Edges: []kernel.ReachEdge{{Kind: "act", From: []string{"ghost"}, To: "mbox"}}},
		kernel.DeclReach{Edges: []kernel.ReachEdge{{Kind: "copy", From: []string{"mbox"}, To: "ghost"}}},
		kernel.DeclReach{Nodes: []kernel.ReachNode{{ID: "ghost"}}})
	if w := worth(t, s, true, key.Read); w != key.MaxRank {
		t.Fatalf("a ghost From declared late: worth %d", w)
	}
	// Declared in the same entry as the edge, a node prices as declared.
	same := declared(t, kernel.DeclReach{Nodes: []kernel.ReachNode{mbox, {ID: "bank"}}, Edges: first.Edges})
	if w := worth(t, same, true, key.Read); w != 1 {
		t.Fatalf("declared with its edge: worth %d, want 1", w)
	}
}

// KEY-9: an edge the graph cannot rule out counts, so an edge to a node no
// declaration gave classes reaches every class.
func TestAnUnknownEdgePricesAsReached(t *testing.T) {
	mbox := kernel.ReachNode{ID: "mbox", Clerk: "mail", Classes: []key.Asset{key.AssetData}}
	known := declared(t, kernel.DeclReach{Nodes: []kernel.ReachNode{mbox}})
	if w := worth(t, known, true, key.Read); w != 1 {
		t.Fatalf("a mailbox alone: worth %d, want 1", w)
	}
	s := declared(t, kernel.DeclReach{Nodes: []kernel.ReachNode{mbox},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox"}, To: "elsewhere"}}})
	if w := worth(t, s, true, key.Read); w != key.MaxRank {
		t.Fatalf("an edge to an undeclared node: worth %d, want %d", w, key.MaxRank)
	}
	// A verb that reaches nothing directly does not enter the closure.
	if w := worth(t, s, true, key.Draft); w != 0 {
		t.Fatalf("draft over the same graph: worth %d, want 0", w)
	}
	// A key whose clerk has no node keeps its direct reach.
	if got := kernel.GraphReach(s, "other"); got != nil {
		t.Fatalf("a clerk with no node: graph reach %v", got)
	}
}

// KEY-9 (Mark, #4999 comment 6705669120): a device reaches safety only when
// its declaration marks it so; declared without the mark it reaches none.
func TestADeviceIsSafetyOnlyWhenMarked(t *testing.T) {
	d := kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "hub", Clerk: "mail"}, {ID: "lamp"}},
		Edges: []kernel.ReachEdge{{Kind: "act", From: []string{"hub"}, To: "lamp"}},
	}
	s := declared(t, d)
	if got := kernel.GraphReach(s, "mail"); len(got) != 0 {
		t.Fatalf("an unmarked device reaches %v", got)
	}
	if w := worth(t, s, true, key.Present); w != 1 {
		t.Fatalf("present on an unmarked lamp: worth %d, want 1", w)
	}
	marked := declared(t, d, kernel.DeclReach{Nodes: []kernel.ReachNode{{ID: "lamp", Classes: []key.Asset{key.AssetSafety}}}})
	if w := worth(t, marked, true, key.Present); w != key.MaxRank {
		t.Fatalf("present on a lock marked safety: worth %d, want %d", w, key.MaxRank)
	}
}

// KRN-2, CLK-10: the kernel's reached set is graph.Reach's for the same
// data; the kernel itself does not import the graph.
func TestReachMatchesTheGraph(t *testing.T) {
	rng := rand.New(rand.NewPCG(4, 2))
	for range 500 {
		d := genDecl(rng)
		var nodes []graph.Node
		for _, n := range d.Nodes {
			nodes = append(nodes, graph.Node{ID: n.ID, Kind: graph.Account, Source: graph.Answer})
		}
		var edges []graph.Edge
		for _, e := range d.Edges {
			edges = append(edges, graph.Edge{Kind: graph.EdgeKind(e.Kind), From: e.From, To: e.To, Source: graph.Answer})
		}
		g, err := graph.New(nodes, edges)
		must(t, err)
		s := declared(t, d)
		for _, n := range d.Nodes {
			want, _ := g.Reach(n.ID)
			slices.Sort(want)
			if got := kernel.Reached(s, n.ID); !slices.Equal(got, want) {
				t.Fatalf("from %s: kernel %v, graph %v over %+v", n.ID, got, want, d)
			}
		}
	}
}

// KEY-9: the verbs that take a node over already reach identity, the top
// rank, so a held step's term cannot rise with the graph and Window keeps
// its own verb's direct reach. A table change that lowers them fails here
// and owes the hold its graph term.
func TestAControlVerbsHoldIsAlreadyTop(t *testing.T) {
	for _, v := range []key.Verb{key.ChangeAccount, key.RevealOrCreateSecret, key.DeleteRemote} {
		if w := key.WorthOf(key.AssetsOf(v), true); w != key.MaxRank {
			t.Fatalf("%s: direct worth %d, want %d", v, w, key.MaxRank)
		}
	}
}

// LOG-5: a malformed or removing decl.reach entry changes nothing, and a
// replay of the log gives the same reach.
func TestADeclarationThatLowersOrBreaksIsRefused(t *testing.T) {
	base := kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "mail", Classes: []key.Asset{key.AssetData}}, {ID: "bank", Classes: []key.Asset{key.AssetIdentity}}},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox"}, To: "bank"}},
	}
	bad := map[string]kernel.DeclReach{
		"unknown class": {Nodes: []kernel.ReachNode{{ID: "x", Classes: []key.Asset{key.AssetSafety + 1}}}},
		"empty node ID": {Nodes: []kernel.ReachNode{{ID: ""}}},
		"repeated node": {Nodes: []kernel.ReachNode{{ID: "x"}, {ID: "x", Clerk: "cal"}}},
		"unknown edge":  {Edges: []kernel.ReachEdge{{Kind: "cutoff", From: []string{"mbox"}, To: "bank"}}},
		"no From":       {Edges: []kernel.ReachEdge{{Kind: "act", To: "bank"}}},
		"empty To":      {Edges: []kernel.ReachEdge{{Kind: "act", From: []string{"mbox"}}}},
		"empty From":    {Edges: []kernel.ReachEdge{{Kind: "act", From: []string{""}, To: "bank"}}},
		// Moving the clerk to an empty node would drop the bank from its reach.
		"clerk moved":  {Nodes: []kernel.ReachNode{{ID: "empty", Clerk: "mail"}}},
		"node rebound": {Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "cal"}}},
	}
	for name, d := range bad {
		s := declared(t, base)
		before := kernel.Reached(s, "mbox")
		// A good node ahead of the bad part is refused with it: all or nothing.
		d.Nodes = append([]kernel.ReachNode{{ID: "extra", Classes: []key.Asset{key.AssetMoney}}}, d.Nodes...)
		must(t, s.Apply(declEntry(t, s.Seq+1, d)))
		if got := kernel.Reached(s, "mbox"); !slices.Equal(got, before) || kernel.Reached(s, "extra") != nil {
			t.Fatalf("%s: reach %v after, %v before", name, got, before)
		}
		if w := worth(t, s, true, key.Read); w != key.MaxRank {
			t.Fatalf("%s: worth %d", name, w)
		}
	}
	// Redeclaring a node with fewer classes keeps its classes.
	s := declared(t, base, kernel.DeclReach{Nodes: []kernel.ReachNode{{ID: "bank", Clerk: "bank"}}})
	if w := worth(t, s, true, key.Read); w != key.MaxRank {
		t.Fatalf("a redeclared bank lowered the mail key to %d", w)
	}
	// A node declared with no clerk may gain one later: that only adds.
	if got := kernel.GraphReach(s, "bank"); !slices.Equal(got, []key.Asset{key.AssetIdentity}) {
		t.Fatalf("the bank's clerk, bound on redeclaring, reaches %v", got)
	}
	if err := s.Apply(kernel.Entry{Seq: s.Seq + 1, Type: kernel.TDeclReach, V: 1, Body: []byte(`{"nodes":7}`)}); err == nil {
		t.Fatal("an undecodable body folds")
	}
}

// LOG-1: a declaration logged by the kernel rederives, and a replay from
// empty prices the same.
func TestADeclarationReplays(t *testing.T) {
	r := newRig(t)
	d := kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "mail"}, {ID: "bank", Classes: []key.Asset{key.AssetIdentity}}},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox"}, To: "bank"}},
	}
	must(t, kernel.Emit(r.k, 1, kernel.TDeclReach, d))
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries()); err != nil {
		t.Fatalf("rederive: %v", err)
	}
	s, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if got, want := kernel.Reached(s, "mbox"), kernel.Reached(r.k.State(), "mbox"); !slices.Equal(got, want) || len(got) != 2 {
		t.Fatalf("replayed reach %v, live %v", got, want)
	}
	if kernel.Widening(kernel.TDeclReach) {
		t.Fatal("a declaration only raises prices; it is not a widening")
	}
}

// A grant is priced over its graph reach (KEY-9, D-307): a new `read` mail
// key is rank 1 and asks only the tap, until a declaration says the mailbox
// resets an account; then the same key is rank 3 and asks the hardware key.
func TestAGrantPricesItsGraphReach(t *testing.T) {
	r := newRig(t)
	read := func(serial string) key.Key {
		return key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Read}, Serial: serial})
	}
	draft := func(serial string) key.Key {
		return key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Draft}, Serial: serial})
	}
	must(t, r.issue(0, read("r0"), draft("d0"))) // new verbs: big, co-signed
	live := kernel.GrantHold
	if err := r.k.Issue(live, nil, read("r1")); err != nil {
		t.Fatalf("a rank-1 read key with one tap: %v", err)
	}
	must(t, kernel.Emit(r.k, live, kernel.TDeclReach, kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "mail", Classes: []key.Asset{key.AssetData}},
			{ID: "bank", Classes: []key.Asset{key.AssetMoney, key.AssetIdentity}}},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox"}, To: "bank"}},
	}))
	if err := r.k.Issue(live, nil, read("r2")); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a read key over a reset edge with one tap: %v", err)
	}
	if err := r.issue(live, read("r2")); err != nil {
		t.Fatalf("a read key over a reset edge with the hardware key: %v", err)
	}
	if err := r.k.Issue(live, nil, draft("d1")); err != nil {
		t.Fatalf("a draft key reaches nothing, so the edge does not price it: %v", err)
	}
}
