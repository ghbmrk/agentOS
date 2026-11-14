package kernel_test

// REQ: KEY-9, CLK-10, CLK-14, LOG-5, KRN-2

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/owner/graph"
)

// declare folds d onto s as a decl.reach entry.
func declare(t *testing.T, s *kernel.State, d kernel.DeclReach) {
	t.Helper()
	b, err := json.Marshal(d)
	must(t, err)
	must(t, kernel.Fold(s, kernel.TDeclReach, b))
}

func node(id string, as ...key.Asset) kernel.DeclNode {
	return kernel.DeclNode{ID: id, Clerk: id, Assets: as}
}

func edge(to string, from ...string) kernel.DeclEdge {
	return kernel.DeclEdge{Kind: "reset", From: from, To: to}
}

// genGraph is a random declaration: n nodes, each its own clerk, some
// devices, marked or not, with random classes (none: unknown), and m edges
// with one to three distinct From.
func genGraph(rng *rand.Rand, n, m int) kernel.DeclReach {
	var d kernel.DeclReach
	for i := range n {
		nd := kernel.DeclNode{ID: fmt.Sprint("n", i), Clerk: fmt.Sprint("n", i)}
		for a := key.AssetNone; a <= key.AssetSafety; a++ {
			if rng.Intn(4) == 0 {
				nd.Assets = append(nd.Assets, a)
			}
		}
		nd.Device = rng.Intn(4) == 0
		nd.Marked = nd.Device && rng.Intn(2) == 0
		d.Nodes = append(d.Nodes, nd)
	}
	for range m {
		e := kernel.DeclEdge{Kind: []string{"reset", "copy", "act"}[rng.Intn(3)], To: fmt.Sprint("n", rng.Intn(n))}
		for _, f := range rng.Perm(n)[:1+rng.Intn(min(3, n))] {
			e.From = append(e.From, fmt.Sprint("n", f))
		}
		d.Edges = append(d.Edges, e)
	}
	return d
}

// Adding an edge or a class never lowers any key's worth: every fact is a
// union, so growth only raises (KEY-9). Catches a closure that drops a node
// on growth.
func TestAddingAnEdgeNeverLowersWorth(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	for range 200 {
		n := 2 + rng.Intn(8)
		full := genGraph(rng, n, rng.Intn(12))
		s := kernel.NewState(nil)
		worth := map[string]key.Rank{}
		reached := map[string]map[string]bool{}
		// Fold the nodes and edges one item at a time, in a random order.
		var items []kernel.DeclReach
		for _, nd := range full.Nodes {
			items = append(items, kernel.DeclReach{Nodes: []kernel.DeclNode{nd}})
		}
		for _, e := range full.Edges {
			items = append(items, kernel.DeclReach{Edges: []kernel.DeclEdge{e}})
		}
		rng.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
		for _, it := range items {
			declare(t, s, it)
			for _, nd := range full.Nodes {
				for _, capped := range []bool{false, true} {
					w := key.WorthOf(s.GraphReach(nd.Clerk), capped)
					k := fmt.Sprint(nd.Clerk, capped)
					if w < worth[k] {
						t.Fatalf("%s fell from %d to %d after %+v", k, worth[k], w, it)
					}
					worth[k] = w
				}
				got := kernel.Reached(s, nd.Clerk)
				for was := range reached[nd.Clerk] {
					if !got[was] {
						t.Fatalf("%s lost %s after %+v", nd.Clerk, was, it)
					}
				}
				reached[nd.Clerk] = got
			}
		}
	}
}

// An edge into a node no declaration gave classes reaches every class, so
// the key is worth the most (fail closed).
func TestAnUnknownEdgePricesAsReached(t *testing.T) {
	s := kernel.NewState(nil)
	declare(t, s, kernel.DeclReach{Nodes: []kernel.DeclNode{node("mail", key.AssetData)}})
	if w := key.WorthOf(s.GraphReach("mail"), false); w != 1 {
		t.Fatalf("mail alone is worth %d, want 1", w)
	}
	declare(t, s, kernel.DeclReach{Edges: []kernel.DeclEdge{edge("unknown", "mail")}})
	if w := key.WorthOf(s.GraphReach("mail"), true); w != key.MaxRank {
		t.Fatalf("an edge to an unknown node is worth %d, want %d", w, key.MaxRank)
	}
	// Declaring its classes later adds to them; it never lowers the price.
	declare(t, s, kernel.DeclReach{Nodes: []kernel.DeclNode{{ID: "unknown", Assets: []key.Asset{key.AssetNone}}}})
	if w := key.WorthOf(s.GraphReach("mail"), true); w != key.MaxRank {
		t.Fatalf("a later declaration lowered the unknown node to %d", w)
	}
	// A node declared with no classes is unknown too; AssetNone is known.
	declare(t, s, kernel.DeclReach{Nodes: []kernel.DeclNode{node("blank"), node("plain", key.AssetNone)}})
	if w := key.WorthOf(s.GraphReach("blank"), true); w != key.MaxRank {
		t.Fatalf("a node of no stated classes is worth %d", w)
	}
	if w := key.WorthOf(s.GraphReach("plain"), true); w != 0 {
		t.Fatalf("a node of class none is worth %d", w)
	}
	if s.GraphReach("nobody") != nil {
		t.Fatal("a clerk with no node has a graph reach")
	}
}

// On generated graphs the kernel reaches the node set graph.Reach does for
// the same data: the rule is matched as data, not imported (KRN-2).
func TestReachMatchesTheGraph(t *testing.T) {
	rng := rand.New(rand.NewSource(10))
	for range 300 {
		n := 1 + rng.Intn(9)
		d := genGraph(rng, n, rng.Intn(15))
		s := kernel.NewState(nil)
		declare(t, s, d)
		var nodes []graph.Node
		for _, nd := range d.Nodes {
			nodes = append(nodes, graph.Node{ID: nd.ID, Kind: graph.Account, Source: graph.Shipped})
		}
		var edges []graph.Edge
		for _, e := range d.Edges {
			edges = append(edges, graph.Edge{Kind: graph.EdgeKind(e.Kind), From: e.From, To: e.To, Source: graph.Shipped})
		}
		g, err := graph.New(nodes, edges)
		must(t, err)
		for _, nd := range d.Nodes {
			want, _ := g.Reach(nd.ID)
			got := slices.Sorted(maps.Keys(kernel.Reached(s, nd.Clerk)))
			if !slices.Equal(got, want) {
				t.Fatalf("from %s: kernel %v, graph %v (%+v)", nd.ID, got, want, d)
			}
		}
	}
}

// A device reaches safety only when its declaration marks it safety or
// access; unmarked, it reaches none (Mark, #4999 comment 6705669120).
func TestADeviceIsSafetyOnlyWhenMarked(t *testing.T) {
	s := kernel.NewState(nil)
	declare(t, s, kernel.DeclReach{
		Nodes: []kernel.DeclNode{
			node("hub", key.AssetNone),
			{ID: "lamp", Device: true, Assets: []key.Asset{key.AssetSafety}},
			{ID: "lock", Device: true, Marked: true},
			node("hub2", key.AssetNone),
		},
		Edges: []kernel.DeclEdge{{Kind: "act", From: []string{"hub"}, To: "lamp"}, {Kind: "act", From: []string{"hub2"}, To: "lock"}},
	})
	if got := s.GraphReach("hub"); !slices.Equal(got, []key.Asset{key.AssetNone}) {
		t.Fatalf("an unmarked device reaches %v", got)
	}
	if got := s.GraphReach("hub2"); !slices.Contains(got, key.AssetSafety) {
		t.Fatalf("a marked device reaches %v, not safety", got)
	}
	// Marking the lamp later raises it.
	declare(t, s, kernel.DeclReach{Nodes: []kernel.DeclNode{{ID: "lamp", Device: true, Marked: true}}})
	if got := s.GraphReach("hub"); !slices.Contains(got, key.AssetSafety) {
		t.Fatalf("a device marked later reaches %v", got)
	}
}

// A malformed decl.reach, or one that tries to remove, is refused live and
// changes nothing on replay; Replay of the log gives the same reach (LOG-5).
func TestADeclarationIsRefusedOrReplayed(t *testing.T) {
	r := newRig(t)
	good := kernel.DeclReach{Nodes: []kernel.DeclNode{node("mail", key.AssetData), node("bank", key.AssetMoney)},
		Edges: []kernel.DeclEdge{edge("bank", "mail")}}
	must(t, r.k.DeclareReach(1, good))
	for _, bad := range []kernel.DeclReach{
		{},
		{Nodes: []kernel.DeclNode{{ID: ""}}},
		{Nodes: []kernel.DeclNode{{ID: "x", Assets: []key.Asset{key.AssetSafety + 1}}}},
		{Edges: []kernel.DeclEdge{{Kind: "cutoff", From: []string{"a"}, To: "b"}}},
		{Edges: []kernel.DeclEdge{{Kind: "reset", To: "b"}}},
		{Edges: []kernel.DeclEdge{{Kind: "reset", From: []string{"a", "a"}, To: "b"}}},
		{Edges: []kernel.DeclEdge{{Kind: "reset", From: []string{""}, To: "b"}}},
	} {
		if err := r.k.DeclareReach(2, bad); !errors.Is(err, kernel.ErrDecl) {
			t.Fatalf("%+v: %v, want ErrDecl", bad, err)
		}
	}
	// Written past the kernel, a removal or a bad class folds to nothing.
	for _, raw := range []string{
		`{"nodes":[{"id":"mail","assets":[3]}],"remove":[{"kind":"reset","from":["mail"],"to":"bank"}]}`,
		`{"nodes":[{"id":"mail","assets":[9]}]}`,
	} {
		must(t, kernel.Emit(r.k, 3, kernel.TDeclReach, json.RawMessage(raw)))
	}
	want := []key.Asset{key.AssetData, key.AssetMoney}
	if got := r.k.State().GraphReach("mail"); !slices.Equal(got, want) {
		t.Fatalf("live reach %v, want %v", got, want)
	}
	s, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if got := s.GraphReach("mail"); !slices.Equal(got, want) {
		t.Fatalf("replayed reach %v, want %v", got, want)
	}
	rederives(t, r)
}
