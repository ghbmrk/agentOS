package graph

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The reach writer (KEY-9, CLK-10, CLK-14) sends the graph's control facts
// to the kernel as decl.reach entries, which price every grant over what its
// clerk's node reaches. The kernel folds an entry only when it adds, so the
// writer sends only what the log lacks.

// Declarer is the kernel's owner socket as the writer uses it; proc.Owner
// is one.
type Declarer interface {
	DeclReach() (kernel.DeclReach, error)
	DeclareReach(kernel.DeclReach) error
}

var assetOf = map[Class]key.Asset{Data: key.AssetData, Money: key.AssetMoney, Identity: key.AssetIdentity, Safety: key.AssetSafety}

// Decl is g as the kernel declares it: each node with its classes and the
// clerk rooted on it (clerks maps a clerk to its node's ID), and each reset,
// copy or act edge. A device's safety class is its mark as safety or access;
// nothing else makes a device safety. A clerk on a node g lacks is an error,
// since its keys would price on their direct reach alone.
func (g *Graph) Decl(clerks map[string]string) (kernel.DeclReach, error) {
	rooted := map[string]string{}
	for c, id := range clerks {
		if _, ok := g.index[id]; !ok || c == "" {
			return kernel.DeclReach{}, fmt.Errorf("graph: clerk %q is rooted on unknown node %q", c, id)
		}
		rooted[id] = c
	}
	var d kernel.DeclReach
	for _, n := range g.nodes {
		r := kernel.ReachNode{ID: n.ID, Clerk: rooted[n.ID]}
		for _, c := range n.Assets {
			r.Classes = append(r.Classes, assetOf[c])
		}
		d.Nodes = append(d.Nodes, r)
	}
	for _, e := range g.edges {
		if control(e.Kind) {
			d.Edges = append(d.Edges, kernel.ReachEdge{Kind: string(e.Kind), From: slices.Clone(e.From), To: e.To})
		}
	}
	return d, nil
}

// Additions is what want declares that have lacks: new nodes, new classes
// and clerk bindings on known nodes, and new edges. A binding have already
// gives a clerk or a node is kept: moving it could lower a price, which the
// kernel refuses whole, and would hold back every other addition with it.
func Additions(have, want kernel.DeclReach) kernel.DeclReach {
	nodes, bound, edges := map[string]kernel.ReachNode{}, map[string]bool{}, map[string]bool{}
	for _, n := range have.Nodes {
		old := nodes[n.ID]
		old.ID, old.Classes = n.ID, append(old.Classes, n.Classes...)
		if n.Clerk != "" {
			old.Clerk, bound[n.Clerk] = n.Clerk, true
		}
		nodes[n.ID] = old
	}
	for _, e := range have.Edges {
		edges[edgeKey(e)] = true
	}
	var add kernel.DeclReach
	for _, n := range want.Nodes {
		h, had := nodes[n.ID]
		r := kernel.ReachNode{ID: n.ID}
		for _, c := range n.Classes {
			if !slices.Contains(h.Classes, c) && !slices.Contains(r.Classes, c) {
				r.Classes = append(r.Classes, c)
			}
		}
		if n.Clerk != "" && h.Clerk == "" && !bound[n.Clerk] {
			r.Clerk = n.Clerk
		}
		if !had || r.Clerk != "" || len(r.Classes) > 0 {
			add.Nodes = append(add.Nodes, r)
		}
	}
	for _, e := range want.Edges {
		if k := edgeKey(e); !edges[k] {
			edges[k] = true
			add.Edges = append(add.Edges, e)
		}
	}
	return add
}

// edgeKey names an edge whatever the order of its From.
func edgeKey(e kernel.ReachEdge) string {
	from := slices.Sorted(slices.Values(e.From))
	return e.Kind + "\x00" + e.To + "\x00" + strings.Join(from, "\x00")
}

// WriteReach sends, as one entry, what g declares that the log lacks, and
// nothing when the log already holds it all.
func WriteReach(k Declarer, g *Graph, clerks map[string]string) error {
	want, err := g.Decl(clerks)
	if err != nil {
		return err
	}
	have, err := k.DeclReach()
	if err != nil {
		return err
	}
	if add := Additions(have, want); len(add.Nodes)+len(add.Edges) > 0 {
		return k.DeclareReach(add)
	}
	return nil
}
