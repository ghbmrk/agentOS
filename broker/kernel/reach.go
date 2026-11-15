package kernel

import (
	"maps"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// TDeclReach (v1) is the declarations' control facts (KEY-9, CLK-10, CLK-14):
// nodes, their classes and the clerk rooted on each (a device marked safety
// or access declares AssetSafety), and edges. It only adds, so an unsigned
// writer can only raise a price. graph.Reach's rule, matched in reach_test.go.
const TDeclReach = "decl.reach"

type (
	ReachNode struct {
		ID      string      `json:"id"`
		Clerk   string      `json:"clerk,omitempty"`
		Classes []key.Asset `json:"classes,omitempty"`
	}
	ReachEdge struct {
		Kind string   `json:"kind"`
		From []string `json:"from"` // any one fires it
		To   string   `json:"to"`
	}
	DeclReach struct {
		Nodes []ReachNode `json:"nodes,omitempty"`
		Edges []ReachEdge `json:"edges,omitempty"`
	}
	declState struct {
		nodes  map[string]ReachNode
		clerks map[string]string // clerk -> its node
		edges  []ReachEdge
	}
)

// applyDecl folds a decl.reach entry. It refuses the whole entry, changing
// nothing, on an empty ID, a class past the table, a repeated node, an edge
// not reset, copy or act or without From, a clerk or node rebound, or a first
// declaration of a node an edge named (priced as every class): each lowers.
func (s *State) applyDecl(e Entry) error {
	b, err := body[DeclReach](e)
	if err != nil {
		return err
	}
	d, bind, seen := &s.decl, maps.Collect(maps.All(s.decl.clerks)), map[string]bool{}
	for _, n := range b.Nodes {
		c, bound := bind[n.Clerk]
		old, had := d.nodes[n.ID]
		if seen[n.ID] || n.ID == "" || slices.ContainsFunc(n.Classes, func(a key.Asset) bool { return a > key.AssetSafety }) ||
			!had && slices.ContainsFunc(d.edges, func(e ReachEdge) bool { return e.To == n.ID || slices.Contains(e.From, n.ID) }) ||
			n.Clerk != "" && (had && old.Clerk != "" && old.Clerk != n.Clerk || bound && c != n.ID) {
			return nil
		}
		seen[n.ID], bind[n.Clerk] = true, n.ID
	}
	for _, e := range b.Edges {
		if !slices.Contains([]string{"reset", "copy", "act"}, e.Kind) || len(e.From) == 0 || e.To == "" || slices.Contains(e.From, "") {
			return nil
		}
	}
	if d.nodes == nil {
		d.nodes, d.clerks = map[string]ReachNode{}, map[string]string{}
	}
	for _, n := range b.Nodes {
		old := d.nodes[n.ID]
		old.ID, old.Classes = n.ID, append(old.Classes, n.Classes...)
		if n.Clerk != "" {
			old.Clerk, d.clerks[n.Clerk] = n.Clerk, n.ID
		}
		d.nodes[n.ID] = old
	}
	d.edges = append(d.edges, b.Edges...)
	return nil
}

// reached is node and all it reaches; nil for a node no entry declared.
func (s *State) reached(node string) map[string]bool {
	if _, ok := s.decl.nodes[node]; !ok {
		return nil
	}
	in := map[string]bool{node: true}
	for grew := true; grew; {
		grew = false
		for _, e := range s.decl.edges {
			if !in[e.To] && slices.ContainsFunc(e.From, func(f string) bool { return in[f] }) {
				in[e.To], grew = true, true
			}
		}
	}
	return in
}

// graphReach is clerk's node's reach (nil: none); an undeclared node is all.
func (s *State) graphReach(clerk string) []key.Asset {
	var out []key.Asset
	for id := range s.reached(s.decl.clerks[clerk]) {
		n, ok := s.decl.nodes[id]
		if !ok {
			return []key.Asset{key.AssetData, key.AssetMoney, key.AssetIdentity, key.AssetSafety}
		}
		out = append(out, n.Classes...)
	}
	return out
}
