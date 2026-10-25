package graph

import "sort"

// Cut is a set of failure domains that together take an asset.
type Cut struct {
	Asset   string   // the asset node's ID
	Domains []string // one domain, or a minimal pair, sorted
}

// compromised returns which nodes a thief holding the failure domains in d
// controls: a node with a domain in d, then, to a fixed point, the To of any
// reset, copy or act edge whose every From is held.
func (g *Graph) compromised(d map[string]bool) []bool {
	in := make([]bool, len(g.nodes))
	for i, n := range g.nodes {
		for _, x := range n.Domains {
			if d[x] {
				in[i] = true
				break
			}
		}
	}
	return g.closure(in, true, control, nil)
}

// bounded reports whether asset a is held back from a thief who controls
// comp: a brake edge from a Set brake node, where that brake or the asset has
// a watch edge from a node the thief does not control (KRN-11).
func (g *Graph) bounded(a int, comp []bool) bool {
	id := g.nodes[a].ID
	for _, e := range g.edges {
		if e.Kind != Brake || e.To != id {
			continue
		}
		b := g.index[e.From[0]]
		if !g.nodes[b].Set {
			continue
		}
		for _, w := range g.edges {
			if w.Kind == Watch && (w.To == id || w.To == g.nodes[b].ID) && !comp[g.index[w.From[0]]] {
				return true
			}
		}
	}
	return false
}

// taken reports whether asset a of class c falls to a thief who controls
// comp. Data falls whenever it is compromised, since a read cannot be delayed.
func (g *Graph) taken(a int, c Class, comp []bool) bool {
	if !comp[a] {
		return false
	}
	return c == Data || !g.bounded(a, comp)
}

// CutSets returns, per asset of class c, every failure domain that alone
// takes it and every pair that takes it where neither member does alone,
// sorted by asset, then size, then domains (KRN-11).
func (g *Graph) CutSets(c Class) []Cut {
	assets := g.assets(c)
	if len(assets) == 0 {
		return nil
	}
	doms := g.Domains()
	single := make([]map[string]bool, len(assets))
	for k := range assets {
		single[k] = map[string]bool{}
	}
	var out []Cut
	for _, x := range doms {
		comp := g.compromised(map[string]bool{x: true})
		for k, a := range assets {
			if g.taken(a, c, comp) {
				single[k][x] = true
				out = append(out, Cut{g.nodes[a].ID, []string{x}})
			}
		}
	}
	for i, x := range doms {
		for _, y := range doms[i+1:] {
			var comp []bool
			for k, a := range assets {
				if single[k][x] || single[k][y] {
					continue
				}
				if comp == nil {
					comp = g.compromised(map[string]bool{x: true, y: true})
				}
				if g.taken(a, c, comp) {
					out = append(out, Cut{g.nodes[a].ID, []string{x, y}})
				}
			}
		}
	}
	sortCuts(out)
	return out
}

func sortCuts(cs []Cut) {
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Asset != b.Asset {
			return a.Asset < b.Asset
		}
		if len(a.Domains) != len(b.Domains) {
			return len(a.Domains) < len(b.Domains)
		}
		for k := range a.Domains {
			if a.Domains[k] != b.Domains[k] {
				return a.Domains[k] < b.Domains[k]
			}
		}
		return false
	})
}

// thiefNeed is the smallest cut size across class c's assets: 1, 2, or 3
// meaning more than two. A class with no assets needs 3.
func (g *Graph) thiefNeed(c Class) int {
	need := 3
	for _, cut := range g.CutSets(c) {
		if len(cut.Domains) < need {
			need = len(cut.Domains)
		}
	}
	return need
}

// CutOff lists the providers whose loss alone leaves the owner unable to
// reach an asset.
type CutOff struct {
	Asset     string
	Providers []string
}

func isProvider(k Kind) bool { return k == Provider || k == Power || k == Uplink }

// reach is what the owner reaches from the owner's person nodes over reset,
// copy and act edges (AND and OR), never entering a removed node.
func (g *Graph) reach(removed []bool) []bool {
	in := make([]bool, len(g.nodes))
	for i, n := range g.nodes {
		if n.Owner && n.Kind == Person && !removed[i] {
			in[i] = true
		}
	}
	return g.closure(in, true, control, removed)
}

// removal is provider p and everything its loss cuts off, transitively over
// cutoff edges: power that cuts the uplink also cuts what the uplink cuts.
func (g *Graph) removal(p int) []bool {
	gone := make([]bool, len(g.nodes))
	gone[p] = true
	return g.closure(gone, false, func(k EdgeKind) bool { return k == Cutoff }, nil)
}

// CutOffs returns, per asset of class c the owner reaches, each provider
// (kinds provider, power and uplink) whose removal leaves it unreached, and
// separately the assets the owner does not reach even with nothing removed
// (KRN-11, D-152). Both are sorted; assets with no cut-off provider are
// left out of the first list.
func (g *Graph) CutOffs(c Class) (cut []CutOff, unreached []string) {
	assets := g.assets(c)
	if len(assets) == 0 {
		return nil, nil
	}
	base := g.reach(make([]bool, len(g.nodes)))
	by := map[int][]string{}
	for p, n := range g.nodes {
		if !isProvider(n.Kind) {
			continue
		}
		after := g.reach(g.removal(p))
		for _, a := range assets {
			if base[a] && !after[a] {
				by[a] = append(by[a], n.ID)
			}
		}
	}
	for _, a := range assets {
		if !base[a] {
			unreached = append(unreached, g.nodes[a].ID)
			continue
		}
		if ps := by[a]; len(ps) > 0 {
			sort.Strings(ps)
			cut = append(cut, CutOff{g.nodes[a].ID, ps})
		}
	}
	sort.Slice(cut, func(i, j int) bool { return cut[i].Asset < cut[j].Asset })
	sort.Strings(unreached)
	return cut, unreached
}

// cutOffCount is the number of distinct providers in class c's cut-off sets.
func (g *Graph) cutOffCount(c Class) int {
	cut, _ := g.CutOffs(c)
	set := map[string]bool{}
	for _, x := range cut {
		for _, p := range x.Providers {
			set[p] = true
		}
	}
	return len(set)
}
