package graph

import (
	"fmt"
	"sort"
)

// Proposal is a candidate change to the owner's world: a connection, a
// standing key or a fix (CH-12).
type Proposal struct {
	Text       string // what the owner is asked to do, in owner words
	Minutes    int    // the owner's time it takes; below 1 counts as 1
	Structural bool   // removes a failure rather than adding a safeguard
	AddNodes   []Node
	AddEdges   []Edge
	DropEdges  []Edge   // matched by kind, To and the set of From
	SetBrakes  []string // brake node IDs to set
}

// Apply returns the graph with p applied. The receiver is never changed.
// It refuses a dropped edge or a brake that is not in the graph.
func (g *Graph) Apply(p Proposal) (*Graph, error) {
	nodes := g.Nodes()
	for _, id := range p.SetBrakes {
		i, ok := g.index[id]
		if !ok || nodes[i].Kind != BrakeKind {
			return nil, fmt.Errorf("graph: proposal sets %q, which is not a brake", id)
		}
		nodes[i].Set = true
	}
	edges := g.Edges()
	for _, d := range p.DropEdges {
		k := -1
		for i, e := range edges {
			if sameEdge(e, d) {
				k = i
				break
			}
		}
		if k < 0 {
			return nil, fmt.Errorf("graph: proposal drops a %s edge to %q that is not in the graph", d.Kind, d.To)
		}
		edges = append(edges[:k], edges[k+1:]...)
	}
	nodes = append(nodes, p.AddNodes...)
	edges = append(edges, p.AddEdges...)
	return New(nodes, edges)
}

func sameEdge(a, b Edge) bool {
	if a.Kind != b.Kind || a.To != b.To || len(a.From) != len(b.From) {
		return false
	}
	for _, f := range b.From {
		if !contains(a.From, f) {
			return false
		}
	}
	return true
}

// Score is one class's line on the scoreboard.
type Score struct {
	ThiefNeed int // smallest cut set across the class's assets: 1, 2, or 3 for more than two
	CutOff    int // distinct providers whose loss cuts the owner off from one of its assets
	Assets    int // how many assets carry the class
}

// Board is the scoreboard, one score per class (CH-12).
type Board map[Class]Score

// Board scores every class. A class with no assets scores ThiefNeed 3 and
// CutOff 0.
func (g *Graph) Board() Board {
	b := Board{}
	for _, c := range Classes {
		b[c] = Score{ThiefNeed: g.thiefNeed(c), CutOff: g.cutOffCount(c), Assets: len(g.assets(c))}
	}
	return b
}

// Weakest is the class with the lowest ThiefNeed, then the highest CutOff,
// then the order money, identity, safety, data. A class with no assets is
// never the weakest, so a board with no assets at all has no weakest class
// and returns false.
func (b Board) Weakest() (Class, bool) {
	var best Class
	found := false
	for _, c := range Classes {
		s := b[c]
		if s.Assets == 0 {
			continue
		}
		if !found || s.ThiefNeed < b[best].ThiefNeed || (s.ThiefNeed == b[best].ThiefNeed && s.CutOff > b[best].CutOff) {
			best, found = c, true
		}
	}
	return best, found
}

// Weakest is the graph's weakest class; see Board.Weakest.
func (g *Graph) Weakest() (Class, bool) { return g.Board().Weakest() }

// Effect is a proposal's effect on the board, shown before the owner
// approves it (CH-12).
type Effect struct {
	Before, After Board
	Gain          int // the sum over classes of the rise in ThiefNeed and the fall in CutOff
}

// Effect applies p to a copy and compares the boards.
func (g *Graph) Effect(p Proposal) (Effect, error) {
	h, err := g.Apply(p)
	if err != nil {
		return Effect{}, err
	}
	e := Effect{Before: g.Board(), After: h.Board()}
	for _, c := range Classes {
		e.Gain += e.After[c].ThiefNeed - e.Before[c].ThiefNeed
		e.Gain += e.Before[c].CutOff - e.After[c].CutOff
	}
	return e, nil
}

type ranked struct {
	p    Proposal
	gain int
}

func minutes(p Proposal) int {
	if p.Minutes < 1 {
		return 1
	}
	return p.Minutes
}

// rank orders candidates: structural first, then gain per owner minute, then
// Text. Candidates that do not apply are dropped.
func (g *Graph) rank(candidates []Proposal) []ranked {
	var rs []ranked
	for _, p := range candidates {
		e, err := g.Effect(p)
		if err != nil {
			continue
		}
		rs = append(rs, ranked{p, e.Gain})
	}
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.p.Structural != b.p.Structural {
			return a.p.Structural
		}
		if l, r := a.gain*minutes(b.p), b.gain*minutes(a.p); l != r {
			return l > r
		}
		return a.p.Text < b.p.Text
	})
	return rs
}

// Next picks the next action among candidates with gain above zero:
// structural ones first, then the highest gain per owner minute, then by
// Text. It returns false when none qualifies.
func (g *Graph) Next(candidates []Proposal) (Proposal, bool) {
	for _, r := range g.rank(candidates) {
		if r.gain > 0 {
			return r.p, true
		}
	}
	return Proposal{}, false
}

// Confidence counts, by source, the edges a class's measurement rests on
// (CLK-10).
type Confidence struct {
	Shipped, Answer, Observed int
}

// Total is the number of edges counted.
func (c Confidence) Total() int { return c.Shipped + c.Answer + c.Observed }

// AnswerPercent is the share of edges that rest on the owner's answers,
// rounded down; 0 when there are none.
func (c Confidence) AnswerPercent() int {
	if c.Total() == 0 {
		return 0
	}
	return 100 * c.Answer / c.Total()
}

// Confidence counts by source every edge that can reach an asset of class c:
// an edge whose To is such an asset or one of its ancestors over reset, copy
// and act edges.
func (g *Graph) Confidence(c Class) Confidence {
	in := make([]bool, len(g.nodes))
	for _, a := range g.assets(c) {
		in[a] = true
	}
	for changed := true; changed; {
		changed = false
		for _, e := range g.edges {
			if !control(e.Kind) || !in[g.index[e.To]] {
				continue
			}
			for _, f := range e.From {
				if i := g.index[f]; !in[i] {
					in[i] = true
					changed = true
				}
			}
		}
	}
	var out Confidence
	for _, e := range g.edges {
		if !in[g.index[e.To]] {
			continue
		}
		switch e.Source {
		case Shipped:
			out.Shipped++
		case Answer:
			out.Answer++
		case Observed:
			out.Observed++
		}
	}
	return out
}
