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
// It refuses a dropped edge or a brake that is not in the graph, any added
// owner node (a proposal never changes who the owner is), and an added
// control edge from the owner onto a node the proposal does not add.
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
	added := map[string]bool{}
	for _, n := range p.AddNodes {
		if n.Owner {
			// The owner set is what reach is measured from: a proposal that
			// adds an owner could mask a lock-out of the real one.
			return nil, fmt.Errorf("graph: proposal adds owner node %q", n.ID)
		}
		added[n.ID] = true
	}
	for _, e := range p.AddEdges {
		// The owner cannot fail, so a new edge from the owner onto a node
		// already there is free reach that could mask a lock-out. Only a
		// node the proposal adds, such as a new key, may gain one.
		if !control(e.Kind) || len(e.From) != 1 {
			continue // New checks the rest
		}
		if i, ok := g.index[e.From[0]]; ok && g.nodes[i].Owner && !added[e.To] {
			return nil, fmt.Errorf("graph: proposal adds an owner edge onto %q, which it does not add", e.To)
		}
	}
	nodes = append(nodes, p.AddNodes...)
	edges = append(edges, p.AddEdges...)
	return New(nodes, edges)
}

func sameEdge(a, b Edge) bool {
	return a.Kind == b.Kind && a.To == b.To && subset(a.From, b.From) && subset(b.From, a.From)
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
	// Weakens is set when the proposal breaks the non-regression
	// invariant for some asset in the after state, new assets included
	// (TN-graph-A16): the owner must still reach every asset reached
	// before; no asset may gain a cut-off provider; and no asset may gain a
	// thief cut (a single domain or a pair) at or below its old smallest
	// cut. A new asset's old state is its own maker or provider alone: one
	// failure of a domain only it carries, no other cut, no cut-off
	// provider. Next and the STATUS fixes never offer a proposal that
	// weakens, whatever its gain.
	Weakens bool
	// Steps is the fall in single-domain cuts across every asset and class
	// plus the fall in assets some provider can cut off: progress the
	// per-class minimum misses, such as removing one of two single cuts.
	// An asset the proposal locks the owner out of counts on neither side.
	Steps int
}

// facts is one asset's exposure in one class.
type facts struct {
	cuts    [][]string
	cutBy   map[string]bool
	reached bool
	owned   []string // domains no other node carries
}

// exposure is, per asset and class, its cuts, its cut-off providers and
// whether the owner reaches it.
type exposure map[[2]string]*facts

func (g *Graph) exposure() exposure {
	x := exposure{}
	base := g.reach(make([]bool, len(g.nodes)))
	for _, c := range Classes {
		for _, a := range g.assets(c) {
			f := &facts{cutBy: map[string]bool{}, reached: base[a]}
			for _, d := range g.nodes[a].Domains {
				if g.onlyCarrier(d, g.nodes[a].ID) {
					f.owned = append(f.owned, d)
				}
			}
			x[[2]string{g.nodes[a].ID, string(c)}] = f
		}
		for _, cut := range g.CutSets(c) {
			f := x[[2]string{cut.Asset, string(c)}]
			f.cuts = append(f.cuts, cut.Domains)
		}
		offs, _ := g.CutOffs(c)
		for _, o := range offs {
			for _, p := range o.Providers {
				x[[2]string{o.Asset, string(c)}].cutBy[p] = true
			}
		}
	}
	return x
}

// smallest is the size of f's smallest cut: 1, 2, or 3 for none.
func (f *facts) smallest() int {
	n := 3
	for _, c := range f.cuts {
		if len(c) < n {
			n = len(c)
		}
	}
	return n
}

// baseline is what a new asset is held to: its own maker or provider alone
// can take it (a single cut of each domain only it carries, the floor any
// asset has), nothing else, and no provider can cut the owner off from it.
func baseline(a *facts) *facts {
	b := &facts{cutBy: map[string]bool{}}
	for _, d := range a.owned {
		b.cuts = append(b.cuts, []string{d})
	}
	return b
}

// weakens checks the non-regression invariant (Effect.Weakens, TN-graph-A16)
// over every asset and class in after:
//
//	reached(before) => reached(after)
//	cutOffProviders(after) is a subset of cutOffProviders(before)
//	every cut of after that before lacks is larger than before's smallest
//
// where a new asset's before is its baseline and its smallest is taken as 1.
func (before exposure) weakens(after exposure) bool {
	for k, a := range after {
		b, min := before[k], 0
		if b == nil {
			b, min = baseline(a), 1
		} else {
			min = b.smallest()
		}
		if b.reached && !a.reached {
			return true // locked out: cut off by nothing at all
		}
		for p := range a.cutBy {
			if !b.cutBy[p] {
				return true
			}
		}
		for _, cut := range a.cuts {
			if len(cut) <= min && !hasCut(b.cuts, cut) {
				return true
			}
		}
	}
	return false
}

func hasCut(cuts [][]string, c []string) bool {
	for _, x := range cuts {
		if len(x) == len(c) && subset(x, c) {
			return true
		}
	}
	return false
}

// steps is the fall in single cuts and cut-off assets from before to
// after, leaving out any asset the owner reached before and not after.
func (before exposure) steps(after exposure) int {
	count := func(f *facts) int {
		n := 0
		for _, c := range f.cuts {
			if len(c) == 1 {
				n++
			}
		}
		if len(f.cutBy) > 0 {
			n++
		}
		return n
	}
	lockedOut := func(k [2]string) bool {
		b, a := before[k], after[k]
		return b != nil && a != nil && b.reached && !a.reached
	}
	n := 0
	for k, b := range before {
		if !lockedOut(k) {
			n += count(b)
		}
	}
	for k, a := range after {
		if !lockedOut(k) {
			n -= count(a)
		}
	}
	return n
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
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
	before, after := g.exposure(), h.exposure()
	e.Weakens = before.weakens(after)
	e.Steps = before.steps(after)
	return e, nil
}

type ranked struct {
	p       Proposal
	gain    int
	steps   int
	weakens bool
	lowers  bool // some class's ThiefNeed falls or CutOff rises
}

func minutes(p Proposal) int {
	if p.Minutes < 1 {
		return 1
	}
	return p.Minutes
}

// rank orders candidates: structural first, then gain per owner minute,
// then steps per owner minute, then Text. Candidates that do not apply are dropped.
func (g *Graph) rank(candidates []Proposal) []ranked {
	var rs []ranked
	for _, p := range candidates {
		e, err := g.Effect(p)
		if err != nil {
			continue
		}
		rs = append(rs, ranked{p, e.Gain, e.Steps, e.Weakens, e.Lowers()})
	}
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.p.Structural != b.p.Structural {
			return a.p.Structural
		}
		if l, r := a.gain*minutes(b.p), b.gain*minutes(a.p); l != r {
			return l > r
		}
		if l, r := a.steps*minutes(b.p), b.steps*minutes(a.p); l != r {
			return l > r
		}
		return a.p.Text < b.p.Text
	})
	return rs
}

// Lowers reports whether some class scores worse after: a lower ThiefNeed
// or a higher CutOff. A gain summed across classes never hides one.
func (e Effect) Lowers() bool {
	for _, c := range Classes {
		if e.After[c].ThiefNeed < e.Before[c].ThiefNeed || e.After[c].CutOff > e.Before[c].CutOff {
			return true
		}
	}
	return false
}

// acceptable is the bar every offered proposal clears: it weakens no asset
// (Effect.Weakens) and lowers no class on the board (Effect.Lowers), so its
// gain is at least zero.
func (r ranked) acceptable() bool { return !r.weakens && !r.lowers }

// Next picks the next action among acceptable candidates with gain or steps
// above zero: structural ones first, then the highest gain per owner
// minute, then steps per minute, then by Text. It returns false when none
// qualifies.
func (g *Graph) Next(candidates []Proposal) (Proposal, bool) {
	for _, r := range g.rank(candidates) {
		if r.acceptable() && (r.gain > 0 || r.steps > 0) {
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
