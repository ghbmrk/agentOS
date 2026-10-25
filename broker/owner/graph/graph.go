// Package graph is the owner's account graph (D-149): accounts, credentials,
// providers, devices, keys and people, and the edges between them. Every list
// the box shows about the owner's exposure comes from it: thief cut sets,
// cut-off sets, rotation lists, unset brakes and correlated safeguards
// (KRN-11, CLK-10, CH-12).
//
// The package is advisory. It holds no key and sends nothing; enforcement
// stays in the clerks and the kernel. It imports only the standard library.
package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind is a node's kind.
type Kind string

// Node kinds. Provider, Power and Uplink are the providers whose loss can
// cut the owner off (D-152).
const (
	Account    Kind = "account"
	Credential Kind = "credential"
	Provider   Kind = "provider"
	Device     Kind = "device"
	Key        Kind = "key"
	Person     Kind = "person"
	NodeKind   Kind = "node"
	Surface    Kind = "surface"
	Power      Kind = "power"
	Uplink     Kind = "uplink"
	BrakeKind  Kind = "brake"
)

var kinds = map[Kind]bool{Account: true, Credential: true, Provider: true, Device: true, Key: true,
	Person: true, NodeKind: true, Surface: true, Power: true, Uplink: true, BrakeKind: true}

// Class is an asset class a node can carry.
type Class string

// Asset classes, in the order Weakest breaks ties.
const (
	Money    Class = "money"
	Identity Class = "identity"
	Safety   Class = "safety"
	Data     Class = "data"
)

// Classes lists the asset classes in tie-break order.
var Classes = []Class{Money, Identity, Safety, Data}

// Source says where a node or edge came from (CLK-10).
type Source string

// Sources.
const (
	Shipped  Source = "shipped"
	Answer   Source = "answer"
	Observed Source = "observed"
)

// Node is one thing in the owner's world.
type Node struct {
	ID      string
	Kind    Kind
	Name    string   // what the owner calls it; the only label owner text uses
	Domains []string // failure-domain labels, such as "maker:yubico"
	Assets  []Class
	Page    string // the provider page that sets a brake or applies a fix
	Set     bool   // a brake's state
	Owner   bool   // the owner's own person node
	LastUse time.Time
	Source  Source
}

// EdgeKind is an edge's kind.
type EdgeKind string

// Edge kinds. Reset, Copy and Act carry control: an edge with several From
// needs all of them (AND); several edges into one To are an OR.
const (
	Reset  EdgeKind = "reset"  // From can reset To
	Copy   EdgeKind = "copy"   // From holds a copy of To
	Act    EdgeKind = "act"    // From can act on To
	Cutoff EdgeKind = "cutoff" // losing From cuts off To
	Brake  EdgeKind = "brake"  // From[0] brakes To
	Watch  EdgeKind = "watch"  // From[0] is a witness that sees To
)

var edgeKinds = map[EdgeKind]bool{Reset: true, Copy: true, Act: true, Cutoff: true, Brake: true, Watch: true}

// Edge joins nodes.
type Edge struct {
	Kind   EdgeKind
	From   []string
	To     string
	Source Source
}

func control(k EdgeKind) bool { return k == Reset || k == Copy || k == Act }

// Graph is an immutable owner graph. Build one with New.
type Graph struct {
	nodes []Node
	edges []Edge
	index map[string]int
}

func validSource(s Source) bool { return s == Shipped || s == Answer || s == Observed }

// New checks and copies nodes and edges into a graph. It refuses an empty or
// repeated ID, an unknown kind or source, an edge naming an unknown node or
// repeating a From, a cutoff, brake or watch edge without exactly one From,
// and a brake edge whose From is not a brake node.
func New(nodes []Node, edges []Edge) (*Graph, error) {
	g := &Graph{index: make(map[string]int, len(nodes))}
	for _, n := range nodes {
		if n.ID == "" {
			return nil, fmt.Errorf("graph: node with empty ID")
		}
		if _, dup := g.index[n.ID]; dup {
			return nil, fmt.Errorf("graph: node %q repeated", n.ID)
		}
		if !kinds[n.Kind] {
			return nil, fmt.Errorf("graph: node %q has unknown kind %q", n.ID, n.Kind)
		}
		if !validSource(n.Source) {
			return nil, fmt.Errorf("graph: node %q has unknown source %q", n.ID, n.Source)
		}
		for _, c := range n.Assets {
			if c != Money && c != Identity && c != Safety && c != Data {
				return nil, fmt.Errorf("graph: node %q has unknown asset class %q", n.ID, c)
			}
		}
		n.Domains = append([]string(nil), n.Domains...)
		n.Assets = append([]Class(nil), n.Assets...)
		g.index[n.ID] = len(g.nodes)
		g.nodes = append(g.nodes, n)
	}
	for i, e := range edges {
		if !edgeKinds[e.Kind] {
			return nil, fmt.Errorf("graph: edge %d has unknown kind %q", i, e.Kind)
		}
		if !validSource(e.Source) {
			return nil, fmt.Errorf("graph: edge %d has unknown source %q", i, e.Source)
		}
		if len(e.From) == 0 {
			return nil, fmt.Errorf("graph: edge %d has no From", i)
		}
		if !control(e.Kind) && len(e.From) != 1 {
			return nil, fmt.Errorf("graph: %s edge %d needs exactly one From, has %d", e.Kind, i, len(e.From))
		}
		if _, ok := g.index[e.To]; !ok {
			return nil, fmt.Errorf("graph: edge %d names unknown node %q", i, e.To)
		}
		seen := map[string]bool{}
		for _, f := range e.From {
			if _, ok := g.index[f]; !ok {
				return nil, fmt.Errorf("graph: edge %d names unknown node %q", i, f)
			}
			if seen[f] {
				return nil, fmt.Errorf("graph: edge %d repeats %q", i, f)
			}
			seen[f] = true
		}
		if e.Kind == Brake && g.nodes[g.index[e.From[0]]].Kind != BrakeKind {
			return nil, fmt.Errorf("graph: brake edge %d is from %q, which is not a brake", i, e.From[0])
		}
		e.From = append([]string(nil), e.From...)
		g.edges = append(g.edges, e)
	}
	return g, nil
}

// Nodes returns a copy of the graph's nodes.
func (g *Graph) Nodes() []Node {
	out := make([]Node, len(g.nodes))
	for i, n := range g.nodes {
		n.Domains = append([]string(nil), n.Domains...)
		n.Assets = append([]Class(nil), n.Assets...)
		out[i] = n
	}
	return out
}

// Edges returns a copy of the graph's edges.
func (g *Graph) Edges() []Edge {
	out := make([]Edge, len(g.edges))
	for i, e := range g.edges {
		e.From = append([]string(nil), e.From...)
		out[i] = e
	}
	return out
}

// Node returns the node with the given ID.
func (g *Graph) Node(id string) (Node, bool) {
	i, ok := g.index[id]
	if !ok {
		return Node{}, false
	}
	return g.Nodes()[i], true
}

// Domains is the sorted union of every node's failure-domain labels.
func (g *Graph) Domains() []string {
	set := map[string]bool{}
	for _, n := range g.nodes {
		for _, d := range n.Domains {
			set[d] = true
		}
	}
	return sortedKeys(set)
}

// assets returns the indices of the nodes carrying class c.
func (g *Graph) assets(c Class) []int {
	var out []int
	for i, n := range g.nodes {
		for _, a := range n.Assets {
			if a == c {
				out = append(out, i)
				break
			}
		}
	}
	return out
}

// closure grows in over control edges to a fixed point. With all set, an edge
// fires when every From is in the set; otherwise when any is. Nodes in skip
// never join.
func (g *Graph) closure(in []bool, all bool, kinds func(EdgeKind) bool, skip []bool) []bool {
	for changed := true; changed; {
		changed = false
		for _, e := range g.edges {
			to := g.index[e.To]
			if !kinds(e.Kind) || in[to] || (skip != nil && skip[to]) {
				continue
			}
			fire := all
			for _, f := range e.From {
				if in[g.index[f]] != all {
					fire = !all
					break
				}
			}
			if fire {
				in[to] = true
				changed = true
			}
		}
	}
	return in
}

// Resolve finds the node a `STOP <name>` names: an ID first, then a unique
// Name, both ignoring case. No match, or a Name shared by several nodes,
// returns false, which the caller reads as "pause everything" (CH-11).
func (g *Graph) Resolve(name string) (string, bool) {
	name = strings.TrimSpace(name)
	for _, n := range g.nodes {
		if strings.EqualFold(n.ID, name) {
			return n.ID, true
		}
	}
	found := ""
	for _, n := range g.nodes {
		if strings.EqualFold(n.Name, name) {
			if found != "" {
				return "", false
			}
			found = n.ID
		}
	}
	return found, found != ""
}

// Reach is what `STOP <name>` pauses: the node and everything it reaches over
// reset, copy and act edges, where an edge fires when any of its From is in
// the set. It is wider than the thief's closure on purpose: an over-wide
// pause costs only a pause (D-151). An unknown ID returns false.
func (g *Graph) Reach(id string) ([]string, bool) {
	i, ok := g.index[id]
	if !ok {
		return nil, false
	}
	in := make([]bool, len(g.nodes))
	in[i] = true
	return g.ids(g.closure(in, false, control, nil)), true
}

// Rotation is what to rotate when a node is lost.
type Rotation struct {
	Recover []string // accounts that recover through the node, over reset edges
	Copies  []string // what the node holds a copy of
}

// Rotation lists the accounts that recover through id (the closure over
// reset edges, any From firing) and what id holds a copy of, each sorted.
// An unknown ID returns false.
func (g *Graph) Rotation(id string) (Rotation, bool) {
	i, ok := g.index[id]
	if !ok {
		return Rotation{}, false
	}
	in := make([]bool, len(g.nodes))
	in[i] = true
	g.closure(in, false, func(k EdgeKind) bool { return k == Reset }, nil)
	var r Rotation
	for j, n := range g.nodes {
		if in[j] && j != i && n.Kind == Account {
			r.Recover = append(r.Recover, n.ID)
		}
	}
	copies := map[string]bool{}
	for _, e := range g.edges {
		if e.Kind == Copy && contains(e.From, id) {
			copies[e.To] = true
		}
	}
	sort.Strings(r.Recover)
	r.Copies = sortedKeys(copies)
	return r, true
}

func (g *Graph) ids(in []bool) []string {
	var out []string
	for i, b := range in {
		if b {
			out = append(out, g.nodes[i].ID)
		}
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
