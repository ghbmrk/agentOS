package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Graph reach (KEY-9, CLK-10, CLK-14). A key reaches what its verbs touch
// directly and what its clerk's node reaches over the declarations' control
// edges. The account graph lives outside the trusted core (broker/owner/graph,
// KRN-2), so the kernel folds only the facts it needs from a decl.reach entry
// and keeps graph.Reach's rule: an edge fires when any of its From is in the
// set. Entries only add, so the log's reach only grows and a writer the kernel
// does not trust can only raise a price; removing an edge lowers one and is
// not in the format.

// TDeclReach is a declaration's reach facts, version 1.
const TDeclReach = "decl.reach"

// Limits on one decl.reach entry, so a fold stays bounded.
const (
	MaxDeclItems = 1024 // nodes plus edges
	MaxDeclID    = 128
)

// ErrDecl refuses a decl.reach the fold would not keep: an empty or long ID,
// an unknown class or edge kind, an edge with no From or a repeated one, a
// field the format does not have, or too many items.
var ErrDecl = errors.New("kernel: not a declaration I can fold")

// DeclNode is one declared node: its ID, the clerk whose keys root on it, and
// its classes. A node declared with no classes is one whose classes are not
// known, so it reaches every class (fail closed); AssetNone says it reaches
// none. A device reaches safety only when marked safety or access (Mark,
// #4999 comment 6705669120): unmarked, its safety class is dropped.
type DeclNode struct {
	ID     string      `json:"id"`
	Clerk  string      `json:"clerk,omitempty"`
	Assets []key.Asset `json:"assets,omitempty"`
	Device bool        `json:"device,omitempty"`
	Marked bool        `json:"marked,omitempty"`
}

// DeclEdge is a control edge: reset, copy or act. To is reached when any
// From is.
type DeclEdge struct {
	Kind string   `json:"kind"`
	From []string `json:"from"`
	To   string   `json:"to"`
}

// DeclReach is a decl.reach body.
type DeclReach struct {
	Nodes []DeclNode `json:"nodes,omitempty"`
	Edges []DeclEdge `json:"edges,omitempty"`
}

const allAssets = 1<<(key.AssetSafety+1) - 1

// reach is the folded declarations: each node's classes as bits, the nodes
// each clerk roots on, and the edges, each kept once.
type reach struct {
	mask  map[string]uint8
	roots map[string][]string
	edges []DeclEdge
	seen  map[string]bool
}

func declID(id string) bool { return id != "" && len(id) <= MaxDeclID }

// check is the shape a decl.reach passes, live and on replay.
func (d DeclReach) check() error {
	if len(d.Nodes)+len(d.Edges) == 0 || len(d.Nodes)+len(d.Edges) > MaxDeclItems {
		return ErrDecl
	}
	for _, n := range d.Nodes {
		if !declID(n.ID) || len(n.Clerk) > MaxDeclID || slices.ContainsFunc(n.Assets, func(a key.Asset) bool { return a > key.AssetSafety }) {
			return ErrDecl
		}
	}
	for _, e := range d.Edges {
		if e.Kind != "reset" && e.Kind != "copy" && e.Kind != "act" || !declID(e.To) || len(e.From) == 0 {
			return ErrDecl
		}
		for i, f := range e.From {
			if !declID(f) || slices.Contains(e.From[:i], f) {
				return ErrDecl
			}
		}
	}
	return nil
}

// decodeDecl reads a decl.reach body strictly: a field the format lacks,
// such as a removal, is refused rather than ignored.
func decodeDecl(b []byte) (DeclReach, error) {
	var d DeclReach
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil {
		return d, ErrDecl
	}
	return d, d.check()
}

// add folds d, which check passed. Every fact is a union, so no entry lowers
// what any node reaches. An edge into a node no entry declared makes that
// node one of unknown classes.
func (r *reach) add(d DeclReach) {
	if r.mask == nil {
		r.mask, r.roots, r.seen = map[string]uint8{}, map[string][]string{}, map[string]bool{}
	}
	for _, n := range d.Nodes {
		var m uint8
		for _, a := range n.Assets {
			m |= 1 << a
		}
		switch {
		case n.Device && n.Marked:
			m |= 1 << key.AssetSafety
		case n.Device:
			m = m&^(1<<key.AssetSafety) | 1<<key.AssetNone
		case m == 0:
			m = allAssets
		}
		r.mask[n.ID] |= m
		if n.Clerk != "" && !slices.Contains(r.roots[n.Clerk], n.ID) {
			r.roots[n.Clerk] = append(r.roots[n.Clerk], n.ID)
		}
	}
	for _, e := range d.Edges {
		from := slices.Sorted(slices.Values(e.From))
		id := strings.Join(from, "\x00") + "\x01" + e.To
		if r.seen[id] {
			continue
		}
		r.seen[id] = true
		r.edges = append(r.edges, DeclEdge{Kind: e.Kind, From: from, To: e.To})
		if r.mask[e.To] == 0 {
			r.mask[e.To] = allAssets
		}
	}
}

// reached is the node set from the nodes clerk roots on, grown over the
// edges to a fixed point, an edge firing when any From is in it (graph.Reach).
func (r *reach) reached(clerk string) map[string]bool {
	in := map[string]bool{}
	for _, n := range r.roots[clerk] {
		in[n] = true
	}
	for changed := len(in) > 0; changed; {
		changed = false
		for _, e := range r.edges {
			if !in[e.To] && slices.ContainsFunc(e.From, func(f string) bool { return in[f] }) {
				in[e.To], changed = true, true
			}
		}
	}
	return in
}

// GraphReach is the classes clerk's node reaches over the declarations, or
// nil when no declaration roots a node on clerk: its keys then keep their
// direct reach.
func (s *State) GraphReach(clerk string) []key.Asset {
	var m uint8
	for n := range s.decl.reached(clerk) {
		m |= s.decl.mask[n]
	}
	var out []key.Asset
	for a := key.AssetNone; a <= key.AssetSafety; a++ {
		if m&(1<<a) != 0 {
			out = append(out, a)
		}
	}
	return out
}

// applyDecl folds a decl.reach. One that fails its check, written past the
// kernel, changes nothing.
func (s *State) applyDecl(e Entry) error {
	if d, err := decodeDecl(e.Body); err == nil {
		s.decl.add(d)
	}
	return nil
}

// DeclareReach logs d. It only raises prices, so it needs no signature; it
// anchors, so a rollback the anchor catches cannot drop it.
func (k *Kernel) DeclareReach(at int64, d DeclReach) error {
	if err := d.check(); err != nil {
		return err
	}
	return k.owner(k.read(at), TDeclReach, d)
}
