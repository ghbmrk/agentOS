package kernel

import (
	"bytes"
	"errors"
	"maps"
	"reflect"
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
		worth  map[key.ID]key.Rank // each grant's worth when first granted
		kept   map[key.ID][]string // the verbs a grant's narrowing keeps
	}
	// KeyNarrowed is the kernel's narrowing of grant Key, whose reach grew
	// from Old to New (KEY-9, KEY-3): the verbs it keeps, those whose reach
	// stays within Old, and the offer of the wider key at Proof,
	// key.Price(key.ActGrant, New).
	KeyNarrowed struct {
		Key   key.ID    `json:"key"`
		Verbs []string  `json:"verbs"`
		Old   key.Rank  `json:"old"`
		New   key.Rank  `json:"new"`
		Proof key.Proof `json:"proof"`
	}
)

// TKeyNarrowed (v1) is a KeyNarrowed: a decision, derived again on replay.
const TKeyNarrowed = "key.narrowed"

// CGrown refuses a key whose reach grew past its worth at grant until the
// kernel narrows it, and then a verb its narrowing does not keep.
const CGrown = "grown"

// ErrDeclReach refuses a declaration the fold would drop: malformed or lowering.
var ErrDeclReach = errors.New("kernel: the declaration is malformed or would lower a price")

// DeclareReach logs d unsigned, not a widening, since it only raises prices;
// one the fold would drop is refused whole and logs nothing.
func (k *Kernel) DeclareReach(at int64, d DeclReach) error {
	if !k.s.declOK(d) {
		return ErrDeclReach
	}
	now := k.read(at)
	if _, err := k.emit(now, TDeclReach, d); err != nil {
		return err
	}
	return k.narrowGrown(now)
}

// narrowGrown logs the narrowing of every grant whose reach grew.
func (k *Kernel) narrowGrown(now Reading) error {
	for _, n := range k.s.narrowings() {
		if _, err := k.emit(now, TKeyNarrowed, n); err != nil {
			return err
		}
	}
	return nil
}

// granted records grant id's worth when first granted; a renewal is a new
// grant, but a key under a narrowed root stays narrowed (State.grown).
func (s *State) granted(id key.ID) {
	if s.decl.worth == nil {
		s.decl.worth, s.decl.kept = map[key.ID]key.Rank{}, map[key.ID][]string{}
	}
	if _, ok := s.decl.worth[id]; !ok {
		s.decl.worth[id] = s.worthOf(id, s.verbsOf(id, false))
	}
}

// verbsOf is grant id's verbs, narrowed (kept) or as granted. A grant was
// checked at its entry, so its last verbs caveat is its verbs.
func (s *State) verbsOf(id key.ID, kept bool) []string {
	if n, ok := s.decl.kept[id]; ok && kept {
		return n
	}
	k := s.Grants[id].Key
	var vs []string
	for _, v := range k.Root.Verbs {
		vs = append(vs, string(v))
	}
	for _, l := range k.Links {
		if f, _ := key.Fold(l.Caveats); f.Verbs != nil {
			vs = f.Verbs
		}
	}
	return vs
}

// worthOf is grant id with only verbs, priced as key.Worth prices a key.
func (s *State) worthOf(id key.ID, verbs []string) key.Rank {
	k := s.Grants[id].Key
	capped := false
	for _, l := range k.Links {
		f, _ := key.Fold(l.Caveats)
		capped = capped || f.Capped()
	}
	var reach []key.Asset
	for _, v := range verbs {
		as := key.AssetsOf(key.Verb(v))
		if slices.ContainsFunc(as, func(a key.Asset) bool { return a >= key.AssetData }) {
			as = append(as, s.graphReach(k.Root.Clerk)...)
		}
		reach = append(reach, as...)
	}
	return key.WorthOf(reach, capped)
}

// narrowing is the narrowing grant id needs now, if what it keeps grew past
// its worth at grant: each verb alone within that worth, so the narrowed
// key is worth no more (a key's worth is its highest verb's).
func (s *State) narrowing(id key.ID) *KeyNarrowed {
	old, ok := s.decl.worth[id]
	vs := s.verbsOf(id, true)
	if !ok || s.Changes.Revoked[id] || s.worthOf(id, vs) <= old { // a revoked grant is offered nothing
		return nil
	}
	n := s.worthOf(id, s.verbsOf(id, false))
	out := &KeyNarrowed{Key: id, Verbs: []string{}, Old: old, New: n, Proof: key.Price(key.ActGrant, n)}
	for _, v := range vs {
		if s.worthOf(id, []string{v}) <= old {
			out.Verbs = append(out.Verbs, v)
		}
	}
	return out
}

// narrowings is every narrowing owed, in grant ID order.
func (s *State) narrowings() []KeyNarrowed {
	var out []KeyNarrowed
	for _, id := range slices.SortedFunc(maps.Keys(s.decl.worth), func(a, b key.ID) int { return bytes.Compare(a[:], b[:]) }) {
		if n := s.narrowing(id); n != nil {
			out = append(out, *n)
		}
	}
	return out
}

// applyNarrowed folds a narrowing only as the kernel derives it now.
func (s *State) applyNarrowed(e Entry) error {
	b, err := body[KeyNarrowed](e)
	if n := s.narrowing(b.Key); err == nil && n != nil && reflect.DeepEqual(*n, b) {
		s.decl.kept[b.Key] = b.Verbs
	}
	return err
}

// grown refuses a key whose root or first link grew and is not narrowed
// yet, or a verb vb outside a narrowing of either.
func (s *State) grown(v *key.Verified, vb key.Verb) *key.Refusal {
	for _, id := range v.IDs[:min(2, len(v.IDs))] {
		if s.narrowing(id) != nil {
			return &key.Refusal{Code: CGrown, Detail: "the key's reach grew; it waits for its narrowing"}
		}
		if n, ok := s.decl.kept[id]; ok && !slices.Contains(n, string(vb)) {
			return &key.Refusal{Code: CGrown, Detail: "outside the key's narrowing: " + string(vb)}
		}
	}
	return nil
}

// DeclReach is a copy of what the log declared, for a writer sending only
// additions: editing it leaves the fold, so no price, unchanged.
func (s *State) DeclReach() (d DeclReach) {
	for _, n := range s.decl.nodes {
		n.Classes = slices.Clone(n.Classes)
		d.Nodes = append(d.Nodes, n)
	}
	for _, e := range s.decl.edges {
		e.From = slices.Clone(e.From)
		d.Edges = append(d.Edges, e)
	}
	return d
}

// applyDecl folds a decl.reach entry, or drops it whole if declOK refuses.
func (s *State) applyDecl(e Entry) error {
	b, err := body[DeclReach](e)
	if err != nil || !s.declOK(b) {
		return err
	}
	d := &s.decl
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

// declOK refuses, on an empty ID, a class past the table, a repeated node,
// an edge not reset, copy or act or without From, a clerk or node rebound,
// or a first declaration of a node an edge named (priced as every class):
// each lowers.
func (s *State) declOK(b DeclReach) bool {
	d, bind, seen := &s.decl, maps.Collect(maps.All(s.decl.clerks)), map[string]bool{}
	for _, n := range b.Nodes {
		c, bound := bind[n.Clerk]
		old, had := d.nodes[n.ID]
		rebound := n.Clerk != "" && (had && old.Clerk != "" && old.Clerk != n.Clerk || bound && c != n.ID)
		if rebound || seen[n.ID] || n.ID == "" || slices.ContainsFunc(n.Classes, func(a key.Asset) bool { return a > key.AssetSafety }) ||
			!had && slices.ContainsFunc(d.edges, func(e ReachEdge) bool { return e.To == n.ID || slices.Contains(e.From, n.ID) }) {
			return false
		}
		seen[n.ID], bind[n.Clerk] = true, n.ID
	}
	for _, e := range b.Edges {
		if !slices.Contains([]string{"reset", "copy", "act"}, e.Kind) || len(e.From) == 0 || e.To == "" || slices.Contains(e.From, "") {
			return false
		}
	}
	return true
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
