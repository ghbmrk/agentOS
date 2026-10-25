package graph

// REQ: TN-graph-a, TN-graph-b, TN-graph-c, TN-graph-d, TN-graph-e, TN-graph-f, TN-graph-g, TN-graph-h, TN-graph-i

import (
	"fmt"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TN-graph-a: the engine counts failure domains, never nodes.
func TestTwoKeysOfOneMakerAreOneDomain(t *testing.T) {
	g := household(t, true)
	// Ana's registrar needs both keys, and the mailbox opens with either; one
	// maker's flaw takes both keys, so it is one single cut, not a pair.
	for _, c := range g.CutSets(Identity) {
		if reflect.DeepEqual(c, Cut{"a.registrar", dom("maker:yubico")}) {
			goto found
		}
	}
	t.Fatalf("one maker's two keys not counted as one domain: %v", g.CutSets(Identity))
found:
	if got := g.Domains(); !reflect.DeepEqual(got, dom("maker:yubico", "node:core", "node:home", "phone:ana", "provider:carrier", "provider:google", "provider:yahoo",
		"self:a.bank", "self:a.blog", "self:a.registrar", "self:b.card", "self:b.payee", "self:c.codes", "self:d.car", "self:d.lock", "self:p.sis", "self:v.power", "self:v.uplink")) {
		t.Fatalf("domains = %v", got)
	}
	// A vault that needs both keys: one maker's keys fall to one failure;
	// keys of two makers need a pair. Counting nodes would see two either way.
	vault := func(m2 string) []Cut {
		h, err := New([]Node{
			n("k.a", Key, "Key A", dom("maker:yubico")), n("k.b", Key, "Key B", dom(m2)),
			n("a.v", Account, "Vault", nil, Money),
		}, []Edge{e(Act, "a.v", "k.a", "k.b")})
		if err != nil {
			t.Fatal(err)
		}
		return h.CutSets(Money)
	}
	if got := vault("maker:yubico"); !reflect.DeepEqual(got, []Cut{{"a.v", dom("maker:yubico")}, {"a.v", dom("self:a.v")}}) {
		t.Errorf("one maker: %v", got)
	}
	if got := vault("maker:other"); !reflect.DeepEqual(got, []Cut{{"a.v", dom("self:a.v")}, {"a.v", dom("maker:other", "maker:yubico")}}) {
		t.Errorf("two makers: %v", got)
	}
}

// TN-graph-a: New refuses malformed edges.
func TestNewRefusesMalformedEdges(t *testing.T) {
	base := []Node{
		n("a.x", Account, "X", nil, Money),
		n("a.y", Account, "Y", nil),
		n("b.z", BrakeKind, "Z", nil),
		n("a.w", Account, "W", nil),
	}
	cases := map[string]Edge{
		"AND brake":      e(Brake, "a.x", "b.z", "a.y"),
		"AND cutoff":     e(Cutoff, "a.x", "a.y", "a.w"),
		"AND watch":      e(Watch, "a.x", "a.y", "a.w"),
		"unknown From":   e(Act, "a.x", "a.nobody"),
		"unknown To":     e(Act, "a.nobody", "a.x"),
		"no From":        {Kind: Act, To: "a.x", Source: Shipped},
		"repeated From":  e(Act, "a.x", "a.y", "a.y"),
		"brake from non": e(Brake, "a.x", "a.y"),
		"unknown kind":   e("owns", "a.x", "a.y"),
		"no source":      {Kind: Act, From: []string{"a.y"}, To: "a.x"},
	}
	for name, bad := range cases {
		if _, err := New(base, []Edge{bad}); err == nil {
			t.Errorf("%s: New accepted %+v", name, bad)
		}
	}
	if _, err := New(append(base, base[0]), nil); err == nil {
		t.Error("New accepted a repeated ID")
	}
	if _, err := New(base, []Edge{e(Brake, "a.x", "b.z"), e(Act, "a.x", "a.y", "a.w")}); err != nil {
		t.Fatalf("well-formed edges refused: %v", err)
	}
}

// TN-graph-b: hand-worked cut sets.
func TestFixtureCutSets(t *testing.T) {
	for _, h := range []struct {
		name string
		ana  bool
		want map[Class][]Cut
	}{{"Ana", true, anaCuts}, {"Ben", false, benCuts()}} {
		g := household(t, h.ana)
		for _, c := range Classes {
			if got := g.CutSets(c); !reflect.DeepEqual(got, h.want[c]) {
				t.Errorf("%s %s cut sets:\n got %v\nwant %v", h.name, c, got, h.want[c])
			}
		}
	}
	// The set new-payee hold bounds the bank's money against the phone, but
	// never its data: a read cannot be delayed.
	g := household(t, true)
	comp := g.compromised(map[string]bool{"phone:ana": true})
	bank := g.index["a.bank"]
	if g.taken(bank, Money, comp) || !g.taken(bank, Data, comp) {
		t.Fatal("phone: the brake must bound the bank's money and not its data")
	}
}

// naiveDomains is the test's own default-domain rule: every node but the
// owner's person node fails, on its own domain if nobody labelled one.
func naiveDomains(x Node) []string {
	if len(x.Domains) == 0 && !(x.Owner && x.Kind == Person) {
		return []string{"self:" + x.ID}
	}
	return x.Domains
}

// naiveDomainSet is the sorted union of naiveDomains over nodes.
func naiveDomainSet(nodes []Node) []string {
	set := map[string]bool{}
	for _, x := range nodes {
		for _, d := range naiveDomains(x) {
			set[d] = true
		}
	}
	return sortedKeys(set)
}

// naiveTaken re-derives a take from the definition, independently of the
// engine: compromise by repeated passes over every edge, then the bound.
func naiveTaken(nodes []Node, edges []Edge, asset string, c Class, d map[string]bool) bool {
	comp := map[string]bool{}
	for _, x := range nodes {
		for _, y := range naiveDomains(x) {
			if d[y] {
				comp[x.ID] = true
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, ed := range edges {
			if ed.Kind != Reset && ed.Kind != Copy && ed.Kind != Act {
				continue
			}
			all := true
			for _, f := range ed.From {
				all = all && comp[f]
			}
			if all && !comp[ed.To] {
				comp[ed.To], changed = true, true
			}
		}
	}
	if !comp[asset] {
		return false
	}
	if c == Data {
		return true
	}
	set := map[string]bool{}
	for _, x := range nodes {
		set[x.ID] = x.Set
	}
	for _, b := range edges {
		if b.Kind != Brake || b.To != asset || !set[b.From[0]] {
			continue
		}
		for _, w := range edges {
			if w.Kind == Watch && (w.To == asset || w.To == b.From[0]) && !comp[w.From[0]] {
				return false
			}
		}
	}
	return true
}

func randomGraph(r *rand.Rand) ([]Node, []Edge) {
	nd := 1 + r.Intn(8)
	nn := 4 + r.Intn(9)
	var nodes []Node
	for i := 0; i < nn; i++ {
		x := Node{ID: "x." + strconv.Itoa(i), Kind: allKinds[r.Intn(len(allKinds))], Name: "N" + strconv.Itoa(i), Source: Shipped}
		x.Owner = x.Kind == Person && r.Intn(2) == 0
		for k := 0; k < r.Intn(3); k++ {
			x.Domains = append(x.Domains, "d:"+strconv.Itoa(r.Intn(nd)))
		}
		if r.Intn(3) == 0 {
			x.Assets = append(x.Assets, Classes[r.Intn(4)])
		}
		if x.Kind == BrakeKind {
			x.Set, x.Owner, x.Assets = r.Intn(2) == 0, false, nil
		}
		nodes = append(nodes, x)
	}
	// A brake is never a control source or a witness; the owner is only a
	// control source alone.
	var srcs, owners []string
	for _, x := range nodes {
		if x.Owner {
			owners = append(owners, x.ID)
		} else if x.Kind != BrakeKind {
			srcs = append(srcs, x.ID)
		}
	}
	var edges []Edge
	for k := 0; k < nn*2 && len(srcs) > 0; k++ {
		to := nodes[r.Intn(nn)].ID
		a, b := srcs[r.Intn(len(srcs))], srcs[r.Intn(len(srcs))]
		switch r.Intn(6) {
		case 0, 1, 2:
			from := []string{a}
			if b != a && r.Intn(3) == 0 {
				from = append(from, b)
			}
			edges = append(edges, Edge{Kind: []EdgeKind{Reset, Copy, Act}[r.Intn(3)], From: from, To: to, Source: Shipped})
		case 3, 4:
			var brakes []string
			for _, x := range nodes {
				if x.Kind == BrakeKind {
					brakes = append(brakes, x.ID)
				}
			}
			if len(brakes) > 0 {
				edges = append(edges, Edge{Kind: Brake, From: []string{brakes[r.Intn(len(brakes))]}, To: to, Source: Shipped})
			}
		case 5:
			edges = append(edges, Edge{Kind: Watch, From: []string{a}, To: to, Source: Shipped})
		}
		if len(owners) > 0 && r.Intn(4) == 0 {
			edges = append(edges, Edge{Kind: Act, From: []string{owners[r.Intn(len(owners))]}, To: to, Source: Shipped})
		}
	}
	return nodes, edges
}

// TN-graph-b: every reported cut, and only those, against exhaustive
// enumeration of every domain set of size 1 and 2.
func TestCutSetsMatchBruteForce(t *testing.T) {
	r := rand.New(rand.NewSource(2857))
	for trial := 0; trial < 300; trial++ {
		nodes, edges := randomGraph(r)
		g, err := New(nodes, edges)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		doms := naiveDomainSet(nodes)
		for _, c := range Classes {
			want := map[string]bool{}
			for _, a := range nodes {
				if !hasClass(a, c) {
					continue
				}
				single := map[string]bool{}
				for _, x := range doms {
					if naiveTaken(nodes, edges, a.ID, c, map[string]bool{x: true}) {
						single[x] = true
						want[a.ID+"|"+x] = true
					}
				}
				for i, x := range doms {
					for _, y := range doms[i+1:] {
						if !single[x] && !single[y] && naiveTaken(nodes, edges, a.ID, c, map[string]bool{x: true, y: true}) {
							want[a.ID+"|"+x+"|"+y] = true
						}
					}
				}
			}
			got := map[string]bool{}
			for _, cut := range g.CutSets(c) {
				got[cut.Asset+"|"+strings.Join(cut.Domains, "|")] = true
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("trial %d %s:\n got %v\nwant %v", trial, c, got, want)
			}
		}
	}
}

// TN-graph-c: hand-worked cut-off sets.
func TestFixtureCutOffs(t *testing.T) {
	g := household(t, true)
	for _, c := range Classes {
		cut, unreached := g.CutOffs(c)
		if !reflect.DeepEqual(cut, anaCutOffs[c]) {
			t.Errorf("%s cut-offs:\n got %v\nwant %v", c, cut, anaCutOffs[c])
		}
		if !reflect.DeepEqual(unreached, anaUnreached[c]) {
			t.Errorf("%s unreached = %v, want %v", c, unreached, anaUnreached[c])
		}
	}
	// Ben's lock hangs on the box alone, which power also cuts; the rest
	// matches Ana.
	b := household(t, false)
	for _, c := range Classes {
		cut, unreached := b.CutOffs(c)
		if !reflect.DeepEqual(cut, benCutOffs[c]) || !reflect.DeepEqual(unreached, anaUnreached[c]) {
			t.Errorf("Ben %s cut-offs = %v, unreached %v", c, cut, unreached)
		}
	}
	if got := b.Board(); !reflect.DeepEqual(got, benBoard) {
		t.Errorf("Ben's board = %v, want %v", got, benBoard)
	}
}

// TN-graph-d: STOP <name> resolution, reach and rotation.
func TestStopReachAndRotation(t *testing.T) {
	g := household(t, true)
	for name, want := range map[string]string{"mailbox": "a.mail", "  MAILBOX ": "a.mail", "A.MAIL": "a.mail", "key 2": "k.two"} {
		if id, ok := g.Resolve(name); !ok || id != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", name, id, ok, want)
		}
	}
	if id, ok := g.Resolve("the moon"); ok || id != "" {
		t.Errorf("an unknown name resolved to %q: the caller must pause everything", id)
	}
	if r, ok := g.Reach("a.nobody"); ok || r != nil {
		t.Errorf("Reach of an unknown ID = %v, %v; want false, not an empty pause", r, ok)
	}
	// The registrar's reset needs the mailbox AND the carrier; a pause of
	// either reaches it.
	if r, _ := g.Reach("a.carrier"); !reflect.DeepEqual(r, []string{"a.carrier", "a.registrar"}) {
		t.Errorf("Reach(carrier) = %v", r)
	}
	if r, _ := g.Reach("a.mail"); !reflect.DeepEqual(r, []string{"a.bank", "a.carrier", "a.mail", "a.registrar", "c.codes"}) {
		t.Errorf("Reach(mail) = %v", r)
	}
	if r, _ := g.Reach("k.one"); !contains(r, "a.registrar") || !contains(r, "a.bank") {
		t.Errorf("Reach(key 1) = %v: the AND edge to the registrar must pause", r)
	}
	rot, ok := g.Rotation("a.mail")
	want := Rotation{Recover: []string{"a.bank", "a.carrier", "a.registrar"}, Copies: []string{"c.codes"}}
	if !ok || !reflect.DeepEqual(rot, want) {
		t.Errorf("Rotation(mail) = %+v, %v; want %+v", rot, ok, want)
	}
	if _, ok := g.Rotation("a.nobody"); ok {
		t.Error("Rotation of an unknown ID succeeded")
	}
	// A Name two nodes share is ambiguous: pause everything.
	h, err := New([]Node{n("a.1", Account, "Mail", nil), n("a.2", Account, "mail", nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Resolve("MAIL"); ok {
		t.Error("an ambiguous name resolved")
	}
	// An internal ID that is another node's Name never wins: the owner
	// cannot see IDs, so a collision pauses everything, never the wrong one.
	s, err := New([]Node{n("bank", Account, "Old card", nil), n("a.x", Account, "Bank", nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := s.Resolve("Bank"); ok {
		t.Errorf("Resolve(Bank) = %q: an ID shadowed the node the owner calls Bank", id)
	}
	if id, ok := s.Resolve("old card"); !ok || id != "bank" {
		t.Errorf("Resolve(old card) = %q, %v", id, ok)
	}
}

// TN-graph-e: a proposal's effect, without changing the graph.
func TestProposalEffectLeavesGraphUnchanged(t *testing.T) {
	g := household(t, true)
	nodes, edges := g.Nodes(), g.Edges()
	before := g.Board()
	if !reflect.DeepEqual(before, anaBoard) {
		t.Fatalf("Ana's board = %v, want %v", before, anaBoard)
	}
	for _, p := range []Proposal{bankReset, carKey, witness, both, cardLimit} {
		eff, err := g.Effect(p)
		if err != nil {
			t.Fatalf("%s: %v", p.Text, err)
		}
		if !reflect.DeepEqual(eff.Before, anaBoard) {
			t.Errorf("%s: Before = %v", p.Text, eff.Before)
		}
		want := map[string]int{bankReset.Text: 1, carKey.Text: 0, witness.Text: 1, both.Text: 2, cardLimit.Text: 0}[p.Text]
		if eff.Gain != want || eff.Weakens {
			t.Errorf("%s: gain %d weakens %v, want %d and false (after %v)", p.Text, eff.Gain, eff.Weakens, want, eff.After)
		}
		// Steps: the bank reset removes money's two single cuts and two of
		// the bank data's; the car key one of the car's; the watcher both of
		// money's.
		wantSteps := map[string]int{bankReset.Text: 4, carKey.Text: 1, witness.Text: 2, both.Text: 4, cardLimit.Text: 0}[p.Text]
		if eff.Steps != wantSteps {
			t.Errorf("%s: steps %d, want %d", p.Text, eff.Steps, wantSteps)
		}
	}
	eff, _ := g.Effect(witness)
	if eff.After[Money].ThiefNeed != 2 {
		t.Errorf("a watcher in another domain must lift money to 2, got %v", eff.After[Money])
	}
	if !reflect.DeepEqual(g.Nodes(), nodes) || !reflect.DeepEqual(g.Edges(), edges) || !reflect.DeepEqual(g.Board(), before) {
		t.Fatal("Effect changed the graph it was applied to")
	}
	if _, err := g.Apply(Proposal{SetBrakes: []string{"a.bank"}}); err == nil {
		t.Error("Apply set a brake on a non-brake")
	}
	if _, err := g.Apply(Proposal{DropEdges: []Edge{e(Act, "d.car", "k.one")}}); err == nil {
		t.Error("Apply dropped an edge that is not there")
	}
	// A drop matches From as a set: {mail, mail} is not {mail, carrier}.
	if _, err := g.Apply(Proposal{DropEdges: []Edge{e(Reset, "a.registrar", "a.mail", "a.mail")}}); err == nil {
		t.Error("Apply dropped the mailbox-and-carrier reset for a repeated-From drop")
	}
	if _, err := g.Apply(Proposal{DropEdges: []Edge{e(Reset, "a.registrar", "a.carrier", "a.mail")}}); err != nil {
		t.Errorf("a drop with From in another order: %v", err)
	}
	// Edges returned to the caller are copies too.
	es := g.Edges()
	es[0].From[0] = "a.bank"
	if g.Edges()[0].From[0] == "a.bank" {
		t.Fatal("Edges shares storage with the graph")
	}
}

// TN-graph-e: the next action is structural first, then gain per minute,
// and never a zero-gain one; a class with no assets is never the weakest.
func TestNextActionStructuralFirst(t *testing.T) {
	g := household(t, true)
	if p, ok := g.Next([]Proposal{witness, both, cardLimit, carKey, bankReset}); !ok || p.Text != bankReset.Text {
		t.Errorf("Next = %q, %v; want the structural %q over higher gain", p.Text, ok, bankReset.Text)
	}
	// With no class gain left among structural ones, a step still counts:
	// the car key removes one of the car's two single cuts (it would stall
	// on the per-class minimum alone) and is structural.
	if p, ok := g.Next([]Proposal{witness, both, cardLimit, carKey}); !ok || p.Text != carKey.Text {
		t.Errorf("Next = %q, %v; want the structural step %q", p.Text, ok, carKey.Text)
	}
	if p, ok := g.Next([]Proposal{both, witness}); !ok || p.Text != witness.Text {
		t.Errorf("Next = %q; want the higher gain per minute %q", p.Text, witness.Text)
	}
	if p, ok := g.Next([]Proposal{cardLimit}); ok {
		t.Errorf("Next chose zero-gain %q", p.Text)
	}
	if p, ok := g.Next([]Proposal{{Text: "bad", SetBrakes: []string{"a.nobody"}}}); ok {
		t.Errorf("Next chose a proposal that does not apply: %q", p.Text)
	}
	if c, ok := g.Weakest(); !ok || c != Money {
		t.Errorf("Ana's weakest = %v, %v; want money (ties broken by cut-offs, then order)", c, ok)
	}

	// A graph whose only asset is data: only data can be weakest.
	d, err := New([]Node{n("a.d", Account, "Notes", nil, Data)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := d.Weakest(); !ok || c != Data {
		t.Errorf("weakest = %v, %v; want data, the only class with assets", c, ok)
	}
	if b := d.Board(); b[Money] != (Score{ThiefNeed: 3}) {
		t.Errorf("empty money scores %v, want ThiefNeed 3, CutOff 0", b[Money])
	}
	// No assets at all: there is no weakest class, and the line says so.
	empty, err := New([]Node{n("p.x", Person, "X", nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := empty.Weakest(); ok {
		t.Errorf("a graph with no assets has weakest %v", c)
	}
	if got := empty.Line(Proposal{}, false); got != "Nothing to protect is recorded yet." {
		t.Errorf("empty Line = %q", got)
	}
}

// TN-graph-f: confidence counts edges by source per class.
func TestConfidenceBySource(t *testing.T) {
	g, err := New([]Node{
		n("p.o", Person, "O", nil), n("k.k", Key, "K", nil), n("a.m", Account, "M", nil),
		n("a.b", Account, "B", nil, Money), n("a.d", Account, "D", nil, Data), n("v.p", Provider, "P", nil),
	}, []Edge{
		{Kind: Act, From: []string{"p.o"}, To: "k.k", Source: Shipped},
		{Kind: Act, From: []string{"k.k"}, To: "a.m", Source: Answer},
		{Kind: Reset, From: []string{"a.m"}, To: "a.b", Source: Observed},
		{Kind: Cutoff, From: []string{"v.p"}, To: "a.b", Source: Answer},
		{Kind: Act, From: []string{"p.o"}, To: "a.d", Source: Answer},
		{Kind: Act, From: []string{"a.b"}, To: "a.d", Source: Shipped}, // into data, not money
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := g.Confidence(Money), (Confidence{Shipped: 1, Answer: 2, Observed: 1}); got != want {
		t.Errorf("money confidence = %+v, want %+v", got, want)
	}
	if got := g.Confidence(Money).AnswerPercent(); got != 50 {
		t.Errorf("money answer share = %d%%, want 50", got)
	}
	// Data's ancestors are the owner and the bank, and through the bank the
	// mailbox, the key and the owner: every edge but the cutoff.
	if got, want := g.Confidence(Data), (Confidence{Shipped: 2, Answer: 3, Observed: 1}); got != want {
		t.Errorf("data confidence = %+v, want %+v", got, want)
	}
	if got := g.Confidence(Safety); got != (Confidence{}) || got.AnswerPercent() != 0 {
		t.Errorf("safety confidence = %+v", got)
	}
}

func gsmOK(s string) bool {
	if len(s) > MaxLine {
		return false
	}
	for _, r := range s {
		if r < ' ' || r > '~' || strings.ContainsRune("`[]{}\\^~|", r) {
			return false
		}
	}
	return true
}

// TN-graph-g: STATUS lines against Ana's.
func TestStatusLines(t *testing.T) {
	g := household(t, true)
	cands := []Proposal{cardLimit, both, witness, carKey, bankReset}
	got := g.Lines(cands)
	want := []string{
		"Bank (money) is lost to one failure shared by Google and Mailbox. Fix: Stop the mailbox from resetting the bank",
		"Bank (money) is lost to one failure shared by Key 1 and Key 2. Fix: Stop the mailbox from resetting the bank",
		"Domain registrar (identity) is lost to one failure of its own maker or provider.",
		"Domain registrar (identity) is lost to one failure shared by Google and Mailbox.",
		"Domain registrar (identity) is lost to one failure shared by Key 1 and Key 2.",
		"Domain registrar (identity) is lost to one failure of Registrar recovery codes.",
		"Car (safety) is lost to one failure of Ana's phone. Fix: Make the car need Key 1 as well as the phone",
		"Car (safety) is lost to one failure of its own maker or provider.",
		"Front door lock (safety) is lost to one failure of its own maker or provider.",
		"Bank: Card limit is off. Turn it on at Bank app, Cards, Limits.",
		"Key 1 and Key 2 fail together, so needing both does not protect Domain registrar. Use two that fail separately.",
		"Losing Google cuts you off from Bank and Mailbox.",
		"Losing Home internet cuts you off from Bank and Mailbox.",
		"Losing Home power cuts you off from Bank, Front door lock and Mailbox.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Lines:\n got %q\nwant %q", got, want)
	}
	next, ok := g.Next(cands)
	line := g.Line(next, ok)
	if line != "Weakest is money: 1 failure can take it. Next: Stop the mailbox from resetting the bank" {
		t.Errorf("Line = %q", line)
	}
	// A one-failure weakness with no fix in hand never reads "nothing needed".
	if got := g.Line(Proposal{}, false); got != "Weakest is money: 1 failure can take it. No fix is known yet." {
		t.Errorf("Line without a next action = %q", got)
	}
	safe := mustNew(t, []Node{
		n("a.b", Account, "Bank", nil, Money), brakeSet("b.h", "Hold"),
		n("n.w1", NodeKind, "Watcher 1", nil), n("n.w2", NodeKind, "Watcher 2", nil),
	}, []Edge{e(Brake, "a.b", "b.h"), e(Watch, "b.h", "n.w1"), e(Watch, "b.h", "n.w2")})
	if got := safe.Line(Proposal{}, false); got != "Weakest is money: it takes more than 2 failures. Nothing needed now." {
		t.Errorf("Line with two independent watchers = %q", got)
	}
	long := g.Line(Proposal{Text: strings.Repeat("Ä{x} ", 60)}, true)
	all := append(append([]string{line, long}, got...), household(t, false).Lines(cands)...)
	for _, s := range all {
		if !gsmOK(s) {
			t.Errorf("not GSM-7 within %d characters: %q", MaxLine, s)
		}
		for _, x := range append(g.Nodes(), witness.AddNodes...) {
			if strings.Contains(s, x.ID) {
				t.Errorf("line names ID %q: %q", x.ID, s)
			}
			for _, d := range x.Domains {
				if strings.Contains(s, d) || strings.Contains(s, d[:strings.Index(d, ":")+1]) {
					t.Errorf("line names domain label %q: %q", d, s)
				}
			}
		}
	}
	// An asset whose labelled domain no other node carries is lost to its
	// own maker or provider, never "to one failure of Bank" (UX delta).
	ownD := mustNew(t, []Node{n("a.b", Account, "Bank", dom("provider:bank"), Money)}, nil)
	if got := ownD.Lines(nil); !reflect.DeepEqual(got, []string{"Bank (money) is lost to one failure of its own maker or provider."}) {
		t.Errorf("own-domain line = %q", got)
	}
	// Ben has no pair of safeguards that fail together.
	for _, s := range household(t, false).Lines(nil) {
		if strings.Contains(s, "fail together") {
			t.Errorf("Ben: %q", s)
		}
	}
}

// TN-graph-h: idle accounts.
func TestIdleAccounts(t *testing.T) {
	g := household(t, true)
	if got := g.Idle(fixtureNow, 0); !reflect.DeepEqual(got, []string{"a.oldmail", "a.blog"}) {
		t.Errorf("Idle(default) = %v; want oldest first, accounts only, unset LastUse skipped", got)
	}
	if got := g.Idle(fixtureNow, 2*DefaultIdle); !reflect.DeepEqual(got, []string{"a.oldmail"}) {
		t.Errorf("Idle(2 years) = %v", got)
	}
}

// TN-graph-h: the STATUS count line.
func TestCountLine(t *testing.T) {
	g := household(t, true)
	if c := g.Count(); c != (Counts{Accounts: 6, Devices: 3}) {
		t.Fatalf("Count = %+v", c)
	}
	for start, want := range map[Counts]string{
		{5, 2}: "6 accounts, 3 devices (+2 this month)",
		{6, 3}: "6 accounts, 3 devices (no change this month)",
		{7, 3}: "6 accounts, 3 devices (-1 this month)",
	} {
		if got := g.CountLine(start); got != want {
			t.Errorf("CountLine(%v) = %q, want %q", start, got, want)
		}
	}
	one, _ := New([]Node{n("a.1", Account, "A", nil), n("d.1", Device, "D", nil)}, nil)
	if got := one.CountLine(Counts{}); got != "1 account, 1 device (+2 this month)" {
		t.Errorf("singular CountLine = %q", got)
	}
}

// TN-graph-h: downtime.
func TestDowntime(t *testing.T) {
	t0 := fixtureNow
	m := func(x int) time.Time { return t0.Add(time.Duration(x) * time.Minute) }
	entries := []time.Time{m(11), m(0), m(1), m(2), m(10)}
	failed := []Span{{m(9), m(12)}, {m(20), m(25)}}
	// Gaps over 3m: 2..10, and 11..15 at the window's end with no later entry.
	// Failure 9..12 overlaps both; 20..25 lies outside. Union: 2..15.
	if got := Downtime(entries, failed, m(0), m(15), 3*time.Minute); got != 13*time.Minute {
		t.Errorf("Downtime = %v, want 13m (overlaps once, outside spans not at all)", got)
	}
	if got := Downtime(nil, nil, m(0), m(15), time.Hour); got != 15*time.Minute {
		t.Errorf("no entries: %v, want the whole window", got)
	}
	// Entries on both sides of the window bound it; a quiet stretch inside
	// it longer than gap counts, clipped.
	if got := Downtime([]time.Time{m(-5), m(30)}, nil, m(0), m(15), 3*time.Minute); got != 15*time.Minute {
		t.Errorf("straddling gap: %v, want 15m", got)
	}
	if got := Downtime([]time.Time{m(-1), m(1), m(3), m(16)}, []Span{{m(-10), m(-2)}}, m(0), m(15), 3*time.Minute); got != 12*time.Minute {
		t.Errorf("busy start: %v, want 12m (3..15)", got)
	}
}

// TN-graph-i: the package imports only the standard library.
func TestImportsOnlyStdlib(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if first := strings.SplitN(p, "/", 2)[0]; strings.Contains(first, ".") || p == "C" {
				t.Errorf("%s imports %q, outside the standard library", f, p)
			}
		}
		checked++
	}
	if checked < 4 {
		t.Fatalf("checked %d files, want graph.go, cut.go, board.go and status.go", checked)
	}
}

var _ = fmt.Sprint

func mustNew(t *testing.T, nodes []Node, edges []Edge) *Graph {
	t.Helper()
	g, err := New(nodes, edges)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func brakeSet(id, name string) Node {
	b := n(id, BrakeKind, name, nil)
	b.Set = true
	return b
}

// allKinds lists every node kind; TestAllKindsListed keeps it equal to the
// engine's own list, so a new kind fails the mutation test until covered.
var allKinds = []Kind{Account, Credential, Provider, Device, Key, Person, NodeKind, Surface, Power, Uplink, BrakeKind}

func TestAllKindsListed(t *testing.T) {
	got := map[Kind]bool{}
	for _, k := range allKinds {
		got[k] = true
	}
	if !reflect.DeepEqual(got, kinds) || len(allKinds) != len(kinds) {
		t.Fatalf("allKinds %v differs from the engine's kinds %v", allKinds, kinds)
	}
}

// TN-graph-a: a node nobody labelled is weak, not safe. Every node fails on
// its own domain, a person or a brake included, except the owner's own
// person node.
func TestUnlabelledNodeIsItsOwnDomain(t *testing.T) {
	own := n("p.me", Person, "Me", nil)
	own.Owner = true
	g := mustNew(t, []Node{own, n("a.b", Account, "Bank", nil, Money), brakeSet("b.h", "Hold"), n("p.sam", Person, "Sam", nil)},
		[]Edge{e(Act, "a.b", "p.me"), e(Brake, "a.b", "b.h")})
	if got := g.CutSets(Money); !reflect.DeepEqual(got, []Cut{{"a.b", dom(SelfDomain("a.b"))}}) {
		t.Errorf("an unlabelled bank: cuts %v; want its own domain", got)
	}
	if got := g.Domains(); !reflect.DeepEqual(got, dom("self:a.b", "self:b.h", "self:p.sam")) {
		t.Errorf("domains = %v; only the owner gets none", got)
	}
	// A recovery contact nobody labelled is one failure away, like any node.
	h := mustNew(t, []Node{own, n("a.b", Account, "Bank", dom("provider:bank"), Money), n("p.sam", Person, "Sam", nil)},
		[]Edge{e(Act, "a.b", "p.me"), e(Reset, "a.b", "p.sam")})
	if got := h.CutSets(Money); !reflect.DeepEqual(got, []Cut{{"a.b", dom("provider:bank")}, {"a.b", dom("self:p.sam")}}) {
		t.Errorf("a recovery contact's reset: cuts %v", got)
	}
}

// TN-graph-a: a brake is a setting, never a credential or a witness; the
// owner is never one member of an AND, nor a witness; and only a person can
// be the owner.
func TestNewRefusesBrakeSourcesAndNonPersonOwner(t *testing.T) {
	own := n("p.me", Person, "Me", nil)
	own.Owner = true
	base := []Node{own, n("a.b", Account, "Bank", nil, Money), brakeSet("b.h", "Hold"), n("k.k", Key, "Key", nil)}
	for _, ed := range []Edge{
		e(Reset, "a.b", "b.h"), e(Copy, "a.b", "b.h"), e(Act, "a.b", "b.h"),
		e(Reset, "a.b", "k.k", "b.h"), e(Watch, "a.b", "b.h"), e(Cutoff, "a.b", "b.h"),
		e(Reset, "a.b", "k.k", "p.me"), e(Act, "a.b", "p.me", "k.k"), e(Watch, "a.b", "p.me"), e(Watch, "b.h", "p.me"),
	} {
		if _, err := New(base, []Edge{ed}); err == nil {
			t.Errorf("accepted %s edge using a brake or the owner: %+v", ed.Kind, ed)
		}
	}
	// A brake may still be braked from, watched and changed, and the owner
	// may still act alone.
	mustNew(t, base, []Edge{e(Brake, "a.b", "b.h"), e(Watch, "b.h", "k.k"), e(Act, "b.h", "k.k"), e(Act, "a.b", "p.me")})
	for _, k := range allKinds {
		if k == Person {
			continue
		}
		x := n("x.o", k, "Thing", nil)
		x.Owner = true
		if _, err := New([]Node{x}, nil); err == nil {
			t.Errorf("accepted a %s as the owner", k)
		}
	}
}

// TN-graph-e: Next and the STATUS fixes refuse a proposal that gives any
// asset a new thief cut or a new cut-off provider, whatever its class gain
// (KRN-11). Security's probe on #3193.
func TestProposalNeverWeakensAnAsset(t *testing.T) {
	own := n("p", Person, "Me", nil)
	own.Owner = true
	g := mustNew(t, []Node{own,
		n("k1", Key, "Key A", dom("maker:a")), n("k2", Key, "Key B", dom("maker:b")),
		n("ph", Device, "Phone", dom("phone")),
		n("bank", Account, "Bank", dom("provider:bank"), Money),
		n("reg", Account, "Registrar", dom("provider:reg"), Identity),
		n("v.isp", Provider, "Internet", dom("provider:isp")),
	}, []Edge{
		e(Act, "k1", "p"), e(Act, "k2", "p"), e(Act, "ph", "p"),
		e(Reset, "bank", "k1", "k2"),
		e(Reset, "reg", "ph"),
	})
	// The phone moves from the registrar to the bank: the registrar gets
	// stronger, the bank gains a single cut through the phone.
	trade := Proposal{Text: "Move phone recovery to the bank", Minutes: 1,
		DropEdges: []Edge{e(Reset, "reg", "ph")},
		AddEdges:  []Edge{e(Reset, "reg", "k1", "k2", "ph"), e(Reset, "bank", "ph")}}
	eff, err := g.Effect(trade)
	if err != nil {
		t.Fatal(err)
	}
	if !eff.Weakens {
		t.Fatalf("a new single cut on the bank not flagged: %+v", eff)
	}
	if p, ok := g.Next([]Proposal{trade}); ok {
		t.Errorf("Next recommends %q, which opens a single thief path on money", p.Text)
	}
	for _, s := range g.Lines([]Proposal{trade}) {
		if strings.Contains(s, "Fix:") {
			t.Errorf("Lines offers a weakening fix: %q", s)
		}
	}
	// A trade with positive steps is still refused: it removes the
	// registrar's two single cuts through the phone and the tablet but
	// opens one on the bank.
	two := mustNew(t, []Node{own,
		n("ph", Device, "Phone", dom("phone")), n("tb", Device, "Tablet", dom("tablet")),
		n("bank", Account, "Bank", dom("provider:bank"), Money),
		n("reg", Account, "Registrar", dom("provider:reg"), Identity),
	}, []Edge{e(Act, "ph", "p"), e(Act, "tb", "p"), e(Reset, "reg", "ph"), e(Reset, "reg", "tb"),
		e(Act, "reg", "ph", "tb")}) // the owner still signs in with both after the swap
	swap := Proposal{Text: "Move device recovery to the bank", Minutes: 1, Structural: true,
		DropEdges: []Edge{e(Reset, "reg", "ph"), e(Reset, "reg", "tb")},
		AddEdges:  []Edge{e(Reset, "bank", "ph")}}
	if eff, _ := two.Effect(swap); eff.Steps <= 0 || !eff.Weakens {
		t.Fatalf("swap: steps %d weakens %v; want a positive step that weakens", eff.Steps, eff.Weakens)
	}
	if p, ok := two.Next([]Proposal{swap}); ok {
		t.Errorf("Next recommends %q, which opens a single thief path on the bank", p.Text)
	}
	// Locking the owner out is a regression, not progress: dropping the
	// only path to the bank removes its thief cuts and its cut-off, yet the
	// owner can no longer reach it (L3 and Security deltas on #3193).
	locked := mustNew(t, []Node{own,
		n("k1", Key, "Key A", dom("maker:a")),
		n("mail", Account, "Mailbox", dom("google")),
		n("bank", Account, "Bank", dom("provider:bank"), Money),
		n("cloud", Provider, "Cloud", dom("provider:cloud")),
	}, []Edge{e(Act, "k1", "p"), e(Reset, "mail", "k1"), e(Reset, "bank", "mail"), e(Cutoff, "bank", "cloud")})
	lockout := Proposal{Text: "Remove the bank's mail recovery", Minutes: 1, Structural: true,
		DropEdges: []Edge{e(Reset, "bank", "mail")}}
	if eff, _ := locked.Effect(lockout); !eff.Weakens || eff.Steps > 0 {
		t.Errorf("lock-out: weakens %v steps %d; want true and no progress", eff.Weakens, eff.Steps)
	}
	if p, ok := locked.Next([]Proposal{lockout}); ok {
		t.Errorf("Next recommends %q, which locks the owner out of the bank", p.Text)
	}
	for _, s := range locked.Lines([]Proposal{lockout}) {
		if strings.Contains(s, "Fix:") {
			t.Errorf("Lines offers a lock-out as a fix: %q", s)
		}
	}
	// Replacing a one-device sign-in with two independent keys raises the
	// bank from 1 failure to 2: the new pair is no regression (Potency and
	// Security deltas). A new pair where nothing under three failures took
	// the asset before still is.
	world := mustNew(t, []Node{own,
		n("ph", Device, "Phone", dom("phone")),
		n("k1", Key, "Key A", dom("maker:a")), n("k2", Key, "Key B", dom("maker:b")),
		n("bank", Account, "Bank", dom("provider:bank"), Money),
		n("vault", Account, "Vault", dom("provider:vault"), Money), brakeSet("b.v", "Vault hold"),
		n("w1", NodeKind, "Watcher 1", dom("w1")), n("w2", NodeKind, "Watcher 2", dom("w2")),
	}, []Edge{e(Act, "ph", "p"), e(Act, "k1", "p"), e(Act, "k2", "p"), e(Act, "bank", "ph"),
		e(Brake, "vault", "b.v"), e(Watch, "b.v", "w1"), e(Watch, "b.v", "w2")})
	keys := Proposal{Text: "Make bank sign-in need both keys", Minutes: 5, Structural: true,
		DropEdges: []Edge{e(Act, "bank", "ph")}, AddEdges: []Edge{e(Act, "bank", "k1", "k2")}}
	if eff, _ := world.Effect(keys); eff.Weakens {
		t.Errorf("phone to both keys flagged as weakening: %+v", eff)
	}
	if p, ok := world.Next([]Proposal{keys}); !ok || p.Text != keys.Text {
		t.Errorf("Next = %q, %v; want %q", p.Text, ok, keys.Text)
	}
	unwatch := Proposal{Text: "Stop the second watcher", Minutes: 1,
		DropEdges: []Edge{e(Watch, "b.v", "w2")}}
	if eff, _ := world.Effect(unwatch); !eff.Weakens {
		t.Error("a vault no pair could take before now falls to a pair: must weaken")
	}
	// Every asset of the after state is judged, new ones included, against
	// the floor of its own maker or provider (round 2 on #3193).
	newSingle := Proposal{Text: "Add a broker app on the phone", Minutes: 1,
		AddNodes: []Node{n("brk", Account, "Broker", dom("phone"), Money)},
		AddEdges: []Edge{e(Act, "brk", "ph")}}
	if eff, _ := world.Effect(newSingle); !eff.Weakens {
		t.Error("a new money account the phone alone takes is not flagged")
	}
	newCut := Proposal{Text: "Add a cloud wallet", Minutes: 1,
		AddNodes: []Node{n("wal", Account, "Wallet", dom("provider:wal"), Money), n("v.c", Provider, "Cloud", dom("provider:cloud"))},
		AddEdges: []Edge{e(Act, "wal", "k1", "k2"), e(Cutoff, "wal", "v.c")}}
	if eff, _ := world.Effect(newCut); !eff.Weakens {
		t.Error("a new asset the owner can be cut off from is not flagged")
	}
	ownOnly := Proposal{Text: "Add a savings account on both keys", Minutes: 1,
		AddNodes: []Node{n("sav", Account, "Savings", dom("provider:sav"), Money)},
		AddEdges: []Edge{e(Act, "sav", "k1", "k2")}}
	if eff, _ := world.Effect(ownOnly); eff.Weakens {
		t.Error("a new account only its own provider can take is flagged")
	}
	// A second pair beside an existing pair is at the old smallest cut.
	pairWorld := mustNew(t, []Node{own,
		n("ph", Device, "Phone", dom("phone")), n("k1", Key, "Key A", dom("maker:a")), n("k2", Key, "Key B", dom("maker:b")),
		n("mail", Account, "Mailbox", dom("provider:mail")), brakeSet("hold", "Hold"),
		n("bank", Account, "Bank", dom("provider:bank"), Money),
	}, []Edge{e(Act, "ph", "p"), e(Act, "k1", "p"), e(Act, "k2", "p"), e(Act, "mail", "k2"), e(Act, "bank", "k1"),
		e(Brake, "bank", "hold"), e(Watch, "bank", "mail")})
	pairBeside := Proposal{Text: "Use the bank app on the phone", Minutes: 1, AddEdges: []Edge{e(Act, "bank", "ph")}}
	if eff, _ := pairWorld.Effect(pairBeside); !eff.Weakens {
		t.Errorf("a second pair beside a pair is not flagged: %v", pairWorld.CutSets(Money))
	}
	// A class may not fall even through an asset that clears its floor:
	// money at 2 plus a new account its own provider takes is gain -1.
	// It also drops the registrar's two device resets, so it has steps.
	savings := mustNew(t, []Node{own, n("w", NodeKind, "Watcher", dom("w")), brakeSet("hold", "Hold"),
		n("vault", Account, "Vault", dom("provider:vault"), Money),
		n("ph", Device, "Phone", dom("phone")), n("tb", Device, "Tablet", dom("tablet")),
		n("reg", Account, "Registrar", dom("provider:reg"), Identity)},
		[]Edge{e(Act, "vault", "p"), e(Brake, "vault", "hold"), e(Watch, "vault", "w"),
			e(Act, "ph", "p"), e(Act, "tb", "p"), e(Act, "reg", "p"), e(Reset, "reg", "ph"), e(Reset, "reg", "tb")})
	connect := Proposal{Text: "Connect savings and drop device resets", Minutes: 1, Structural: true,
		AddNodes:  []Node{n("sav", Account, "Savings", dom("provider:sav"), Money)},
		AddEdges:  []Edge{e(Act, "sav", "p")},
		DropEdges: []Edge{e(Reset, "reg", "ph"), e(Reset, "reg", "tb")}}
	if eff, _ := savings.Effect(connect); eff.Weakens || eff.Gain >= 0 || eff.Steps <= 0 {
		t.Errorf("connect: weakens %v gain %d steps %d; want unflagged, gain below 0, steps above 0", eff.Weakens, eff.Gain, eff.Steps)
	}
	if eff, _ := savings.Effect(connect); !eff.Lowers() {
		t.Error("money from 2 to 1 not read as lowering a class")
	}
	if p, ok := savings.Next([]Proposal{connect}); ok {
		t.Errorf("Next recommends %q, which takes money from 2 failures to 1", p.Text)
	}
	// A proposal never changes who the owner is.
	ghost := n("p2", Person, "Me again", nil)
	ghost.Owner = true
	if _, err := world.Apply(Proposal{AddNodes: []Node{ghost}}); err == nil {
		t.Error("Apply added a second owner, which could mask a lock-out")
	}
	if p, ok := world.Next([]Proposal{{Text: "ghost", Structural: true, AddNodes: []Node{ghost}, DropEdges: []Edge{e(Act, "bank", "ph")}}}); ok {
		t.Errorf("Next recommends %q", p.Text)
	}
	// A second asset of a class already at 1 is still guarded: the class
	// minimum does not move, but the bank gains a single cut.
	second := Proposal{Text: "Let the phone reset the bank", Minutes: 1, AddEdges: []Edge{e(Reset, "bank", "ph")}}
	if eff, _ := g.Effect(second); !eff.Weakens {
		t.Error("a new single cut is missed when the class minimum does not change")
	}
	// A new cut-off provider weakens too, with no thief cut involved.
	cut := Proposal{Text: "Route the bank through the internet", Minutes: 1, AddEdges: []Edge{e(Cutoff, "bank", "v.isp")}}
	if eff, _ := g.Effect(cut); !eff.Weakens {
		t.Error("a new cut-off provider is missed")
	}
	// The original probe's figures: the trade lifts identity more than it
	// drops money, which the summed gain alone would have recommended.
	probe := mustNew(t, []Node{own,
		n("k1", Key, "Key A", dom("maker:a")), n("k2", Key, "Key B", dom("maker:b")),
		n("ph", Device, "Phone", dom("phone")),
		n("bank", Account, "Bank", dom("provider:bank"), Money),
		n("reg", Account, "Registrar", nil, Identity),
	}, []Edge{e(Act, "k1", "p"), e(Act, "k2", "p"), e(Act, "ph", "p"), e(Reset, "bank", "k1", "k2"), e(Reset, "reg", "ph")})
	if p, ok := probe.Next([]Proposal{trade}); ok {
		t.Errorf("probe: Next recommends %q", p.Text)
	}
}

// naiveCuts lists an asset's minimal cuts of size 1 and 2 by brute force.
func naiveCuts(nodes []Node, edges []Edge, asset string, c Class, doms []string) [][]string {
	var out [][]string
	single := map[string]bool{}
	for _, x := range doms {
		if naiveTaken(nodes, edges, asset, c, map[string]bool{x: true}) {
			single[x] = true
			out = append(out, []string{x})
		}
	}
	for i, x := range doms {
		for _, y := range doms[i+1:] {
			if !single[x] && !single[y] && naiveTaken(nodes, edges, asset, c, map[string]bool{x: true, y: true}) {
				out = append(out, []string{x, y})
			}
		}
	}
	return out
}

// naiveWeakens restates the invariant of TN-graph-A16 from scratch: cuts by
// brute force, reach and cut-off providers from CutOffs.
func naiveWeakens(g, h *Graph) bool {
	gn, ge, hn, he := g.Nodes(), g.Edges(), h.Nodes(), h.Edges()
	gd, hd := naiveDomainSet(gn), naiveDomainSet(hn)
	offs := func(x *Graph, c Class) (map[string]map[string]bool, map[string]bool) {
		cut, un := x.CutOffs(c)
		m := map[string]map[string]bool{}
		for _, o := range cut {
			m[o.Asset] = map[string]bool{}
			for _, p := range o.Providers {
				m[o.Asset][p] = true
			}
		}
		u := map[string]bool{}
		for _, a := range un {
			u[a] = true
		}
		return m, u
	}
	for _, c := range Classes {
		gOff, gUn := offs(g, c)
		hOff, hUn := offs(h, c)
		for _, a := range hn {
			if !hasClass(a, c) {
				continue
			}
			var before [][]string
			min := 1
			old, existed := g.Node(a.ID)
			if existed && hasClass(old, c) {
				if !gUn[a.ID] && hUn[a.ID] {
					return true
				}
				for p := range hOff[a.ID] {
					if !gOff[a.ID][p] {
						return true
					}
				}
				before = naiveCuts(gn, ge, a.ID, c, gd)
				min = 3
				for _, cut := range before {
					if len(cut) < min {
						min = len(cut)
					}
				}
			} else {
				if len(hOff[a.ID]) > 0 {
					return true
				}
				for _, d := range naiveDomains(a) {
					only := true
					for _, o := range hn {
						if o.ID != a.ID && contains(naiveDomains(o), d) {
							only = false
						}
					}
					if only {
						before = append(before, []string{d})
					}
				}
			}
			for _, cut := range naiveCuts(hn, he, a.ID, c, hd) {
				if len(cut) <= min && !hasCut(before, cut) {
					return true
				}
			}
		}
	}
	return false
}

// TN-graph-e: Effect.Weakens matches the invariant, restated from scratch,
// over every one-step mutation of Ana's household: each edge dropped, new
// single and AND edges onto each asset, a new cut-off onto each asset, the
// card limit set, a new money account under each kind of label, and a new
// node of every kind in every role (TN-graph-A15).
func TestWeakensInvariantOverFixtureMutations(t *testing.T) {
	g := household(t, true)
	var ps []Proposal
	for _, ed := range g.Edges() {
		ps = append(ps, Proposal{Text: "drop", DropEdges: []Edge{ed}})
	}
	var assets []string
	for _, x := range g.Nodes() {
		if len(x.Assets) > 0 {
			assets = append(assets, x.ID)
		}
	}
	for _, a := range assets {
		for _, src := range []string{"k.one", "d.phone", "a.mail", "a.carrier", "n.core"} {
			ps = append(ps, Proposal{Text: "add", AddEdges: []Edge{e(Act, a, src)}})
		}
		for _, and := range [][]string{{"k.one", "k.two"}, {"d.phone", "k.one"}, {"a.mail", "a.carrier"}} {
			ps = append(ps, Proposal{Text: "and", AddEdges: []Edge{e(Act, a, and...)}})
		}
		ps = append(ps, Proposal{Text: "cutoff", AddEdges: []Edge{e(Cutoff, a, "v.google")}})
	}
	ps = append(ps, cardLimit, witness, both, carKey, bankReset)
	for _, d := range [][]string{nil, dom("phone:ana"), dom("maker:yubico"), dom("provider:new")} {
		for _, from := range [][]string{{"k.one"}, {"k.one", "k.two"}, {"d.phone", "k.one"}} {
			ps = append(ps, Proposal{Text: "new account",
				AddNodes: []Node{n("a.new", Account, "New account", d, Money)},
				AddEdges: []Edge{e(Act, "a.new", from...)}})
		}
	}
	// Every node kind, labelled and not: a new node as a control source onto
	// each asset, as one member of an AND gate on each control edge, as a
	// witness, and as a cut-off provider. A brake may only brake: as any
	// other source it is refused. Nobody, of any kind, may join as owner.
	var refused []Proposal
	for _, kind := range allKinds {
		for _, d := range [][]string{nil, dom("provider:x"), dom("phone:ana")} {
			x := n("x.new", kind, "New thing", d)
			add := func(edges ...Edge) Proposal {
				return Proposal{Text: string(kind), AddNodes: []Node{x}, AddEdges: edges}
			}
			var srcs []Proposal
			for _, a := range assets {
				srcs = append(srcs, add(e(Act, a, "x.new")), add(e(Reset, a, "x.new")))
			}
			for _, ed := range g.Edges() {
				if control(ed.Kind) {
					gate := add(Edge{Kind: ed.Kind, From: append(ed.From, "x.new"), To: ed.To, Source: ed.Source})
					gate.DropEdges = []Edge{ed}
					if contains(ed.From, "p.owner") {
						refused = append(refused, gate) // the owner in an AND
					} else {
						srcs = append(srcs, gate)
					}
				}
			}
			srcs = append(srcs, add(e(Watch, "b.payee", "x.new")), add(e(Watch, "a.bank", "x.new")), add(e(Cutoff, "a.registrar", "x.new")))
			if kind == BrakeKind {
				refused = append(refused, srcs...)
				for _, a := range assets {
					ps = append(ps, add(e(Brake, a, "x.new"), e(Watch, "x.new", "k.one")))
				}
			} else {
				ps = append(ps, srcs...)
			}
			owner := add(e(Act, "a.mail", "x.new"))
			owner.AddNodes = []Node{x}
			owner.AddNodes[0].Owner = true
			refused = append(refused, owner)
		}
	}
	// The owner as one member of an AND gate, or as a witness.
	for _, ed := range g.Edges() {
		if control(ed.Kind) && !contains(ed.From, "p.owner") {
			gate := Proposal{Text: "owner gate", DropEdges: []Edge{ed},
				AddEdges: []Edge{{Kind: ed.Kind, From: append(ed.From, "p.owner"), To: ed.To, Source: ed.Source}}}
			refused = append(refused, gate)
		}
	}
	refused = append(refused, Proposal{Text: "owner witness", AddEdges: []Edge{e(Watch, "b.payee", "p.owner")}})
	for _, p := range refused {
		if _, err := g.Apply(p); err == nil {
			t.Errorf("applied %s: %+v", p.Text, p.AddEdges)
		}
		if _, ok := g.Next([]Proposal{p}); ok {
			t.Errorf("Next offered a refused %s proposal", p.Text)
		}
	}
	weak, fine := 0, 0
	for i, p := range ps {
		h, err := g.Apply(p)
		if err != nil {
			t.Fatalf("mutation %d: %v", i, err)
		}
		eff, err := g.Effect(p)
		if err != nil {
			t.Fatal(err)
		}
		if want := naiveWeakens(g, h); eff.Weakens != want {
			t.Errorf("mutation %d %+v: Weakens %v, invariant says %v", i, p, eff.Weakens, want)
		}
		// The engine's cuts are the brute force's, under its own default rule.
		hd := naiveDomainSet(h.Nodes())
		for _, c := range Classes {
			want := map[string]bool{}
			for _, x := range h.Nodes() {
				if hasClass(x, c) {
					for _, cut := range naiveCuts(h.Nodes(), h.Edges(), x.ID, c, hd) {
						want[x.ID+"|"+strings.Join(cut, "|")] = true
					}
				}
			}
			got := map[string]bool{}
			for _, cut := range h.CutSets(c) {
				got[cut.Asset+"|"+strings.Join(cut.Domains, "|")] = true
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("mutation %d %s %s: cuts %v, brute force %v", i, p.Text, c, got, want)
			}
		}
		if eff.Weakens {
			weak++
			continue
		}
		fine++
		// What passes never locks the owner out of an asset.
		for _, c := range Classes {
			_, ub := g.CutOffs(c)
			_, ua := h.CutOffs(c)
			for _, x := range ua {
				if x != "a.new" && !contains(ub, x) {
					t.Errorf("mutation %d passed but locks the owner out of %s", i, x)
				}
			}
		}
		// What passes never shrinks an existing asset's smallest cut.
		for _, c := range Classes {
			for _, a := range assets {
				x, _ := g.Node(a)
				if hasClass(x, c) && smallestNaive(h, a, c) < smallestNaive(g, a, c) {
					t.Errorf("mutation %d passed but shrank %s's %s cut", i, a, c)
				}
			}
		}
	}
	if weak == 0 || fine == 0 {
		t.Fatalf("mutations not discriminating: %d weaken, %d pass", weak, fine)
	}
}

func smallestNaive(g *Graph, asset string, c Class) int {
	min := 3
	for _, cut := range naiveCuts(g.Nodes(), g.Edges(), asset, c, naiveDomainSet(g.Nodes())) {
		if len(cut) < min {
			min = len(cut)
		}
	}
	return min
}
