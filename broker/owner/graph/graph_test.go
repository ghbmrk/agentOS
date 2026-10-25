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
		"self:a.bank", "self:a.blog", "self:a.registrar", "self:c.codes", "self:d.car", "self:d.lock", "self:v.power", "self:v.uplink")) {
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

// naiveTaken re-derives a take from the definition, independently of the
// engine: compromise by repeated passes over every edge, then the bound.
func naiveTaken(nodes []Node, edges []Edge, asset string, c Class, d map[string]bool) bool {
	comp := map[string]bool{}
	for _, x := range nodes {
		ds := x.Domains
		if len(ds) == 0 && x.Kind != Person && x.Kind != BrakeKind {
			ds = []string{"self:" + x.ID} // missing data is weak
		}
		for _, y := range ds {
			if d[y] {
				comp[x.ID] = true
			}
		}
	}
	for i := 0; i <= len(nodes); i++ {
		for _, ed := range edges {
			if ed.Kind != Reset && ed.Kind != Copy && ed.Kind != Act {
				continue
			}
			all := true
			for _, f := range ed.From {
				all = all && comp[f]
			}
			if all {
				comp[ed.To] = true
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
		x := Node{ID: "x." + strconv.Itoa(i), Kind: Account, Name: "N" + strconv.Itoa(i), Source: Shipped}
		for k := 0; k < r.Intn(3); k++ {
			x.Domains = append(x.Domains, "d:"+strconv.Itoa(r.Intn(nd)))
		}
		if r.Intn(3) == 0 {
			x.Assets = append(x.Assets, Classes[r.Intn(4)])
		}
		if r.Intn(5) == 0 {
			x.Kind, x.Set, x.Domains, x.Assets = BrakeKind, r.Intn(2) == 0, nil, nil
		}
		nodes = append(nodes, x)
	}
	var edges []Edge
	for k := 0; k < nn*2; k++ {
		to := nodes[r.Intn(nn)].ID
		a, b := nodes[r.Intn(nn)].ID, nodes[r.Intn(nn)].ID
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
		doms := g.Domains()
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

// TN-graph-a: a node nobody labelled is weak, not safe. It fails on its own
// domain; person and brake nodes get none.
func TestUnlabelledNodeIsItsOwnDomain(t *testing.T) {
	own := n("p.me", Person, "Me", nil)
	own.Owner = true
	g := mustNew(t, []Node{own, n("a.b", Account, "Bank", nil, Money), brakeSet("b.h", "Hold")},
		[]Edge{e(Act, "a.b", "p.me"), e(Brake, "a.b", "b.h")})
	if got := g.CutSets(Money); !reflect.DeepEqual(got, []Cut{{"a.b", dom(SelfDomain("a.b"))}}) {
		t.Errorf("an unlabelled bank: cuts %v; want its own domain", got)
	}
	if got := g.Domains(); !reflect.DeepEqual(got, dom("self:a.b")) {
		t.Errorf("domains = %v; person and brake nodes get none", got)
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
	}, []Edge{e(Act, "ph", "p"), e(Act, "tb", "p"), e(Reset, "reg", "ph"), e(Reset, "reg", "tb")})
	swap := Proposal{Text: "Move device recovery to the bank", Minutes: 1, Structural: true,
		DropEdges: []Edge{e(Reset, "reg", "ph"), e(Reset, "reg", "tb")},
		AddEdges:  []Edge{e(Reset, "bank", "ph")}}
	if eff, _ := two.Effect(swap); eff.Steps <= 0 || !eff.Weakens {
		t.Fatalf("swap: steps %d weakens %v; want a positive step that weakens", eff.Steps, eff.Weakens)
	}
	if p, ok := two.Next([]Proposal{swap}); ok {
		t.Errorf("Next recommends %q, which opens a single thief path on the bank", p.Text)
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
