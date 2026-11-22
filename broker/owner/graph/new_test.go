package graph

import "testing"

// New refuses a node with no ID, an unknown kind, an unknown source or an
// unknown asset class, each alone in an otherwise good graph.
func TestNewRefusesMalformedNodes(t *testing.T) {
	good := n("a.mail", Account, "Mailbox", dom("provider:mail"), Data)
	for name, bad := range map[string]func(*Node){
		"empty ID":       func(x *Node) { x.ID = "" },
		"unknown kind":   func(x *Node) { x.Kind = "planet" },
		"unknown source": func(x *Node) { x.Source = "rumour" },
		"unknown class":  func(x *Node) { x.Assets = []Class{Data, "gold"} },
	} {
		x := n("a.bank", Account, "Bank", dom("provider:bank"), Money)
		bad(&x)
		if g, err := New([]Node{good, x}, nil); err == nil {
			t.Errorf("%s: New built %+v", name, g.nodes)
		}
	}
}

// New copies what it keeps: a caller editing its slices afterwards leaves
// the graph as built.
func TestNewCopiesTheCallersSlices(t *testing.T) {
	doms, assets, from := dom("provider:mail"), []Class{Data}, []string{"a.mail"}
	g, err := New([]Node{n("a.mail", Account, "Mailbox", doms, assets...), n("a.bank", Account, "Bank", nil)},
		[]Edge{e(Reset, "a.bank", from...)})
	if err != nil {
		t.Fatal(err)
	}
	doms[0], from[0] = "provider:other", "a.bank"
	if got := g.nodes[0]; got.Domains[0] != "provider:mail" {
		t.Errorf("domains %v follow the caller's edit", got.Domains)
	}
	if got := g.edges[0].From[0]; got != "a.mail" {
		t.Errorf("edge From %q follows the caller's edit", got)
	}
	nodes := []Node{n("a.mail", Account, "Mailbox", nil, Data)}
	g, err = New(nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	nodes[0].Assets[0] = Money
	if got := g.nodes[0].Assets[0]; got != Data {
		t.Errorf("assets %v follow the caller's edit", g.nodes[0].Assets)
	}
}
