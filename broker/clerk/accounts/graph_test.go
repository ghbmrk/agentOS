package accounts

import (
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/graph"
)

// REQ: TN-account-plan-7

// handoff is the household table's plan for mail from the bank and the IMAP
// mailbox, a thermostat, and the card connected, handed to the graph.
func handoff(t *testing.T) ([]Item, []graph.Node, []graph.Edge) {
	t.Helper()
	tab := household(t)
	plan := Build(tab, []string{"alerts.bank.test", "imapmail.test"}, []string{"thermostat"})
	nodes, edges := Facts(tab, plan, []string{CardID}, []Device{{ID: "d.thermo", Kind: "thermostat"}})
	return plan, nodes, edges
}

func node(ns []graph.Node, id string) (graph.Node, bool) {
	i := slices.IndexFunc(ns, func(n graph.Node) bool { return n.ID == id })
	if i < 0 {
		return graph.Node{}, false
	}
	return ns[i], true
}

// Every account the plan shows reaches the graph with its provider, each
// fact with its source: found in mail or connected is observed, the table's
// device implication and every table fact are shipped. Offers not taken up
// (the wallet, the mailbox) are no account (TN-account-plan-7).
func TestGraphHandOffSources(t *testing.T) {
	tab := household(t)
	plan, nodes, edges := handoff(t)
	want := map[string]graph.Source{
		CardID: graph.Observed, "bank": graph.Observed, "mail-imap": graph.Observed,
		"power": graph.Shipped, "airline": graph.Shipped,
	}
	for _, it := range plan {
		a, aok := node(nodes, AccountNode(it.ID))
		p, pok := node(nodes, ProviderNode(it.ID))
		src, listed := want[it.ID]
		if !listed {
			if aok || pok {
				t.Errorf("%s: an offer not connected reached the graph", it.ID)
			}
			continue
		}
		if !aok || !pok {
			t.Fatalf("%s: account %v, provider %v", it.ID, aok, pok)
		}
		e, _ := tab.Entry(it.ID)
		if a.Kind != graph.Account || a.Source != src || a.Name != e.Name {
			t.Errorf("%s account = %+v, want source %s", it.ID, a, src)
		}
		if p.Kind != graph.Provider || p.Source != graph.Shipped || p.Name != e.Name+ProviderSuffix {
			t.Errorf("%s provider = %+v", it.ID, p)
		}
		for _, k := range []graph.EdgeKind{graph.Act, graph.Cutoff} {
			if !slices.ContainsFunc(edges, func(x graph.Edge) bool {
				return x.Kind == k && slices.Equal(x.From, []string{p.ID}) && x.To == a.ID
			}) {
				t.Errorf("%s: no %s edge from its provider", it.ID, k)
			}
		}
		delete(want, it.ID)
	}
	if len(want) != 0 {
		t.Fatalf("not handed off: %v", want)
	}
	if n, _ := node(nodes, AccountNode("bank")); !slices.Equal(n.Assets, []graph.Class{graph.Money}) {
		t.Errorf("bank assets %v", n.Assets)
	}
	if n, _ := node(nodes, AccountNode("mail-imap")); !slices.Equal(n.Assets, []graph.Class{graph.Data}) {
		t.Errorf("mailbox assets %v", n.Assets)
	}
	if n, _ := node(nodes, AccountNode("power")); n.Assets != nil {
		t.Errorf("a utility declared assets %v", n.Assets)
	}
	var dev []string
	for _, e := range edges {
		if e.Source != graph.Shipped {
			t.Errorf("edge %+v is not the table's", e)
		}
		if e.To == "d.thermo" {
			if e.Kind != graph.Cutoff {
				t.Errorf("device edge %+v", e)
			}
			dev = append(dev, e.From...)
		}
	}
	if !slices.Equal(dev, []string{AccountNode("power"), AccountNode("airline")}) {
		t.Errorf("device edges from %v", dev)
	}
	// Connecting an item found through a device makes it observed.
	nodes, _ = Facts(tab, plan, []string{"power"}, nil)
	if n, _ := node(nodes, AccountNode("power")); n.Source != graph.Observed {
		t.Errorf("connected power source %s", n.Source)
	}
	if _, ok := node(nodes, AccountNode(CardID)); ok {
		t.Error("the card reached the graph unconnected")
	}
}

// The table answers no failure domain, recovery path, page or last use, so
// the hand-off sets none and #2857's engine reads each at its weakest: the
// account falls to its own failure or its provider's, the owner does not
// reach it, and it is never idle. A device the owner reaches is cut off
// through the account the table implies (TN-account-plan-7).
func TestGraphHandOffUnansweredIsUnverified(t *testing.T) {
	_, facts, factEdges := handoff(t)
	for _, n := range facts {
		if n.Domains != nil || n.Page != "" || !n.LastUse.IsZero() || n.Set || n.Owner {
			t.Errorf("%s answers a field the table does not: %+v", n.ID, n)
		}
	}
	owner := graph.Node{ID: "p.owner", Kind: graph.Person, Name: "Ana", Owner: true, Source: graph.Shipped}
	key := graph.Node{ID: "k.one", Kind: graph.Key, Name: "Key 1", Domains: []string{"maker:k"}, Source: graph.Shipped}
	thermo := graph.Node{ID: "d.thermo", Kind: graph.Device, Name: "Thermostat", Assets: []graph.Class{graph.Safety}, Source: graph.Answer}
	g, err := graph.New(append([]graph.Node{owner, key, thermo}, facts...), append([]graph.Edge{
		{Kind: graph.Act, From: []string{"p.owner"}, To: "k.one", Source: graph.Shipped},
		{Kind: graph.Act, From: []string{"k.one"}, To: "d.thermo", Source: graph.Answer},
	}, factEdges...))
	if err != nil {
		t.Fatal(err)
	}
	bank, bankProv := AccountNode("bank"), ProviderNode("bank")
	var singles []string
	for _, c := range g.CutSets(graph.Money) {
		if c.Asset == bank && len(c.Domains) == 1 {
			singles = append(singles, c.Domains[0])
		}
	}
	if !slices.Equal(singles, []string{graph.SelfDomain(bank), graph.SelfDomain(bankProv)}) {
		t.Errorf("bank single cuts %v", singles)
	}
	if got := g.Board()[graph.Money].ThiefNeed; got != 1 {
		t.Errorf("money thief need %d, want 1", got)
	}
	_, unreached := g.CutOffs(graph.Money)
	if !slices.Equal(unreached, []string{bank, AccountNode(CardID)}) {
		t.Errorf("money unreached %v", unreached)
	}
	if c := g.Confidence(graph.Money); c.Answer != 0 || c.Observed != 0 || c.Shipped == 0 {
		t.Errorf("money confidence %+v: table facts are shipped", c)
	}
	if idle := g.Idle(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC), 0); len(idle) != 0 {
		t.Errorf("idle %v: no last use is answered", idle)
	}
	cut, _ := g.CutOffs(graph.Safety)
	want := []graph.CutOff{{Asset: "d.thermo", Providers: []string{ProviderNode("airline"), ProviderNode("power")}}}
	if len(cut) != 1 || cut[0].Asset != want[0].Asset || !slices.Equal(cut[0].Providers, want[0].Providers) {
		t.Errorf("safety cut-offs %v, want %v", cut, want)
	}
}
