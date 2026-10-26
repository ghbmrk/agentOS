package accounts

import (
	"slices"

	"github.com/ghbmrk/agentos/broker/owner/graph"
)

// Device is a device node already in the owner's graph and the ONB-3 kind
// the plan step connected it as.
type Device struct{ ID, Kind string }

// AccountNode and ProviderNode are the graph IDs a plan item's account and
// its provider get.
func AccountNode(id string) string  { return "acct." + id }
func ProviderNode(id string) string { return "prov." + id }

// ProviderSuffix ends a provider node's name, so no two nodes share a name
// and STOP <name> resolves the account alone (TN-graph-A6).
const ProviderSuffix = " provider"

// assets is the asset class a table kind declares; other kinds declare none.
var assets = map[string]graph.Class{"money": graph.Money, "identity": graph.Identity, "mail": graph.Data}

// Facts hands a plan to the owner's graph (CLK-10, TN-account-plan-7): per
// item an account node and its provider's node, an act and a cutoff edge
// from the provider to the account, and a cutoff edge from the account to
// each listed device whose kind the entry is implied by. The caller passes
// them, with its own nodes, to graph.New.
//
// Each fact carries its source. The account is observed when the owner's
// mail showed it or it is connected, and shipped when only the table's
// device implication puts it there; the provider and every edge are the
// table's (shipped). A card, wallet or mailbox item is an offer, not an
// account, so it gets nodes only once connected.
//
// Facts the table does not answer stay absent: no failure domain (graph.New
// then gives each node its own), no page, no last use, no edge from the
// owner. The engine reads each at its weakest: the account falls alone and
// the owner does not reach it, until an answer or #2860's fields say more.
func Facts(t *Table, plan []Item, connected []string, devices []Device) ([]graph.Node, []graph.Edge) {
	if t == nil {
		return nil, nil
	}
	var nodes []graph.Node
	var edges []graph.Edge
	for _, it := range plan {
		on := slices.Contains(connected, it.ID)
		if it.Source == Always && !on {
			continue
		}
		e, ok := t.Entry(it.ID)
		if !ok {
			continue
		}
		acct, prov := AccountNode(e.ID), ProviderNode(e.ID)
		src := graph.Shipped
		if it.Source == FromMail || on {
			src = graph.Observed
		}
		a := graph.Node{ID: acct, Kind: graph.Account, Name: e.Name, Source: src}
		if c, ok := assets[e.Kind]; ok {
			a.Assets = []graph.Class{c}
		}
		nodes = append(nodes, a,
			graph.Node{ID: prov, Kind: graph.Provider, Name: e.Name + ProviderSuffix, Source: graph.Shipped})
		edges = append(edges,
			graph.Edge{Kind: graph.Act, From: []string{prov}, To: acct, Source: graph.Shipped},
			graph.Edge{Kind: graph.Cutoff, From: []string{prov}, To: acct, Source: graph.Shipped})
		for _, d := range devices {
			if slices.Contains(e.ImpliedBy, d.Kind) {
				edges = append(edges, graph.Edge{Kind: graph.Cutoff, From: []string{acct}, To: d.ID, Source: graph.Shipped})
			}
		}
	}
	return nodes, edges
}
