package kernel_test

// REQ: KEY-9

import (
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// KEY-9-reach-read-copy: the read is a copy, so an in-process caller that
// edits it cannot edit the fold and lower a price.
func TestDeclReachReadIsACopy(t *testing.T) {
	s := declared(t, kernel.DeclReach{
		Nodes: []kernel.ReachNode{{ID: "mbox", Clerk: "mail", Classes: []key.Asset{key.AssetData}},
			{ID: "bank", Classes: []key.Asset{key.AssetMoney, key.AssetIdentity}}},
		Edges: []kernel.ReachEdge{{Kind: "reset", From: []string{"mbox"}, To: "bank"}},
	})
	sorted := func() []key.Asset { return slices.Sorted(slices.Values(kernel.GraphReach(s, "mail"))) }
	reach, price := sorted(), worth(t, s, false, key.Read)
	if !slices.Contains(reach, key.AssetIdentity) {
		t.Fatalf("the reset edge is not in the reach: %v", reach)
	}
	got := s.DeclReach()
	for i := range got.Nodes {
		got.Nodes[i].Classes[0] = key.AssetData
		got.Nodes[i].Classes = got.Nodes[i].Classes[:1]
	}
	got.Edges[0].From[0], got.Edges[0].To = "elsewhere", "elsewhere"
	if after := sorted(); !slices.Equal(after, reach) {
		t.Fatalf("editing the read changed the reach: %v, was %v", after, reach)
	}
	if after := worth(t, s, false, key.Read); after != price {
		t.Fatalf("editing the read changed a grant's price: %v, was %v", after, price)
	}
}
