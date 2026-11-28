package nft

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// These tests pin behaviour that mutgate found unchecked on #5951, whose
// ASSUMPTIONS.md change widened the gate to every line the package's tests
// run.

// TestDropsFlushesEveryChainItFills: an update's drop text adds rules only
// to a chain it creates or has flushed first, so applying it again never
// leaves a chain with the old rules and the new ones (the drop chains, the
// edge's quota chain and a shared address's chain). Mutants: a flush line
// gone, the shared chain's add line gone.
func TestDropsFlushesEveryChainItFills(t *testing.T) {
	both := netip.MustParseAddr("203.0.113.10")
	a := DropGroup{Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100, Addrs: []netip.Addr{both, netip.MustParseAddr("203.0.113.30")}}
	b := DropGroup{Dests: []string{"b.example"}, Caps: []uint64{200}, Cap: 200, Addrs: []netip.Addr{both, netip.MustParseAddr("2001:db8::10")}}
	text := mustDrops(t, twoCaps(), []byte(`{"nftables": []}`), Drop{Day: 1, Groups: []DropGroup{a, b}, EdgeCap: 1000})
	ready := map[string]bool{}
	filled := map[string]bool{}
	const add, flush, rule = "add chain inet " + Table + " ", "flush chain inet " + Table + " ", "add rule inet " + Table + " "
	for _, ln := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(ln, add):
			ready[strings.TrimPrefix(ln, add)] = true
		case strings.HasPrefix(ln, flush):
			ready[strings.TrimPrefix(ln, flush)] = true
		case strings.HasPrefix(ln, rule):
			c, _, _ := strings.Cut(strings.TrimPrefix(ln, rule), " ")
			if !ready[c] {
				t.Errorf("rule for chain %s before the text creates or flushes it: %q", c, ln)
			}
			filled[c] = true
		}
	}
	m := sharedName(slices.Sorted(slices.Values([]string{first(groupNames(1, a)), first(groupNames(1, b))})))
	for _, c := range []string{capDropChain(false), capDropChain(true), dropEdgeChain, m} {
		if !filled[c] {
			t.Errorf("the text adds no rule to %s, so this test does not see its flush:\n%s", c, text)
		}
	}
}

func first(chain, _ string) string { return chain }

// TestGroupNameFollowsItsDestinations: a group's chain and quota change
// with its destinations' names, not only their caps, so moving a cap from
// one destination to another starts a new quota. Mutant: the destination
// left out of the name.
func TestGroupNameFollowsItsDestinations(t *testing.T) {
	ca, qa := groupNames(1, DropGroup{Dests: []string{"a.example"}, Caps: []uint64{100}})
	cb, qb := groupNames(1, DropGroup{Dests: []string{"b.example"}, Caps: []uint64{100}})
	if ca == cb || qa == qb {
		t.Errorf("groups of a.example and b.example share names %s, %s", ca, qa)
	}
}

// TestEdgeTrippedRefusesAnElementThatDoesNotRead: a TripSet element that
// fails to read is an error even when part of it named the edge before
// the failure, so a malformed listing never reads as a cut. Mutant: the
// error return of an element object that does not read.
func TestEdgeTrippedRefusesAnElementThatDoesNotRead(t *testing.T) {
	p := fresh(fixturePolicy())
	running := `{"nftables": [{"set": {"family": "inet", "table": "enforcer", "name": "` + TripSet + `", "elem": [{"elem": {"val": "edge0"}, "elem": 7}]}}]}`
	if got, err := EdgeTripped([]byte(running), fixtureLayout(), p); err == nil {
		t.Errorf("an element that does not read gives tripped %v, no error", got)
	}
}

// TestPairDeviceFirst (NET-3): a pair that names the device first and an
// Owner or Household device second is the same path as the other order,
// from that whole network to the device, and a pair naming no device of
// the document is refused. Mutants: the device-first case's path gone, the
// network switch gone.
func TestPairDeviceFirst(t *testing.T) {
	d := fixturePolicy()
	d.Devices = append(d.Devices, policy.Device{ID: "phone", Network: policy.NetOwner})
	for _, c := range []struct {
		pair policy.Pair
		want Path
	}{
		{pair: policy.Pair{A: "printer", B: "laptop"}, want: Path{From: "hh0", To: "ap0.105"}},
		{pair: policy.Pair{A: "tv", B: "phone"}, want: Path{From: "own0", To: "ap0.101"}},
	} {
		d.Pairs = []policy.Pair{c.pair}
		got, err := Paths(d, fixtureLayout())
		if err != nil || !slices.Equal(got, []Path{c.want}) {
			t.Errorf("pair %v: paths %v (err %v), want %v", c.pair, got, err, c.want)
		}
	}
	d.Pairs = []policy.Pair{{A: "printer", B: "nobody"}}
	if got, err := Paths(d, fixtureLayout()); !errors.Is(err, ErrPolicy) {
		t.Errorf("a pair naming no device: paths %v (err %v)", got, err)
	}
}
