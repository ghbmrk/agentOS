package nft

// REQ: NET-2

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// carryListing is a running table as nft -j lists it, only the parts the
// carry reads: each quota with its charged bytes, each group chain, the
// drop's resolver-set rules (set -> chain) and one verdict map (address ->
// chain).
func carryListing(quotas map[string]uint64, chains []string, sets [][2]string, vmap [][2]string) []byte {
	var objs []string
	for q, n := range quotas {
		objs = append(objs, fmt.Sprintf(`{"quota": {"family": "inet", "table": "enforcer", "name": %q, "used": %d}}`, q, n))
	}
	for _, c := range chains {
		objs = append(objs, fmt.Sprintf(`{"chain": {"family": "inet", "table": "enforcer", "name": %q}}`, c))
	}
	for _, s := range sets {
		objs = append(objs, fmt.Sprintf(`{"rule": {"family": "inet", "table": "enforcer", "chain": "capd_4", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@%s"}}, {"goto": {"target": %q}}]}}`, s[0], s[1]))
	}
	if len(vmap) > 0 {
		var es []string
		for _, e := range vmap {
			es = append(es, fmt.Sprintf(`[%q, {"goto": {"target": %q}}]`, e[0], e[1]))
		}
		objs = append(objs, fmt.Sprintf(`{"rule": {"family": "inet", "table": "enforcer", "chain": "capd_4", "expr": [{"vmap": {"key": {"payload": {"protocol": "ip", "field": "daddr"}}, "data": {"set": [%s]}}}]}}`, strings.Join(es, ", ")))
	}
	return []byte(`{"nftables": [` + strings.Join(objs, ", ") + `]}`)
}

func wantQuota(t *testing.T, text, name string, n, used uint64) {
	t.Helper()
	if want := fmt.Sprintf("add quota inet enforcer %s { over %d bytes used %d bytes; }", name, n, used); !strings.Contains(text, want) {
		t.Errorf("update lacks %q:\n%s", want, text)
	}
}

// TestDropsCarryGuardsErrClosed (#4867 item 4, L3 release 1 on #4866): the
// carry's two guards are pinned. A gap as large as a uint64 (two old edge
// quotas, one charged 2^64-1 since the reading) saturates, so the new quota
// is loaded full rather than wrapping to a small count; a quota whose
// charged bytes fell since the reading (a reset) carries nothing rather
// than a wrapped difference. Mutants: `sat` without its `a+b < a` guard
// (the sum wraps to the count less one), gap's `n > b` as `n != b` (the
// reset carries 2^64-497 and loads the quota full).
func TestDropsCarryGuardsErrClosed(t *testing.T) {
	p := Drop{Day: 1, EdgeCap: 60, EdgeCount: 5, Past: true}
	qe := edgeQuota(1, 60)
	old1, old2 := edgeQuota(1, 50), edgeQuota(1, 40)
	for _, tc := range []struct {
		name          string
		read, running map[string]uint64
		used          uint64
	}{
		{"huge gap saturates", map[string]uint64{old1: 0, old2: 0}, map[string]uint64{old1: ^uint64(0), old2: 1}, 60},
		{"reset carries nothing", map[string]uint64{old1: 500}, map[string]uint64{old1: 3}, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.Read = carryListing(tc.read, nil, nil, nil)
			wantQuota(t, mustDrops(t, twoCaps(), carryListing(tc.running, nil, nil, nil), p), qe, 60, tc.used)
		})
	}
}

// TestDropsSplitCarriesTheWholeGapToEach (#4867 item 2, UX on #4866): an
// update that splits one running group in two (an owner's cap edit) loads
// each new group's quota with its count plus the old quota's whole gap,
// since the running drop sent both groups' destinations to the old chain:
// each new quota then trips no later than the old one would have
// (ASSUMPTIONS ENF-cap-trip-c-2). Mutant: carrying only into the first
// group.
func TestDropsSplitCarriesTheWholeGapToEach(t *testing.T) {
	d := twoCaps()
	core := allowSets(d, nil)[0]
	ab := DropGroup{Dests: []string{"a.example", "b.example"}, Caps: []uint64{100, 200}, Cap: 300}
	gab, qab := groupNames(1, ab)
	sets := [][2]string{{core.Named("a.example", false), gab}, {core.Named("b.example", false), gab}}
	read := carryListing(map[string]uint64{qab: 30}, []string{gab}, sets, nil)
	running := carryListing(map[string]uint64{qab: 50}, []string{gab}, sets, nil)
	a := DropGroup{Dests: []string{"a.example"}, Caps: []uint64{90}, Cap: 90, Count: 10}
	b := DropGroup{Dests: []string{"b.example"}, Caps: []uint64{200}, Cap: 200, Count: 20}
	text := mustDrops(t, d, running, Drop{Day: 1, EdgeCap: 60, Past: true, Read: read, Groups: []DropGroup{a, b}})
	_, qa := groupNames(1, a)
	_, qb := groupNames(1, b)
	wantQuota(t, text, qa, 90, 10+20)
	wantQuota(t, text, qb, 200, 20+20)
}

// TestDropsSharedChainGapNotCarried (#4867 item 3, L3 release 3 and
// Security release 2 on #4866): the carry learns which old group fed a new
// one from the running drop's resolver-set rules and its verdict map's
// entries to group chains. An address the verdict map sent to a shared
// chain (`m_`, an address held by several groups) is not traced through
// that chain, so an old group the running drop reached only that way
// carries nothing into the new group holding the address; its gap bytes
// pass the new quota uncharged once, and the counting set still trips on
// them at the next reading (ASSUMPTIONS ENF-cap-trip-c-2). The old group a
// destination's set fed is carried as usual. This pins the stated
// behaviour: a change that traces shared chains must restate the row.
func TestDropsSharedChainGapNotCarried(t *testing.T) {
	d := twoCaps()
	core := allowSets(d, nil)[0]
	s := netip.MustParseAddr("203.0.113.40")
	oa := DropGroup{Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100, Addrs: []netip.Addr{s}}
	or := DropGroup{Dests: []string{"r.example"}, Caps: []uint64{50}, Cap: 50, Addrs: []netip.Addr{s}} // off the list: no resolver set
	ga, qa := groupNames(1, oa)
	gr, qr := groupNames(1, or)
	cs := []string{ga, gr}
	if gr < ga {
		cs = []string{gr, ga}
	}
	m := sharedName(cs)
	listing := func(ua, ur uint64) []byte {
		return carryListing(map[string]uint64{qa: ua, qr: ur}, []string{ga, gr, m},
			[][2]string{{core.Named("a.example", false), ga}}, [][2]string{{s.String(), m}})
	}
	merged := DropGroup{Dests: []string{"a.example", "r.example"}, Caps: []uint64{100, 50}, Cap: 150, Count: 7, Addrs: []netip.Addr{s}}
	text := mustDrops(t, d, listing(25, 11), Drop{Day: 1, EdgeCap: 60, Past: true, Read: listing(20, 1), Groups: []DropGroup{merged}})
	_, qm := groupNames(1, merged)
	wantQuota(t, text, qm, 150, 7+5) // a's gap of 5, not r's of 10
}
