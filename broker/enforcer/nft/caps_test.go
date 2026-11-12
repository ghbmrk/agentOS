package nft

// REQ: NET-2

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

func twoCaps() policy.Document {
	d := fixturePolicy()
	d.Destinations = []string{"a.example", "b.example", "c.example"}
	d.Caps = map[string]uint64{"a.example": 100, "b.example": 200, "c.example": 300}
	return d
}

func mustDrops(t *testing.T, d policy.Document, running []byte, p Drop) string {
	t.Helper()
	text, err := Drops(d, fixtureLayout(), running, p)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// TestDropQuotaEdge (NET-2 Byte caps, D-255): each group's quota is
// loaded with the group's count and stops the first byte past its cap: N
// is the cap plus one where the kernel's quota matches at N, the cap where
// it matches past N, and a count already past the cap is loaded full, so
// the next byte drops. A cap the kernel's quota cannot hold gets none. The
// fallback for an address the counter does not know yet charges the first
// listed name whose set holds it, after the counter's own addresses.
// Mutants: N off by one either way, the count not loaded.
func TestDropQuotaEdge(t *testing.T) {
	d := twoCaps()
	a := netip.MustParseAddr("203.0.113.30")
	p := Drop{Day: 1, EdgeCap: 50, EdgeCount: 70, Groups: []DropGroup{
		{Dests: []string{"a.example", "b.example"}, Caps: []uint64{100, 200}, Cap: 300, Count: 40, Addrs: []netip.Addr{a}},
		{Dests: []string{"c.example"}, Caps: []uint64{MaxDropCap + 1}, Cap: MaxDropCap + 1, Count: 1},
	}}
	ab, qab := groupNames(1, p.Groups[0])
	cc, qc := groupNames(1, p.Groups[1])
	for _, past := range []bool{false, true} {
		p.Past = past
		text := mustDrops(t, d, nil, p)
		n, e := 301, 51
		if past {
			n, e = 300, 50
		}
		core := allowSets(d, nil)[0]
		for _, want := range []string{
			fmt.Sprintf("add quota inet enforcer %s { over %d bytes used 40 bytes; }", qab, n),
			fmt.Sprintf("add quota inet enforcer %s { over %d bytes used %d bytes; }", edgeQuota(1, 50), e, e),
			"add rule inet enforcer " + ab + ` quota name "` + qab + `" goto log_cap`,
			"add chain inet enforcer " + cc,
			"add rule inet enforcer capd_4 ip daddr vmap { 203.0.113.30 : goto " + ab + " }\n" +
				"add rule inet enforcer capd_4 ip daddr @" + core.Named("a.example", false) + " goto " + ab + "\n" +
				"add rule inet enforcer capd_4 ip daddr @" + core.Named("b.example", false) + " goto " + ab + "\n" +
				"add rule inet enforcer capd_4 ip daddr @" + core.Named("c.example", false) + " goto " + cc + "\n" +
				"add rule inet enforcer capd_4 drop\n",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("past %v: drop text lacks %q:\n%s", past, want, text)
			}
		}
		if strings.Contains(text, qc) {
			t.Errorf("a cap past MaxDropCap has a quota:\n%s", text)
		}
		if !strings.HasPrefix(text, DropHeader+"\n") {
			t.Errorf("drop text does not start with DropHeader")
		}
	}
}

// TestDropsKeepsUnchangedQuotas: an update keeps the quota of a group
// that is unchanged, so its count in the kernel goes on, and deletes the
// chains and quotas of groups the state no longer has. Mutants: every
// quota added afresh (the bytes since the last reading forgotten), stale
// quotas left to pile up.
func TestDropsKeepsUnchangedQuotas(t *testing.T) {
	d := twoCaps()
	keep := DropGroup{Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100}
	gone := DropGroup{Dests: []string{"b.example"}, Caps: []uint64{200}, Cap: 200}
	ck, qk := groupNames(1, keep)
	cg, qg := groupNames(1, gone)
	qe := edgeQuota(1, 0)
	running := fmt.Sprintf(`{"nftables": [{"chain": {"family": "inet", "table": "enforcer", "name": %q}}, {"chain": {"family": "inet", "table": "enforcer", "name": %q}},
		{"quota": {"family": "inet", "table": "enforcer", "name": %q}}, {"quota": {"family": "inet", "table": "enforcer", "name": %q}}, {"quota": {"family": "inet", "table": "enforcer", "name": %q}},
		{"chain": {"family": "inet", "table": "enforcer", "name": "capd_4"}}, {"quota": {"family": "inet", "table": "other", "name": "q_x"}}]}`, ck, cg, qk, qg, qe)
	text := mustDrops(t, d, []byte(running), Drop{Day: 1, Groups: []DropGroup{keep, {Dests: []string{"c.example"}, Caps: []uint64{300}, Cap: 300}}})
	for _, want := range []string{"delete chain inet enforcer " + cg + "\n", "delete quota inet enforcer " + qg + "\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("update lacks %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"quota inet enforcer " + qk, "chain inet enforcer " + ck + "\n", "quota inet enforcer " + qe, "q_x", "delete chain inet enforcer capd_4"} {
		if strings.Contains(text, not) {
			t.Errorf("update touches %q:\n%s", not, text)
		}
	}
	if strings.Index(text, "delete chain") < strings.Index(text, "flush chain inet enforcer "+dropEdgeChain) {
		t.Errorf("a chain deleted before the rules that jump to it are flushed:\n%s", text)
	}
}

// TestDropsCarriesTheGap (NET-2 Byte caps, #4614, L3 R2 on #4611): a
// quota an update starts in place of running ones is loaded with the
// counter's count plus what the replaced quotas charged between the
// reading's listing and the running one: a merged group's from each old
// group the running drop sent one of its destinations (by resolver set)
// or addresses (by verdict map) to, a recapped group's from its own old
// quota, the edge's from the old edge quota. A kept quota is neither
// carried nor re-added, and without the reading's listing nothing is
// carried. Mutants: no carry, carrying a kept quota's or an unrelated
// group's bytes, carrying the old quota's whole count, mapping by
// destination only.
func TestDropsCarriesTheGap(t *testing.T) {
	d := twoCaps()
	core := allowSets(d, nil)[0]
	retired, moved := netip.MustParseAddr("203.0.113.31"), netip.MustParseAddr("203.0.113.32")
	old := map[string]DropGroup{
		"a": {Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100},
		"b": {Dests: []string{"b.example"}, Caps: []uint64{200}, Cap: 200},
		"c": {Dests: []string{"c.example"}, Caps: []uint64{300}, Cap: 300},
		"r": {Dests: []string{"r.example"}, Caps: []uint64{50}, Cap: 50}, // off the list: no resolver set
		"k": {Dests: []string{"k.example"}, Caps: []uint64{10}, Cap: 10}, // kept, though an address the running drop sent it is ab's now
	}
	ab := DropGroup{Dests: []string{"a.example", "b.example", "r.example"}, Caps: []uint64{100, 200, 50}, Cap: 350, Count: 40, Addrs: []netip.Addr{retired, moved}}
	c := DropGroup{Dests: []string{"c.example"}, Caps: []uint64{250}, Cap: 250, Count: 1}
	p := Drop{Day: 1, EdgeCap: 60, EdgeCount: 5, Past: true, Groups: []DropGroup{ab, c, old["k"]}}
	listing := func(used map[string]uint64) []byte {
		var objs []string
		quota := func(name string, n uint64) {
			objs = append(objs, fmt.Sprintf(`{"quota": {"family": "inet", "table": "enforcer", "name": %q, "used": %d}}`, name, n))
		}
		rule := func(set, chain string) {
			objs = append(objs, fmt.Sprintf(`{"rule": {"family": "inet", "table": "enforcer", "chain": "capd_4", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@%s"}}, {"goto": {"target": %q}}]}}`, set, chain))
		}
		for k, g := range old {
			ch, q := groupNames(1, g)
			objs = append(objs, fmt.Sprintf(`{"chain": {"family": "inet", "table": "enforcer", "name": %q}}`, ch))
			quota(q, used[k])
			if k != "r" {
				rule(core.Named(g.Dests[0], false), ch)
			}
		}
		quota(edgeQuota(1, 50), used["edge"])
		cr, _ := groupNames(1, old["r"])
		ck, _ := groupNames(1, old["k"])
		objs = append(objs, fmt.Sprintf(`{"rule": {"family": "inet", "table": "enforcer", "chain": "capd_4", "expr": [{"vmap": {"key": {"payload": {"protocol": "ip", "field": "daddr"}}, "data": {"set": [[%q, {"goto": {"target": %q}}], [%q, {"goto": {"target": %q}}]]}}}]}}`, retired, cr, moved, ck),
			`{"rule": {"family": "inet", "table": "enforcer", "chain": "forward", "expr": [{"vmap": {"key": {"meta": {"key": "iifname"}}, "data": "@named"}}]}}`)
		return []byte(`{"nftables": [` + strings.Join(objs, ", ") + `]}`)
	}
	d.Destinations = append(d.Destinations, "k.example")
	d.Caps["k.example"] = 10
	read := listing(map[string]uint64{"a": 50, "b": 10, "c": 5, "r": 3, "k": 4, "edge": 15})
	running := listing(map[string]uint64{"a": 70, "b": 30, "c": 10, "r": 10, "k": 9, "edge": 20})
	_, qab := groupNames(1, ab)
	_, qc := groupNames(1, c)
	_, qk := groupNames(1, old["k"])
	for _, tc := range []struct {
		read       []byte
		ab, c, edg uint64
	}{
		{read, 40 + 20 + 20 + 7, 1 + 5, 5 + 5},
		{nil, 40, 1, 5},
	} {
		p.Read = tc.read
		text := mustDrops(t, d, running, p)
		for _, want := range []string{
			fmt.Sprintf("add quota inet enforcer %s { over 350 bytes used %d bytes; }", qab, tc.ab),
			fmt.Sprintf("add quota inet enforcer %s { over 250 bytes used %d bytes; }", qc, tc.c),
			fmt.Sprintf("add quota inet enforcer %s { over 60 bytes used %d bytes; }", edgeQuota(1, 60), tc.edg),
		} {
			if !strings.Contains(text, want) {
				t.Errorf("read listing %v: update lacks %q:\n%s", tc.read != nil, want, text)
			}
		}
		if strings.Contains(text, "quota inet enforcer "+qk) {
			t.Errorf("a kept quota is touched:\n%s", text)
		}
	}
}

// TestDropsRefuses: a state the text cannot hold to the byte is refused:
// a destination in two groups, an address twice in one, a group with no
// destination or unsorted ones, and an address not in its plain form.
func TestDropsRefuses(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.30")
	for name, g := range map[string][]DropGroup{
		"dest twice": {{Dests: []string{"a.example"}, Caps: []uint64{1}}, {Dests: []string{"a.example"}, Caps: []uint64{1}}},
		"addr twice": {{Dests: []string{"a.example"}, Caps: []uint64{1}, Addrs: []netip.Addr{a, a}}},
		"no dest":    {{}},
		"unsorted":   {{Dests: []string{"b.example", "a.example"}, Caps: []uint64{1, 1}}},
		"caps short": {{Dests: []string{"a.example"}}},
		"mapped":     {{Dests: []string{"a.example"}, Caps: []uint64{1}, Addrs: []netip.Addr{netip.MustParseAddr("::ffff:203.0.113.30")}}},
	} {
		if _, err := Drops(twoCaps(), fixtureLayout(), nil, Drop{Groups: g}); !errors.Is(err, ErrDrop) {
			t.Errorf("%s: %v, want ErrDrop", name, err)
		}
	}
}

// TestUpdateOnlyTakesADropText: the loader applies a text outside a full
// load only when it is a drop update (its first line is DropHeader), so
// a text in any other form is refused. It checks only the first line;
// the rest is Drops' own output, built by the enforcer.
func TestUpdateOnlyTakesADropText(t *testing.T) {
	l := load.Loader{Bin: "/nonexistent/nft"}
	for _, text := range []string{"flush ruleset\n", "add rule inet enforcer forward accept\n", DropHeader + " \n", DropHeader} {
		if err := l.Update(context.Background(), text); err == nil || !strings.Contains(err.Error(), "not a byte-cap drop update") {
			t.Errorf("Update(%q): %v, want refused as not a drop update", text, err)
		}
	}
	text := mustDrops(t, twoCaps(), []byte(`{"nftables": []}`), Drop{})
	if err := l.Update(context.Background(), text); err == nil || strings.Contains(err.Error(), "not a byte-cap drop update") {
		t.Errorf("Update(Drops text) refused for its form: %v", err)
	}
}

// TestDropsChargesSharedAddressToEachGroup (L3 on #4611): an address in
// two groups (held by both sets, idle today) goes to a chain of its own
// that charges each group's quota in turn, and each group's own addresses
// to its own quota alone, so the shared address raises neither cap.
func TestDropsChargesSharedAddressToEachGroup(t *testing.T) {
	own, both := netip.MustParseAddr("203.0.113.30"), netip.MustParseAddr("203.0.113.10")
	a := DropGroup{Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100, Addrs: []netip.Addr{both, own}}
	b := DropGroup{Dests: []string{"b.example"}, Caps: []uint64{200}, Cap: 200, Addrs: []netip.Addr{both}}
	text := mustDrops(t, twoCaps(), nil, Drop{Day: 1, Groups: []DropGroup{a, b}})
	ga, qa := groupNames(1, a)
	gb, qb := groupNames(1, b)
	m := sharedName([]string{ga, gb})
	if ga > gb {
		m = sharedName([]string{gb, ga})
	}
	for _, want := range []string{
		"ip daddr vmap { 203.0.113.10 : goto " + m + ", 203.0.113.30 : goto " + ga + " }",
		"add rule inet enforcer " + m + ` quota name "` + qa + `" goto log_cap`,
		"add rule inet enforcer " + m + ` quota name "` + qb + `" goto log_cap`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("drop text lacks %q:\n%s", want, text)
		}
	}
	// An update that finds the shared chain keeps it as it is: adding its
	// rules again would charge each quota twice.
	kept := fmt.Sprintf(`{"nftables": [{"chain": {"family": "inet", "table": "enforcer", "name": %q}}, {"chain": {"family": "inet", "table": "enforcer", "name": %q}}, {"chain": {"family": "inet", "table": "enforcer", "name": %q}}, {"quota": {"family": "inet", "table": "enforcer", "name": %q}}, {"quota": {"family": "inet", "table": "enforcer", "name": %q}}]}`, m, ga, gb, qa, qb)
	if text := mustDrops(t, twoCaps(), []byte(kept), Drop{Day: 1, Groups: []DropGroup{a, b}}); strings.Contains(text, "add chain inet enforcer "+m) || strings.Contains(text, "add rule inet enforcer "+m+" ") || !strings.Contains(text, ": goto "+m) {
		t.Errorf("an update rewrites a kept shared chain:\n%s", text)
	}
	running := fmt.Sprintf(`{"nftables": [{"chain": {"family": "inet", "table": "enforcer", "name": %q}}]}`, m)
	if text := mustDrops(t, twoCaps(), []byte(running), Drop{Day: 1, Groups: []DropGroup{{Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100}}}); !strings.Contains(text, "delete chain inet enforcer "+m+"\n") {
		t.Errorf("a stale shared chain is kept:\n%s", text)
	}
}

// TestDropsWritesEveryCapTheKernelHolds (mutgate on #4611): Drops refuses
// a layout Compile refuses; a cap of MaxDropCap, the largest the kernel's
// quota holds, gets its quota and its drop; the vmap lists its addresses
// in order, so the same state gives the same text; and a group's name
// changes with its day and each cap, the edge's with its day and cap, so a
// changed cap starts a new quota. Mutants: the layout check gone, the
// bound off by one either way, the vmap in map order, a field left out of
// a name.
func TestDropsWritesEveryCapTheKernelHolds(t *testing.T) {
	if _, err := Drops(twoCaps(), Layout{}, nil, Drop{}); err == nil {
		t.Error("Drops took a layout Compile refuses")
	}
	var addrs []netip.Addr
	for i := 1; i <= 16; i++ {
		addrs = append(addrs, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}))
	}
	g := DropGroup{Dests: []string{"a.example"}, Caps: []uint64{MaxDropCap}, Cap: MaxDropCap, Addrs: addrs}
	c, q := groupNames(1, g)
	text := mustDrops(t, twoCaps(), nil, Drop{Day: 1, Groups: []DropGroup{g}})
	var elems []string
	for _, a := range addrs {
		elems = append(elems, a.String()+" : goto "+c)
	}
	slices.Sort(elems)
	for _, want := range []string{
		fmt.Sprintf("add quota inet enforcer %s { over %d bytes used 0 bytes; }", q, uint64(MaxDropCap)+1),
		"add rule inet enforcer " + c + ` quota name "` + q + `" goto log_cap`,
		"ip daddr vmap { " + strings.Join(elems, ", ") + " }",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("drop text lacks %q:\n%s", want, text)
		}
	}
	other := g
	other.Caps = []uint64{MaxDropCap - 1}
	if _, q2 := groupNames(1, other); q2 == q {
		t.Error("a group's name ignores its caps")
	}
	if _, q2 := groupNames(2, g); q2 == q {
		t.Error("a group's name ignores its day")
	}
	if edgeQuota(1, 50) == edgeQuota(2, 50) || edgeQuota(1, 50) == edgeQuota(1, 51) {
		t.Error("the edge's quota name ignores its day or cap")
	}
}

// TestDropsRefusesAListing: a reading's or running listing the update
// cannot read to the byte, or a running verdict map address that is no
// address, is refused, not read as nothing charged or sent.
func TestDropsRefusesAListing(t *testing.T) {
	quota := `{"nftables": [{"quota": {"family": "inet", "table": "enforcer", "name": "q", "used": %s}}]}`
	vmap := `{"nftables": [{"rule": {"family": "inet", "table": "enforcer", "chain": %q, "expr": [{"vmap": {"key": {"payload": {"protocol": "ip", "field": "daddr"}}, "data": {"set": [["%s", {"goto": {"target": "g_x"}}]]}}}]}}]}`
	for name, c := range map[string]struct{ read, running string }{
		"reading":      {`{"nftables": [`, fmt.Sprintf(quota, "1")},
		"running":      {fmt.Sprintf(quota, "1"), fmt.Sprintf(quota, `"x"`)},
		"vmap address": {"", fmt.Sprintf(vmap, capDropChain(false), "bogus")},
	} {
		p := Drop{Day: 1, Groups: []DropGroup{{Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100}}}
		if c.read != "" {
			p.Read = []byte(c.read)
		}
		if text, err := Drops(twoCaps(), fixtureLayout(), []byte(c.running), p); err == nil {
			t.Errorf("%s: an update\n%s", name, text)
		}
	}
}

// TestDropsCarryTheEdgeCut (#5014, KRN-12): every Drops text empties the
// cut chain first, and fills it with a counted drop only while the edge
// is cut, so a text on its own or appended to a full load sets the cut
// to exactly p's; the forward chain sends the edge's every packet, both
// ways, through it before any other rule.
func TestDropsCarryTheEdgeCut(t *testing.T) {
	d := fixturePolicy()
	rule := `add rule inet enforcer cut_edge counter name "edge_cut" drop`
	for _, running := range [][]byte{nil, []byte(`{"nftables": []}`)} {
		for _, cut := range []bool{false, true} {
			p := fresh(d)
			p.EdgeCut = cut
			text := mustDrops(t, d, running, p)
			if !strings.HasPrefix(text, DropHeader+"\n") || !strings.Contains(text, "flush chain inet enforcer cut_edge\n") {
				t.Errorf("cut %v: the cut chain is not emptied first:\n%s", cut, text)
			}
			if got := strings.Count(text, rule); got != map[bool]int{false: 0, true: 1}[cut] {
				t.Errorf("cut %v: %d cut rules:\n%s", cut, got, text)
			}
		}
	}
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	fwd := text[strings.Index(text, "chain forward {"):]
	want := "type filter hook forward priority filter; policy drop;\n\t\tiifname \"edge0\" jump cut_edge\n\t\toifname \"edge0\" jump cut_edge\n"
	if !strings.Contains(fwd, want) {
		t.Errorf("the forward chain does not start with the cut:\n%s", fwd[:400])
	}
	if !strings.Contains(text, "\tchain cut_edge {\n\t}\n") {
		t.Error("the cut chain is not declared empty")
	}
	if !strings.Contains(text, "\tchain over_edge {\n\t\tadd @edge_trip { \"edge0\" }\n\t\tgoto log_cap\n\t}\n") {
		t.Error("past the edge's quota, a packet does not put the edge in TripSet before it is dropped")
	}

	// #5282: the kernel's own cut. Unless the edge is held, the cut chain
	// drops every packet once TripSet holds the edge; the edge's quota
	// sends what passes it to over_edge; TripSet is emptied when the
	// running edge quota is another (a new day or cap) and holds the edge
	// at once when the count is already past the cap.
	trip := []string{
		`add rule inet enforcer cut_edge iifname @edge_trip counter name "edge_cut" drop`,
		`add rule inet enforcer cut_edge oifname @edge_trip counter name "edge_cut" drop`,
	}
	const (
		flush = "flush set inet enforcer edge_trip\n"
		fill  = `add element inet enforcer edge_trip { "edge0" }` + "\n"
	)
	p := fresh(d)
	p.EdgeCap = 1000
	qe := edgeQuota(p.Day, p.EdgeCap)
	listing := func(quotas ...string) []byte {
		var objs []string
		for _, q := range quotas {
			objs = append(objs, `{"quota": {"family": "inet", "table": "enforcer", "name": "`+q+`"}}`)
		}
		return []byte(`{"nftables": [` + strings.Join(objs, ", ") + `]}`)
	}
	for _, c := range []struct {
		name          string
		cut, hold     bool
		count         uint64
		running       []byte
		rules         []string
		flush, filled bool
	}{
		{name: "uncut", rules: trip},
		{name: "held", hold: true},
		{name: "cut", cut: true, rules: []string{rule}},
		{name: "at the cap", count: 1000, rules: trip},
		{name: "past the cap", count: 1001, rules: trip, filled: true},
		{name: "past the cap, held", count: 1001, hold: true, filled: true},
		{name: "the same quota running", running: listing(qe), rules: trip},
		{name: "another quota running", running: listing(qe, edgeQuota(p.Day-1, p.EdgeCap)), rules: trip, flush: true},
		{name: "two other quotas running", running: listing(edgeQuota(p.Day-1, p.EdgeCap), edgeQuota(p.Day, 2000)), rules: trip, flush: true},
		{name: "a new day past the cap", count: 1001, running: listing(edgeQuota(p.Day-1, p.EdgeCap)), rules: trip, flush: true, filled: true},
	} {
		q := p
		q.EdgeCut, q.EdgeHold, q.EdgeCount = c.cut, c.hold, c.count
		text := mustDrops(t, d, c.running, q)
		var rules []string
		for _, ln := range strings.Split(text, "\n") {
			if strings.HasPrefix(ln, "add rule inet enforcer cut_edge ") {
				rules = append(rules, ln)
			}
		}
		if !slices.Equal(rules, c.rules) {
			t.Errorf("%s: cut rules %q, want %q", c.name, rules, c.rules)
		}
		if n := strings.Count(text, flush); n != map[bool]int{false: 0, true: 1}[c.flush] {
			t.Errorf("%s: TripSet emptied %d times, want it once %v:\n%s", c.name, n, c.flush, text)
		}
		if i := strings.Index(text, fill); (i >= 0) != c.filled || c.flush && c.filled && i < strings.Index(text, flush) {
			t.Errorf("%s: TripSet filled %v, want %v, after it is emptied:\n%s", c.name, i >= 0, c.filled, text)
		}
		if want := `add rule inet enforcer capd_edge quota name "` + qe + `" goto over_edge`; !strings.Contains(text, want+"\n") {
			t.Errorf("%s: the edge's quota does not send what passes it to over_edge:\n%s", c.name, text)
		}
	}
}

// TestEdgeTrippedFollowsTheText (#5399 item 2, KRN-12): the kernel cuts
// the edge once a Drops text is applied exactly when TripSet holds the
// edge's interface and the text does not empty the set: the running edge
// quota is p's or none. Another interface cuts nothing; a listing that
// does not read back, or an element of the set that is not a name, is an
// error.
func TestEdgeTrippedFollowsTheText(t *testing.T) {
	d, l := fixturePolicy(), fixtureLayout()
	p := fresh(d)
	p.EdgeCap = 1000
	qe, old := edgeQuota(p.Day, p.EdgeCap), edgeQuota(p.Day-1, p.EdgeCap)
	quota := func(q string) string {
		return `{"quota": {"family": "inet", "table": "enforcer", "name": "` + q + `"}}`
	}
	set := func(elems string) string {
		return `{"set": {"family": "inet", "table": "enforcer", "name": "edge_trip", "elem": [` + elems + `]}}`
	}
	for _, c := range []struct {
		name string
		objs []string
		want bool
	}{
		{name: "empty", objs: []string{set("")}},
		{name: "filled", objs: []string{set(`"edge0"`)}, want: true},
		{name: "filled, the same quota running", objs: []string{quota(qe), set(`"edge0"`)}, want: true},
		{name: "filled, another quota running", objs: []string{quota(old), set(`"edge0"`)}},
		{name: "filled, as an element object", objs: []string{set(`{"elem": {"val": "edge0"}}`)}, want: true},
		{name: "another interface", objs: []string{set(`"core0"`)}},
		{name: "another set", objs: []string{`{"set": {"family": "inet", "table": "enforcer", "name": "capc_4", "elem": ["edge0"]}}`}},
		{name: "another table", objs: []string{`{"set": {"family": "inet", "table": "other", "name": "edge_trip", "elem": ["edge0"]}}`}},
	} {
		running := []byte(`{"nftables": [` + strings.Join(c.objs, ", ") + `]}`)
		got, err := EdgeTripped(running, l, p)
		if err != nil || got != c.want {
			t.Errorf("%s: tripped %v, %v; want %v", c.name, got, err, c.want)
		}
		// The text Drops writes agrees: it empties the set only where
		// EdgeTripped says the cut does not hold.
		if text := mustDrops(t, d, running, p); c.want && strings.Contains(text, "flush set inet enforcer edge_trip\n") {
			t.Errorf("%s: the text empties a set EdgeTripped says still cuts", c.name)
		}
	}
	for _, bad := range []string{`{`, `{"nftables": [{"quota": "unreadable"}]}`, `{"nftables": [{"set": "unreadable"}]}`, `{"nftables": [` + set(`7`) + `]}`, `{"nftables": [` + set(`{"elem": 7}`) + `]}`,
		// An element with no name is an error wherever it sits among the
		// others (#5445 item 3), not skipped.
		`{"nftables": [` + set(`{"elem": {}}`) + `]}`, `{"nftables": [` + set(`{"elem": {"val": ""}}`) + `]}`,
		`{"nftables": [` + set(`{"elem": {}}, "edge0"`) + `]}`, `{"nftables": [` + set(`"edge0", {"elem": {}}`) + `]}`,
		`{"nftables": [` + set(`""`) + `]}`} {
		if _, err := EdgeTripped([]byte(bad), l, p); err == nil {
			t.Errorf("listing %s read back", bad)
		}
	}
}
