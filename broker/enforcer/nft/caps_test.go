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
