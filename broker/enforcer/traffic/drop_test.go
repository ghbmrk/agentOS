package traffic

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// REQ: NET-2, KRN-12

func capLayout() nft.Layout {
	return nft.Layout{
		WAN: "wan0", Owner: "own0", Household: "hh0", Guests: "gst0", Admin: "adm0",
		Core: "core0", Edge: "edge0", Trunk: "ap0", APMgmt: "apm0",
		APAdmin: []netip.Addr{netip.MustParseAddr("10.70.0.2")}, ISP: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		EdgeGateway: netip.MustParseAddr("10.60.0.1"), PagePort: 8443, ChannelPort: 7443, CorePagePort: 443,
	}
}

func capPolicy() policy.Document {
	d := doc()
	d.Destinations = []string{"a.example", "b.example"}
	d.Caps = map[string]uint64{"a.example": 100, "b.example": 100}
	d.EdgeCap = 50
	return d
}

// capListing is a running table as nft -j lists it: the table's handle, the
// counting sets' elements with their counters, the edge's counter and the
// core's name sets.
func capListing(t *testing.T, handle uint64, core map[netip.Addr]uint64, edge uint64, named map[string][]netip.Addr) []byte {
	t.Helper()
	sets, err := nft.AllowSets(capPolicy(), capLayout())
	if err != nil {
		t.Fatal(err)
	}
	objs := []any{
		map[string]any{"metainfo": map[string]any{"version": "1.0.9"}},
		map[string]any{"table": map[string]any{"family": "inet", "name": nft.Table, "handle": handle}},
		map[string]any{"table": map[string]any{"family": "inet", "name": "other", "handle": handle + 1}},
		map[string]any{"counter": map[string]any{"family": "inet", "table": nft.Table, "name": nft.EdgeOut, "packets": 1, "bytes": edge}},
		map[string]any{"counter": map[string]any{"family": "inet", "table": "other", "name": nft.EdgeOut, "packets": 1, "bytes": 999}},
	}
	for _, v6 := range []bool{false, true} {
		var elems []any
		for a, n := range core {
			if a.Is6() == v6 {
				elems = append(elems, map[string]any{"elem": map[string]any{"val": a.String(), "counter": map[string]any{"packets": 1, "bytes": n}}})
			}
		}
		set := map[string]any{"family": "inet", "table": nft.Table, "name": nft.CapSet(v6)}
		if elems != nil {
			set["elem"] = elems
		}
		objs = append(objs, map[string]any{"set": set})
		for name, as := range named {
			var e []any
			for _, a := range as {
				if a.Is6() == v6 {
					e = append(e, a.String())
				}
			}
			objs = append(objs, map[string]any{"set": map[string]any{"family": "inet", "table": nft.Table, "name": sets[0].Named(name, v6), "elem": e}})
		}
	}
	b, err := json.Marshal(map[string]any{"nftables": objs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReadingOfTheFirewall (ENF-cap-1, ENF-cap-trip-c): a reading is the
// firewall's own counters: each address's bytes in the counting sets, the
// edge's counter, and each listed name's resolver set; nothing from any
// other table. Mutants: the edge read from the wrong table, a name set
// read under the wrong name, a counting set's counter skipped.
func TestReadingOfTheFirewall(t *testing.T) {
	core := map[netip.Addr]uint64{addrA: 70, addrC: 30}
	named := map[string][]netip.Addr{"a.example": {addrA}, "b.example": {addrA, addrC}}
	r, err := ReadingOf(capPolicy(), capLayout(), "boot-1", capListing(t, 4, core, 20, named))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Core, core) || r.Edge != 20 {
		t.Fatalf("reading %+v, want core %v and edge 20", r, core)
	}
	if !reflect.DeepEqual(r.Named, map[string][]netip.Addr{"a.example": {addrA}, "b.example": {addrA, addrC}}) {
		t.Fatalf("named %v", r.Named)
	}
	for _, bad := range map[string][]byte{
		"not JSON":        []byte("{"),
		"no table":        []byte(`{"nftables": [{"counter": {"family": "inet", "table": "enforcer", "name": "edge_out", "bytes": 1}}]}`),
		"no edge counter": []byte(`{"nftables": [{"table": {"family": "inet", "name": "enforcer", "handle": 4}}, {"set": {"family": "inet", "table": "enforcer", "name": "capc_4"}}, {"set": {"family": "inet", "table": "enforcer", "name": "capc_6"}}]}`),
		"no counting set": []byte(`{"nftables": [{"table": {"family": "inet", "name": "enforcer", "handle": 4}}, {"counter": {"family": "inet", "table": "enforcer", "name": "edge_out", "bytes": 1}}]}`),
		"bad element":     []byte(`{"nftables": [{"table": {"family": "inet", "name": "enforcer", "handle": 4}}, {"counter": {"family": "inet", "table": "enforcer", "name": "edge_out", "bytes": 1}}, {"set": {"family": "inet", "table": "enforcer", "name": "capc_4", "elem": [{"prefix": {"addr": "11.0.0.0", "len": 8}}]}}, {"set": {"family": "inet", "table": "enforcer", "name": "capc_6"}}]}`),
	} {
		if _, err := ReadingOf(capPolicy(), capLayout(), "boot-1", bad); !errors.Is(err, ErrListing) {
			t.Errorf("listing %s: %v, want ErrListing", bad, err)
		}
	}
	if _, err := ReadingOf(capPolicy(), capLayout(), "", capListing(t, 4, core, 20, named)); !errors.Is(err, ErrListing) {
		t.Errorf("no boot id: %v, want ErrListing", err)
	}
}

// TestGenUniqueAcrossBoots (ENF-cap-6, #4561 L3 and Security release
// items): a ruleset's Gen is its table's handle with the boot's id, so the
// load at boot never reuses the saved Gen, even when the new kernel hands
// out the same handle. Saved at Gen 4 with 90 counted, a restart under the
// same load reading 95 counts 5; a boot that loads the table again with
// the same handle and reads 95 counts all 95. Mutant: Gen from the handle
// alone counts 5 after the boot, so 90 bytes leave uncounted.
func TestGenUniqueAcrossBoots(t *testing.T) {
	clk := &clock{noon}
	big := Caps{Core: map[string]uint64{"a.example": 1000, "b.example": 1000}, Edge: 1000}
	named := map[string][]netip.Addr{"a.example": {addrA}}
	at := func(boot string, n uint64) Reading {
		r, err := ReadingOf(capPolicy(), capLayout(), boot, capListing(t, 4, map[netip.Addr]uint64{addrA: n}, 0, named))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if at("boot-1", 1).Gen == at("boot-2", 1).Gen {
		t.Fatal("two boots with the same table handle share a Gen")
	}
	r1, err := ReadingOf(capPolicy(), capLayout(), "boot-1", capListing(t, 5, nil, 0, named))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Gen == at("boot-1", 1).Gen {
		t.Fatal("two loads in one boot share a Gen")
	}
	c := NewCounter(clk.now, big)
	c.Add(at("boot-1", 90))
	saved := c.Save()

	same, _ := Restore(clk.now, big, saved)
	same.Add(at("boot-1", 95))
	if g := groupOf(t, same.Counts(), "a.example"); g.Count != 95 {
		t.Fatalf("restart under the same load: %d, want 95", g.Count)
	}
	booted, _ := Restore(clk.now, big, saved)
	booted.Add(at("boot-2", 95))
	if g := groupOf(t, booted.Counts(), "a.example"); g.Count != 185 {
		t.Fatalf("a boot that reused the table handle: %d, want 185", g.Count)
	}
}

// TestRetiredCapsNeverOverflowAGroup (#4561 Security release item): a
// destination taken off the list keeps its cap until midnight, so caps
// from two versions can share a group. With a=2^63 in one version, b=2^63
// in the next and a shared address, the group's cap stays 2^64-1 and the
// counts still encode, so the kernel keeps a count to check sends against.
// Mutant: the retired cap kept whole, which the shared format refuses.
func TestRetiredCapsNeverOverflowAGroup(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, Caps{Core: map[string]uint64{"a.example": 1 << 63}})
	c.Resolved("a.example", addrA)
	c.SetCaps(Caps{Core: map[string]uint64{"b.example": 1 << 63}})
	c.Resolved("b.example", addrA)
	c.Add(reading(1, 0, addrA, 10))
	check := func(c *Counter, why string) {
		t.Helper()
		cs := c.Counts()
		if _, err := wire.EncodeCounts(cs); err != nil {
			t.Fatalf("%s: counts do not encode: %v", why, err)
		}
		if g := groupOf(t, cs, "a.example"); len(g.Dests) != 2 || g.Cap != ^uint64(0) {
			t.Fatalf("%s: group %+v, want both at 2^64-1", why, g)
		}
	}
	check(c, "after the second version")
	r, err := Restore(clk.now, Caps{Core: map[string]uint64{"b.example": 1 << 63}}, c.Save())
	if err != nil {
		t.Fatal(err)
	}
	check(r, "after a restart")
}

// TestRestoreKeepsTheEdgeAndResolved (#4561 L3 release item): Restore
// keeps the last reading's edge counter and the saved resolutions. Under
// the same load the edge counts only past the saved reading, and two
// destinations resolved today to one address stay one group with no bytes
// sent yet. Mutants: LastEdge dropped trips an honest edge; Resolved
// dropped splits the group, so each destination is held to its own cap.
func TestRestoreKeepsTheEdgeAndResolved(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("a.example", addrA)
	c.Resolved("b.example", addrA)
	c.Add(reading(1, 30))
	r, err := Restore(clk.now, twoCap, c.Save())
	if err != nil {
		t.Fatal(err)
	}
	if o := r.Add(reading(1, 50)); len(o) != 0 {
		t.Fatalf("the edge at its cap after a restart: %+v", o)
	}
	if g := groupOf(t, r.Counts(), "a.example"); len(g.Dests) != 2 {
		t.Fatalf("restored group %+v, want a.example and b.example", g)
	}
}

// TestHeldAddressPrunedAndGivenBack pins what happens to an address a
// resolver set holds at every reading but that is never resolved to the
// counter and carries nothing: its idle clock starts when first seen, so a
// full day later the day's roll forgets it, and the next reading gives its
// destinations back from the set, its clock starting again. It is never
// stray while held (TestHeldAddressKeepsItsDestinations).
func TestHeldAddressPrunedAndGivenBack(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	sets := map[string][]netip.Addr{"a.example": {addrA}}
	c.Add(held(reading(1, 0), sets))
	state := func() State {
		var s State
		if err := json.Unmarshal(c.Save(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	clk.t = noon.Add(48 * time.Hour)
	c.Counts() // the roll
	if s := state(); s.Dests[addrA] != nil {
		t.Fatalf("held but idle two days, after the roll: %+v, want forgotten", s.Dests)
	}
	c.Add(held(reading(1, 0), sets))
	if s := state(); !reflect.DeepEqual(s.Dests[addrA], []string{"a.example"}) || s.Used[addrA] != Day(clk.t) {
		t.Fatalf("held, after the next reading: %+v, used %v; want a.example from today", s.Dests, s.Used)
	}
}

// TestDropChargesHeldSharedAddressToEach (ENF-cap-trip-c-2, L3 on #4611):
// the kernel's groups are the counter's. An address two destinations' sets
// hold, idle today, is in both groups and charged to both quotas, so it
// never raises either one's own cap: a's own address stays at a's cap of
// 100, where the counter trips. Mutant: the drop merging groups at held
// addresses gives addrB the cap 200, so 40 bytes past a's cap leave.
func TestDropChargesHeldSharedAddressToEach(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	c.Resolved("a.example", addrB)
	sets := map[string][]netip.Addr{"a.example": {addrA, addrB}, "b.example": {addrA}}
	c.Add(held(reading(1, 7, addrB, 40), sets))
	p := c.Drop()
	want := nft.Drop{Day: Day(noon), EdgeCap: 50, EdgeCount: 7, Groups: []nft.DropGroup{
		{Dests: []string{"a.example"}, Caps: []uint64{100}, Cap: 100, Count: 40, Addrs: []netip.Addr{addrA, addrB}},
		{Dests: []string{"b.example"}, Caps: []uint64{100}, Cap: 100, Addrs: []netip.Addr{addrA}},
	}}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("drop %+v, want %+v", p, want)
	}
	text, err := nft.Drops(capPolicy(), capLayout(), nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, fmt.Sprintf("over %d bytes used %d bytes", 101, 40)) || strings.Contains(text, "over 201 ") {
		t.Fatalf("drop text: want a's quota of 101 used 40 and no merged one:\n%s", text)
	}
	// The counter agrees: more to a's own address trips a alone.
	if o := c.Add(held(reading(1, 7, addrB, 140), sets)); len(o) != 1 || !reflect.DeepEqual(o[0].Dests, []string{"a.example"}) || o[0].Cap != 100 {
		t.Fatalf("overruns %+v, want a.example past 100", o)
	}
}

// TestRestoreFitsRetiredCapsUnderRaisedCaps (#4611 L3 and Security
// blocker): Restore fits the saved retired caps under the caps it restarts
// with, which can be higher than those at the save. Saved with b=2^63
// listed and a=2^63 retired, sharing an address, and restored under
// b=2^63+5, the counts still encode. Mutant: Restore without fitRetired
// stops every capped send until midnight.
func TestRestoreFitsRetiredCapsUnderRaisedCaps(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, Caps{Core: map[string]uint64{"a.example": 1 << 63}})
	c.Resolved("a.example", addrA)
	c.SetCaps(Caps{Core: map[string]uint64{"b.example": 1 << 63}})
	c.Resolved("b.example", addrA)
	c.Add(reading(1, 0, addrA, 10))
	r, err := Restore(clk.now, Caps{Core: map[string]uint64{"b.example": 1<<63 + 5}}, c.Save())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.EncodeCounts(r.Counts()); err != nil {
		t.Fatalf("restored under raised caps: counts do not encode: %v", err)
	}
}

// TestDropLeavesAnAddressOfNoGroupOut (L3 delta on #4611): an idle address
// whose only destination has no group today (taken off the list in an
// earlier version, its address held but carrying nothing) is in no drop
// group, so the drop's default refuses it rather than charging some other
// group. Mutant: such an address charged to the first group.
func TestDropLeavesAnAddressOfNoGroupOut(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Add(held(reading(1, 0), map[string][]netip.Addr{"b.example": {addrB}}))
	clk.t = noon.Add(24 * time.Hour) // a new day: b's retired cap is gone
	c.SetCaps(Caps{Core: map[string]uint64{"a.example": 100}})
	c.Add(held(reading(1, 0), nil))
	for _, g := range c.Drop().Groups {
		if slices.Contains(g.Addrs, addrB) {
			t.Fatalf("an address of no group charged to %v", g.Dests)
		}
	}
}

// TestDropAtANewDay (mutgate on #4611): a drop taken after midnight, with
// no reading since, is the new day's: its day and no bytes counted, so the
// quotas start from nothing. Its addresses are in order, so the same state
// gives the same text. Mutants: the day not rolled, so yesterday's counts
// load under today's quotas; the addresses in map order.
func TestDropAtANewDay(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	r := Reading{Gen: 1, Core: map[netip.Addr]uint64{}, Edge: 9}
	var addrs []netip.Addr
	for i := 1; i <= 16; i++ {
		a := netip.AddrFrom4([4]byte{11, 0, 1, byte(i)})
		c.Resolved("a.example", a)
		r.Core[a] = 3
		addrs = append(addrs, a)
	}
	c.Add(r)
	p := c.Drop()
	if g := p.Groups[0]; !slices.Equal(g.Addrs, addrs) || g.Count != 48 || p.EdgeCount != 9 {
		t.Fatalf("drop %+v, want a's 16 addresses in order, 48 bytes and an edge of 9", p)
	}
	clk.t = noon.Add(24 * time.Hour)
	p = c.Drop()
	if p.Day != Day(clk.t) || p.EdgeCount != 0 {
		t.Fatalf("drop after midnight: day %d edge %d, want day %d and nothing counted", p.Day, p.EdgeCount, Day(clk.t))
	}
	for _, g := range p.Groups {
		if g.Count != 0 {
			t.Fatalf("drop after midnight: group %v counts %d", g.Dests, g.Count)
		}
	}
}

// TestRetiredCapsFitTogether (mutgate on #4611): two retired caps share
// what room the listed caps leave, so three versions' caps of 2^63 in one
// group still encode. Mutant: each retired cap fitted alone, so together
// they overflow the group.
func TestRetiredCapsFitTogether(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, Caps{Core: map[string]uint64{"a.example": 1 << 63}})
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		c.SetCaps(Caps{Core: map[string]uint64{d: 1 << 63}})
		c.Resolved(d, addrA)
	}
	c.Add(reading(1, 0, addrA, 10))
	if _, err := wire.EncodeCounts(c.Counts()); err != nil {
		t.Fatalf("three versions' caps in one group: counts do not encode: %v", err)
	}
}

// TestReadingOfRefuses (mutgate on #4611): a reading needs a layout the
// compiler takes and a listing nft wrote, and each counting set element
// is a plain address. Mutants: the layout's error dropped, the decode
// error replaced by a later one, an element that is no address read as
// the zero address.
func TestReadingOfRefuses(t *testing.T) {
	core := map[netip.Addr]uint64{addrA: 1}
	if _, err := ReadingOf(capPolicy(), nft.Layout{}, "boot-1", capListing(t, 4, core, 0, nil)); err == nil {
		t.Error("a layout the compiler refuses gave a reading")
	}
	if _, err := ReadingOf(capPolicy(), capLayout(), "boot-1", []byte("{")); err == nil || !strings.Contains(err.Error(), "EOF") {
		t.Errorf("a cut listing: %v, want its decode error", err)
	}
	for _, val := range []string{"not-an-address", "fe80::1%eth0"} {
		l := fmt.Sprintf(`{"nftables": [{"table": {"family": "inet", "name": "enforcer", "handle": 4}}, {"counter": {"family": "inet", "table": "enforcer", "name": "edge_out", "bytes": 1}}, {"set": {"family": "inet", "table": "enforcer", "name": "capc_6", "elem": [{"elem": {"val": %q, "counter": {"packets": 1, "bytes": 5}}}]}}, {"set": {"family": "inet", "table": "enforcer", "name": "capc_4"}}]}`, val)
		if _, err := ReadingOf(capPolicy(), capLayout(), "boot-1", []byte(l)); !errors.Is(err, ErrListing) {
			t.Errorf("element %q: %v, want ErrListing", val, err)
		}
	}
}

// TestDropCarriesItsReadingsListing (#4867 item 1, Potency release 1 on
// #4866): Counter.Drop fills Drop.Read with the listing of the reading it
// last added (ReadingOf keeps it on the Reading), so a caller that never
// sets Read still gets the merge carry. Read at the listing with the old
// edge quota charged 5, recapped from 50 to 60, and updated against a
// running listing where it has charged 12, the new edge quota starts at
// the counter's 7 plus the 7 sent since the reading. The listing is the
// counter's own copy: the caller reusing its buffer changes nothing.
// Mutants: Drop not filling Read (the quota starts at 7), Add keeping the
// caller's buffer.
func TestDropCarriesItsReadingsListing(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	named := map[string][]netip.Addr{"a.example": {addrA}}
	base := capListing(t, 4, map[netip.Addr]uint64{addrA: 40}, 7, named)
	r0, err := ReadingOf(capPolicy(), capLayout(), "boot-1", base)
	if err != nil {
		t.Fatal(err)
	}
	c.Add(r0)
	text0, err := nft.Drops(capPolicy(), capLayout(), nil, c.Drop())
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`add quota inet enforcer (qe_[0-9a-f]+) \{ over 51 `).FindStringSubmatch(text0)
	if m == nil {
		t.Fatalf("no edge quota of 50 in:\n%s", text0)
	}
	withQuota := func(used uint64) []byte {
		var doc struct {
			Nftables []json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(base, &doc); err != nil {
			t.Fatal(err)
		}
		doc.Nftables = append(doc.Nftables, json.RawMessage(fmt.Sprintf(`{"quota": {"family": "inet", "table": %q, "name": %q, "used": %d}}`, nft.Table, m[1], used)))
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	read := withQuota(5)
	want := slices.Clone(read)
	r, err := ReadingOf(capPolicy(), capLayout(), "boot-1", read)
	if err != nil {
		t.Fatal(err)
	}
	c.Add(r)
	for i := range read {
		read[i] = ' '
	}
	c.SetCaps(Caps{Core: twoCap.Core, Edge: 60})
	p := c.Drop()
	if string(p.Read) != string(want) {
		t.Fatalf("Drop.Read %q, want the last reading's listing", p.Read)
	}
	text, err := nft.Drops(capPolicy(), capLayout(), withQuota(12), p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "{ over 61 bytes used 14 bytes; }") {
		t.Fatalf("update: want the new edge quota at 7 counted plus 7 since the reading:\n%s", text)
	}
}
