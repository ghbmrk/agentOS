package nft

// REQ: NET-2, NET-3

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// answer adds addr to the allow set set of document d and to name's own
// set there, as slice f's resolver does with one answer (nftset= lists
// both; dns.Generate).
func (h *home) answer(d policy.Document, set, name, addr string) {
	h.t.Helper()
	a, v6 := allowSetOf(h.t, d, set)
	for _, s := range []string{set, a.Named(name, v6)} {
		run(h.t, "nft", "add", "element", "inet", Table, s, "{ "+addr+" }")
	}
}

func allowSetOf(t *testing.T, d policy.Document, set string) (AllowSet, bool) {
	t.Helper()
	sets, err := AllowSets(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range sets {
		if a.Set4 == set || a.Set6 == set {
			return a, a.Set6 == set
		}
	}
	t.Fatalf("no allow set %s", set)
	return AllowSet{}, false
}

// reload loads d the way the enforcer does after the first load: the
// running table's listing and d through Reload, then the loader.
func (h *home) reload(d policy.Document) {
	h.t.Helper()
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		h.t.Fatal(err)
	}
	running, err := (load.Loader{Bin: nftBin}).List(context.Background(), Table)
	if err != nil {
		h.t.Fatal(err)
	}
	text, err := Reload(d, fixtureLayout(), running)
	if err != nil {
		h.t.Fatal(err)
	}
	h.load(text)
}

// twoNames is the fixture with a second name on the TV's list and on the
// core's, each answered with an address no other name gives.
func twoNames() policy.Document {
	d := cutPolicy()
	d.Destinations = []string{"core.example", "old.core.example"}
	d.Devices = slices.Clone(d.Devices)
	for i, dev := range d.Devices {
		if dev.ID == "tv" {
			d.Devices[i].Allow = []string{"tv.example", "cdn.example"}
		}
	}
	return d
}

// NET-2 The core's list, NET-3 (#4237): narrowing a list ends the
// connections already open to the addresses only the dropped name
// answered, both ways, for a device and for the core, in the load that
// narrows it; connections to the names still listed go on. Catches a
// "narrow" the owner signed that stops new connections only, while open
// ones to the dropped name flow until they idle out.
func TestNarrowedListEndsOpenConnections(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	wide := twoNames()
	text, err := Compile(wide, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(text)
	h.answer(wide, DeviceSet(101, false), "tv.example", netAllow)
	h.answer(wide, DeviceSet(101, false), "cdn.example", netOther)
	h.answer(wide, CoreSet(false), "core.example", netCore)
	h.answer(wide, CoreSet(false), "old.core.example", netDoH)
	kept := []*held{
		h.hold("a device to a name still listed", "101", "isp", netAllow, 9241),
		h.hold("the core to a name still listed", "core", "isp", netCore, 9242),
	}
	dropped := []*held{
		h.hold("a device to the dropped name", "101", "isp", netOther, 9243),
		h.hold("the core to the dropped name", "core", "isp", netDoH, 9244),
	}
	if h.v6 {
		h.answer(wide, DeviceSet(101, true), "tv.example", net6Allow)
		h.answer(wide, DeviceSet(101, true), "cdn.example", net6Other)
		kept = append(kept, h.hold("a device to a name still listed over IPv6", "101", "isp", net6Allow, 9245))
		dropped = append(dropped, h.hold("a device to the dropped name over IPv6", "101", "isp", net6Other, 9246))
	}
	h.expectOpen(true, append(slices.Clone(kept), dropped...)...)

	narrow := cutPolicy() // the TV lists tv.example, the core core.example
	h.reload(narrow)
	h.expectOpen(true, kept...)
	h.expectOpen(false, dropped...)
	// A new connection to the dropped name is refused, and one to the
	// kept name opens with no new answer.
	h.expect(
		probe{from: "101", addr: netOther, port: 80, want: silent, why: "a device dials the dropped name's address"},
		probe{from: "101", addr: netAllow, port: 80, want: connected, why: "a device dials a kept name's address with no new answer"},
	)
}

// NET-2 The core's list (#4080): a load keeps every answer for the names
// still listed, so a device that cached its answer reaches its vendor
// cloud right after a load, without asking again; a device whose list is
// unchanged keeps its open connections too. Catches a load that empties
// the allow sets and leaves devices cut off until their next query.
func TestLoadKeepsListedAnswers(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	d := cutPolicy()
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(text)
	h.fillSets()
	h.answer(d, DeviceSet(103, false), "plug.example", netAllow)
	open := h.hold("a device to its allow list", "101", "isp", netAllow, 9247)
	for i := range 2 { // a second load keeps what the first carried
		h.reload(d)
		h.expectOpen(true, open)
		h.expect(
			probe{from: "101", addr: netAllow, port: 80, want: connected, why: "the TV dials its cached answer after a load"},
			probe{from: "103", addr: netAllow, port: 80, want: connected, why: "the plug dials its cached answer after a load"},
			probe{from: "core", addr: netCore, port: 80, want: connected, why: "the core dials its cached answer after a load"},
			probe{from: "101", addr: netOther, port: 80, want: silent, why: "nothing unanswered enters a set"},
		)
		if t.Failed() {
			t.Fatalf("after load %d", i+1)
		}
	}
}

// listing is a running table's JSON as nft prints it, with the given sets.
func listing(sets map[string][]any) []byte {
	var b strings.Builder
	b.WriteString(`{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "enforcer", "handle": 1}}`)
	names := make([]string, 0, len(sets))
	for n := range sets {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		var es []string
		for _, e := range sets[n] {
			switch e := e.(type) {
			case string:
				es = append(es, `"`+e+`"`)
			default:
				es = append(es, e.(raw).s)
			}
		}
		family, table, name := "inet", "enforcer", n
		if p := strings.Split(n, "/"); len(p) == 3 { // another family or table
			family, table, name = p[0], p[1], p[2]
		}
		b.WriteString(`, {"set": {"family": "` + family + `", "name": "` + name + `", "table": "` + table + `", "type": "ipv4_addr", "handle": 2, "flags": ["timeout"], "elem": [` + strings.Join(es, ", ") + `]}}`)
	}
	b.WriteString("]}")
	return []byte(b.String())
}

type raw struct{ s string }

// NET-2 The core's list, NET-3 (#4237, #4080): Reload carries exactly the
// answers of the names still listed, each into its name's set and the
// union into its allow set, and nothing else: not an address only a
// dropped name answered (one a kept name also answered stays), not what
// the old allow set held beyond its names' sets, not the answers of a
// device that held the VLAN before, not an element of the wrong family or
// in any form but a plain address. The first load carries nothing, and a
// listing that is not nft's JSON is refused.
func TestReloadCarriesListedAnswersOnly(t *testing.T) {
	l := fixtureLayout()
	wide := twoNames()
	narrow := cutPolicy()
	tv, _ := allowSetOf(t, wide, DeviceSet(101, false))
	core, _ := allowSetOf(t, wide, CoreSet(false))
	tv6 := func(n string) string { return tv.Named(n, true) }
	running := listing(map[string][]any{
		DeviceSet(101, false):                          {"203.0.113.10", "203.0.113.20", "198.51.100.9"},
		tv.Named("tv.example", false):                  {"203.0.113.10", "203.0.113.40", "2001:db8::1", raw{`{"elem": {"val": "203.0.113.50", "timeout": 60}}`}, raw{`{"prefix": {"addr": "203.0.113.0", "len": 24}}`}, "::ffff:203.0.113.60", "fe80::1%eth0"},
		tv.Named("cdn.example", false):                 {"203.0.113.20", "203.0.113.40"},
		tv6("tv.example"):                              {"2001:db8::10", "203.0.113.70", "::ffff:203.0.113.61", "fe80::2%eth0"},
		"ip/enforcer/" + tv.Named("tv.example", false): {"203.0.113.91"},
		"inet/other/" + tv.Named("tv.example", false):  {"203.0.113.92"},
		core.Named("core.example", false):              {"203.0.113.30"},
		core.Named("old.core.example", false):          {"1.1.1.1"},
		DeviceSet(103, false):                          {"203.0.113.80"},
	})

	base, err := Compile(narrow, l)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Reload(narrow, l, running)
	if err != nil {
		t.Fatal(err)
	}
	extra, ok := strings.CutPrefix(got, base)
	if !ok {
		t.Fatalf("Reload does not start with Compile's ruleset")
	}
	want := strings.Join([]string{
		"add element inet enforcer " + core.Named("core.example", false) + " { 203.0.113.30 }",
		"add element inet enforcer core_4 { 203.0.113.30 }",
		"add element inet enforcer " + tv.Named("tv.example", false) + " { 203.0.113.10, 203.0.113.40 }",
		"add element inet enforcer d101_4 { 203.0.113.10, 203.0.113.40 }",
		"add element inet enforcer " + tv6("tv.example") + " { 2001:db8::10 }",
		"add element inet enforcer d101_6 { 2001:db8::10 }",
	}, "\n") + "\n"
	if extra != want {
		t.Errorf("carried:\n%s\nwant:\n%s", extra, want)
	}

	// The plug's VLAN now belongs to another device listing the same name:
	// it inherits nothing.
	moved := narrow
	moved.Devices = slices.Clone(narrow.Devices)
	for i, dev := range moved.Devices {
		if dev.ID == "plug" {
			moved.Devices[i].ID = "new-plug"
		}
	}
	plug, _ := allowSetOf(t, narrow, DeviceSet(103, false))
	newPlug, _ := allowSetOf(t, moved, DeviceSet(103, false))
	if plug.Named("plug.example", false) == newPlug.Named("plug.example", false) {
		t.Error("a device that takes over a VLAN gets its predecessor's name set")
	}
	got, err = Reload(moved, l, listing(map[string][]any{plug.Named("plug.example", false): {"203.0.113.80"}}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "203.0.113.80") {
		t.Error("a device that takes over a VLAN inherits its predecessor's answers")
	}

	if got, err := Reload(narrow, l, nil); err != nil || got != base {
		t.Errorf("first load: %v, carried %q", err, strings.TrimPrefix(got, base))
	}
	if _, err := Reload(narrow, l, []byte("table inet enforcer {")); err == nil {
		t.Error("a listing that is not JSON was accepted")
	}
	if _, err := Reload(policy.Document{Devices: []policy.Device{{ID: "x", WiFi: "bad"}}}, l, running); err == nil {
		t.Error("a document Compile refuses was reloaded")
	}
}

// NET-2: a name set's name is the list's, a hash and nothing a document
// chooses in clear, so no host name reaches the ruleset text, and it
// differs by holder and by name.
func TestNamedSetNames(t *testing.T) {
	text, err := Compile(twoNames(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"tv.example", "cdn.example", "core.example"} {
		if strings.Contains(text, n) {
			t.Errorf("host name %s in the ruleset", n)
		}
	}
	a := AllowSet{Set4: "d5_4", holder: "x"}
	b := AllowSet{Set4: "d5_4", holder: "y"}
	if a.Named("n", false) == b.Named("n", false) || a.Named("n", false) == a.Named("m", false) {
		t.Error("name sets collide")
	}
	if !strings.HasPrefix(a.Named("n", false), "d5_4_") || len(a.Named("n", false)) != len("d5_4_")+16 {
		t.Errorf("name set %q", a.Named("n", false))
	}
}
