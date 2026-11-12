package nft

// REQ: NET-3, NET-2, NET-1

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/internal/netnstest"
)

var update = flag.Bool("update", false, "rewrite testdata/fixture.nft")

// TestGolden: the fixture policy compiles to exactly testdata/fixture.nft,
// twice, and nft accepts it (checked in a user namespace when nft is
// present). Catches a reachable segment slipped into the ruleset text; the
// netns tests below check what the text does.
func TestGolden(t *testing.T) {
	got, err := Compile(fixturePolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Compile(fixturePolicy(), fixtureLayout())
	if got != again {
		t.Fatal("two compiles of one document differ")
	}
	if *update {
		if err := os.WriteFile("testdata/fixture.nft", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/fixture.nft")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("ruleset differs from testdata/fixture.nft (run with -update and review the diff):\n%s", got)
	}
	netnstest.Ready(t, combined, []string{"-rn"}, "nft")
	cmd := exec.Command("unshare", "-rn", "nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(got)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c refuses the ruleset: %v\n%s", err, out)
	}
}

// TestNoPolicyTextInRuleset: device ids, host names and standing rules
// never reach the ruleset, so a name the core proposed cannot inject a rule.
// Devices appear only by VLAN number.
func TestNoPolicyTextInRuleset(t *testing.T) {
	d := fixturePolicy()
	d.Devices[0].ID = `tv";accept;#`
	d.Pairs = nil
	d.Destinations = []string{`x"}accept`}
	d.Caps = map[string]uint64{`x"}accept`: 5}
	d.Devices[0].Allow = []string{`y{accept}`}
	got, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	// The drop state names destinations only by hashes, too.
	p := fresh(d)
	p.Groups[0].Addrs = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	drops, err := Drops(d, fixtureLayout(), nil, p)
	if err != nil {
		t.Fatal(err)
	}
	got += drops
	// A hardware address is read only as part of a shared segment's host
	// record (#4324) or address claim (#4480), never to tell devices apart
	// (D-225).
	got = stripKeys(got)
	for _, s := range []string{"accept;#", `x"`, "y{", "tv.example", "core.example", "speaker", "ether"} {
		if strings.Contains(got, s) {
			t.Errorf("ruleset carries %q", s)
		}
	}
}

// TestCompileRefuses: a document or layout the ruleset cannot express
// safely is refused, so the previous ruleset stays (P5).
func TestCompileRefuses(t *testing.T) {
	cases := map[string]func(*policy.Document, *Layout){
		"bad vlan":         func(d *policy.Document, _ *Layout) { d.Devices[0].WiFi = "vlan0101" },
		"vlan 1":           func(d *policy.Document, _ *Layout) { d.Devices[0].WiFi = "vlan1" },
		"vlan 4095":        func(d *policy.Document, _ *Layout) { d.Devices[0].WiFi = "vlan4095" },
		"not a vlan":       func(d *policy.Document, _ *Layout) { d.Devices[0].WiFi = "aa:bb:cc:dd:ee:ff" },
		"shared vlan":      func(d *policy.Document, _ *Layout) { d.Devices[1].WiFi = "vlan101" },
		"vlan off devices": func(d *policy.Document, _ *Layout) { d.Devices[9].WiFi = "vlan200" },
		"pair of people": func(d *policy.Document, _ *Layout) {
			d.Devices = append(d.Devices, policy.Device{ID: "phone", Network: policy.NetOwner})
			d.Pairs = []policy.Pair{{A: "laptop", B: "phone"}}
		},
		"pair with guests": func(d *policy.Document, _ *Layout) { d.Devices[9].Network = policy.NetGuests },
		"quoted interface": func(_ *policy.Document, l *Layout) { l.Owner = `own0"` },
		"same interface":   func(_ *policy.Document, l *Layout) { l.Household = l.Owner },
		"under the trunk":  func(_ *policy.Document, l *Layout) { l.APMgmt = "ap0.1" },
		"long trunk":       func(_ *policy.Document, l *Layout) { l.Trunk = "trunk-port0" },
		"no ISP":           func(_ *policy.Document, l *Layout) { l.ISP = nil },
		"mapped ISP": func(_ *policy.Document, l *Layout) {
			l.ISP = []netip.Prefix{netip.MustParsePrefix("::ffff:192.168.1.0/120")}
		},
		"page is channel": func(_ *policy.Document, l *Layout) { l.ChannelPort = l.PagePort },
		"bad document":    func(d *policy.Document, _ *Layout) { d.Devices[0].Network = "attic" },
	}
	for name, mut := range cases {
		d, l := fixturePolicy(), fixtureLayout()
		mut(&d, &l)
		if _, err := Compile(d, l); !errors.Is(err, ErrPolicy) && !errors.Is(err, ErrLayout) {
			t.Errorf("%s: compiled (err %v)", name, err)
		}
	}
}

// TestPathsFollowTheDocument: each path rule appears exactly when the
// document's fields say, and an isolated device or a cut vendor cloud
// removes it (the tightenings ENF-a classifies must change the ruleset).
func TestPathsFollowTheDocument(t *testing.T) {
	has := func(d policy.Document, s string) bool {
		t.Helper()
		got, err := Compile(d, fixtureLayout())
		if err != nil {
			t.Fatal(err)
		}
		// The connection marks are TestEveryAcceptBound's, and every
		// device's refusal chain, isolated or not, TestLinesBound's.
		return strings.Contains(refusedMap.ReplaceAllString(markSet.ReplaceAllString(got, ""), ""), s)
	}
	d := fixturePolicy()
	tvNet := `iifname "ap0.101" oifname "wan0" ip daddr @d101_4_r accept`
	edgeTV := `iifname "edge0" oifname "ap0.101"`
	coreSpk := `iifname "core0" oifname "ap0.102"`
	pair := `iifname "ap0.106" oifname "ap0.107" accept`
	people := `iifname "hh0" oifname "ap0.105" goto learn`
	for _, s := range []string{tvNet, edgeTV, coreSpk, pair, people} {
		if !has(d, s) {
			t.Errorf("fixture lacks %q", s)
		}
	}
	for _, s := range []string{`"ap0.104" oifname "wan0"`, `oifname "ap0.103" goto log_`, `oifname "ap0.104" udp`, `"ap0.108"`, `iifname "ap0.105" oifname "hh0" accept`, `iifname "ap0.105" oifname "hh0" goto`} {
		if has(d, s) {
			t.Errorf("fixture has %q", s)
		}
	}
	cut := fixturePolicy()
	cut.Devices[0].VendorCloud = false
	if has(cut, tvNet) || has(cut, edgeTV) {
		t.Error("cutting the vendor cloud left the device online")
	}
	iso := fixturePolicy()
	iso.Devices[5].Isolated = true
	if has(iso, pair) || has(iso, `"ap0.106"`) {
		t.Error("isolating a device left a rule for it")
	}
	safe := fixturePolicy()
	safe.Devices[1].Everyday = false
	if has(safe, coreSpk) {
		t.Error("the core reaches a safety-list device")
	}

	// Each box reaches an everyday device only on its control ports, and
	// the core a camera only on its stream ports while it is offline
	// (NET-2 Device paths, Cameras and microphones; ENF-e-2).
	for _, s := range []string{
		`iifname "edge0" oifname "ap0.101" tcp dport { 80 } goto log_edge_dev`,
		`iifname "core0" oifname "ap0.102" tcp dport { 80 } goto log_core_dev`,
		`iifname "core0" oifname "ap0.102" udp dport { 123 } goto log_core_dev`,
		`iifname "core0" oifname "ap0.104" tcp dport { 554 } goto log_core_stream`,
	} {
		if !has(d, s) {
			t.Errorf("fixture lacks %q", s)
		}
	}
	for _, s := range []string{`oifname "ap0.105" goto log_`, `oifname "ap0.105" tcp`, `oifname "ap0.104" tcp dport { 80 }`, `oifname "ap0.103" tcp`} {
		if has(d, s) {
			t.Errorf("fixture has %q", s)
		}
	}
	stream := `oifname "ap0.104" tcp dport { 554 }`
	for name, f := range map[string]func(*policy.Device){
		"cloud camera":    func(v *policy.Device) { v.VendorCloud = true },
		"isolated camera": func(v *policy.Device) { v.Isolated = true },
		"no stream port":  func(v *policy.Device) { v.Stream = nil },
	} {
		c := fixturePolicy()
		f(&c.Devices[3])
		if has(c, stream) {
			t.Errorf("%s: the core reaches its stream", name)
		}
	}
	none := fixturePolicy()
	none.Devices[1].Control = nil
	if has(none, `oifname "ap0.102"`) {
		t.Error("the core reaches an everyday device with no control port")
	}
}

// stripKeys is text without the shared segments' host record and address
// claim keys, the only places the ruleset reads a hardware address or a
// packet's own source address as a value.
func stripKeys(text string) string {
	for _, v6 := range []bool{false, true} {
		text = strings.ReplaceAll(text, hostKey(v6), "")
	}
	for _, k := range []string{claimKey, leaseKey, hwField} {
		text = strings.ReplaceAll(text, k, "")
	}
	return text
}

// TestVLANReadsOnlyItsRange: a Wi-Fi identity is a VLAN only as
// "vlan<N>", N from 2 to 4094 in digits alone, so both ends are devices'
// and a letter after the digits is no VLAN (P5).
func TestVLANReadsOnlyItsRange(t *testing.T) {
	for wifi, want := range map[string]int{"vlan2": 2, "vlan4094": 4094, "vlan109": 109} {
		if n, ok := VLAN(wifi); !ok || n != want {
			t.Errorf("VLAN(%q) = %d, %v, want %d", wifi, n, ok, want)
		}
	}
	for _, wifi := range []string{"vlan1", "vlan4095", "vlan1x", "vlan10:", "vlan1/", "vlan", "vlan01", "vlan12345"} {
		if n, ok := VLAN(wifi); ok {
			t.Errorf("VLAN(%q) = %d, a VLAN", wifi, n)
		}
	}
}

// TestRulesetFollowsVLANsNotListOrder: the ruleset lists devices by VLAN,
// whatever order the document lists them in, so one policy has one text.
func TestRulesetFollowsVLANsNotListOrder(t *testing.T) {
	d := fixturePolicy()
	want, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(d.Devices)
	got, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Error("the ruleset changes with the order of the document's devices")
	}
}

// TestPathsOfThePairs (NET-3): an Owner device's pair is a path from the
// whole Owner network, the paths come sorted, and a pair with a device on
// any other network than Owner, Household or Devices is refused at either
// end, not left without a path.
func TestPathsOfThePairs(t *testing.T) {
	d := fixturePolicy()
	d.Devices = append(d.Devices, policy.Device{ID: "phone", Network: policy.NetOwner})
	d.Pairs = append(d.Pairs, policy.Pair{A: "phone", B: "tv"})
	got, err := Paths(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	want := []Path{{From: "ap0.106", To: "ap0.107", Both: true}, {From: "hh0", To: "ap0.105"}, {From: "own0", To: "ap0.101"}}
	if !slices.Equal(got, want) {
		t.Errorf("paths %v, want %v", got, want)
	}
	for _, p := range []policy.Pair{{A: "a-guest", B: "printer"}, {A: "printer", B: "z-guest"}} {
		d := fixturePolicy()
		d.Devices = append(d.Devices, policy.Device{ID: "a-guest", Network: policy.NetGuests}, policy.Device{ID: "z-guest", Network: policy.NetGuests})
		d.Pairs = []policy.Pair{p}
		if paths, err := Paths(d, fixtureLayout()); !errors.Is(err, ErrPolicy) {
			t.Errorf("pair %v: paths %v (err %v)", p, paths, err)
		}
	}
}

// TestAllowSetNames: a set's names are each once and sorted, and
// AllowSets refuses what Compile refuses.
func TestAllowSetNames(t *testing.T) {
	if got := (AllowSet{Names: []string{"b.example", "a.example", "b.example"}}).names(); !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Errorf("names %v", got)
	}
	l := fixtureLayout()
	l.Trunk = ""
	if sets, err := AllowSets(fixturePolicy(), l); !errors.Is(err, ErrLayout) {
		t.Errorf("allow sets %v of a bad layout (err %v)", sets, err)
	}
}

// TestNothingCountedNoCountingMap (NET-5): with every device isolated
// there is no device traffic to count, and the ruleset declares no empty
// verdict map for it, which nft refuses.
func TestNothingCountedNoCountingMap(t *testing.T) {
	d := fixturePolicy()
	for i := range d.Devices {
		d.Devices[i].Isolated = true
	}
	got, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "vmap {  }") {
		t.Errorf("an empty verdict map:\n%s", got)
	}
}

// TestLayoutCheckBounds: Check takes an interface name of 1 to 15 bytes
// of [A-Za-z0-9_.-], not starting with a dot or dash, a trunk of up to
// 10 bytes (so Trunk.4094 fits in 15) and only plain access point
// addresses, and refuses one byte or character past each.
func TestLayoutCheckBounds(t *testing.T) {
	ok := map[string]func(*Layout){
		"trunk of 10":     func(l *Layout) { l.Trunk = "trunk-port" },
		"name of 15":      func(l *Layout) { l.APMgmt = "abcdefghijklmno" },
		"every character": func(l *Layout) { l.APMgmt = "azAZ09_.-" },
	}
	for name, mut := range ok {
		l := fixtureLayout()
		mut(&l)
		if err := l.Check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]func(*Layout){
		"name of 16":   func(l *Layout) { l.APMgmt = "abcdefghijklmnop" },
		"empty name":   func(l *Layout) { l.APMgmt = "" },
		"leading dot":  func(l *Layout) { l.APMgmt = ".apm" },
		"leading dash": func(l *Layout) { l.APMgmt = "-apm" },
		"no address":   func(l *Layout) { l.APAdmin = []netip.Addr{{}} },
		"mapped":       func(l *Layout) { l.APAdmin = []netip.Addr{netip.MustParseAddr("::ffff:10.70.0.2")} },
		"zoned":        func(l *Layout) { l.APAdmin = []netip.Addr{netip.MustParseAddr("fe80::2%apm0")} },
	}
	for _, c := range "`{@[/: \"" {
		bad["character "+string(c)] = func(l *Layout) { l.APMgmt = "ap" + string(c) }
	}
	for name, mut := range bad {
		l := fixtureLayout()
		mut(&l)
		if err := l.Check(); !errors.Is(err, ErrLayout) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
