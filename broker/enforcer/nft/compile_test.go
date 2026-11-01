package nft

// REQ: NET-3, NET-2, NET-1

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
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
	if !haveNetns(t) {
		return
	}
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
	d.Devices[0].Allow = []string{`y{accept}`}
	got, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
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
		// The connection marks are TestEveryAcceptBound's.
		return strings.Contains(markSet.ReplaceAllString(got, ""), s)
	}
	d := fixturePolicy()
	tvNet := `iifname "ap0.101" oifname "wan0" ip daddr @d101_4 accept`
	edgeTV := `iifname "edge0" oifname "ap0.101"`
	coreSpk := `iifname "core0" oifname "ap0.102"`
	pair := `iifname "ap0.106" oifname "ap0.107" accept`
	people := `iifname "hh0" oifname "ap0.105" accept`
	for _, s := range []string{tvNet, edgeTV, coreSpk, pair, people} {
		if !has(d, s) {
			t.Errorf("fixture lacks %q", s)
		}
	}
	for _, s := range []string{`"ap0.104" oifname "wan0"`, `oifname "ap0.103" log`, `oifname "ap0.104" log`, `"ap0.108"`, `iifname "ap0.105" oifname "hh0" accept`} {
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
		`iifname "edge0" oifname "ap0.101" tcp dport { 80 } log`,
		`iifname "core0" oifname "ap0.102" tcp dport { 80 } log`,
		`iifname "core0" oifname "ap0.102" udp dport { 123 } log`,
		`iifname "core0" oifname "ap0.104" tcp dport { 554 } log prefix "enf core-stream 104 " counter name "core_stream" accept`,
	} {
		if !has(d, s) {
			t.Errorf("fixture lacks %q", s)
		}
	}
	for _, s := range []string{`oifname "ap0.105" log`, `oifname "ap0.105" tcp`, `oifname "ap0.104" tcp dport { 80 }`, `oifname "ap0.103" tcp`} {
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
