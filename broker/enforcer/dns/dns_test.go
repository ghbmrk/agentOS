package dns

// REQ: NET-2, NET-3

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var update = flag.Bool("update", false, "rewrite testdata/*.conf")

// The fixture home: the core's list, two online devices whose lists share
// a name, an offline device and an isolated one; the same layout as nft's
// fixture.
func fixtureLayout() nft.Layout {
	return nft.Layout{
		WAN: "wan0", Owner: "own0", Household: "hh0", Guests: "gst0", Admin: "adm0",
		Core: "core0", Edge: "edge0", Trunk: "ap0", APMgmt: "apm0",
		APAdmin:      []netip.Addr{netip.MustParseAddr("10.70.0.2")},
		ISP:          []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		EdgeGateway:  netip.MustParseAddr("10.60.0.1"),
		PagePort:     8443,
		ChannelPort:  7443,
		CorePagePort: 443,
	}
}

func fixturePolicy() policy.Document {
	return policy.Document{
		Version:      7,
		Destinations: []string{"core.example", "updates.core.example"},
		Devices: []policy.Device{
			{ID: "tv", Network: policy.NetDevices, WiFi: "vlan101", Allow: []string{"tv.example", "cdn.example"}, VendorCloud: true, Everyday: true},
			{ID: "speaker", Network: policy.NetDevices, WiFi: "vlan102", Allow: []string{"speaker.example"}, Everyday: true},
			{ID: "plug", Network: policy.NetDevices, WiFi: "vlan103", Allow: []string{"plug.example", "cdn.example"}, VendorCloud: true, Class: policy.ClassPlug, Secure: "off"},
			{ID: "old-tv", Network: policy.NetDevices, WiFi: "vlan108", Allow: []string{"old.example"}, VendorCloud: true, Everyday: true, Isolated: true},
			{ID: "lock", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"},
			{ID: "laptop", Network: policy.NetHousehold, Everyday: true},
		},
	}
}

const upstreamAddr = "198.51.100.53"

func fixtureSetup() Setup {
	nets := []Net{
		{Iface: "own0", Prefix4: netip.MustParsePrefix("10.10.0.0/24"), Prefix6: netip.MustParsePrefix("fd00:10::/64")},
		{Iface: "hh0", Prefix4: netip.MustParsePrefix("10.20.0.0/24")},
		{Iface: "gst0", Prefix4: netip.MustParsePrefix("10.30.0.0/24")},
		{Iface: "adm0", Prefix4: netip.MustParsePrefix("10.40.0.0/24")},
		{Iface: "core0", Prefix4: netip.MustParsePrefix("10.50.0.0/24")},
		{Iface: "ap0.101", Prefix4: netip.MustParsePrefix("10.101.0.0/24")},
		{Iface: "ap0.102", Prefix4: netip.MustParsePrefix("10.102.0.0/24")},
	}
	return Setup{Upstream: []netip.AddrPort{netip.MustParseAddrPort(upstreamAddr + ":53")}, Nets: nets, LeaseFile: "/var/lib/agentos-enforcer/dhcp.leases"}
}

func generate(t *testing.T) Files {
	t.Helper()
	f, err := Generate(fixturePolicy(), fixtureLayout(), fixtureSetup())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestGolden: the fixture's three files, byte for byte. Read the diff when
// it changes: these lines are what decides which names resolve and which
// sets they fill.
func TestGolden(t *testing.T) {
	f := generate(t)
	for name, got := range map[string]string{"listed.conf": f.Listed, "people.conf": f.People, "dhcp.conf": f.DHCP} {
		path := filepath.Join("testdata", name)
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s differs from testdata (run with -update and review the diff):\n%s", name, got)
		}
	}
}

// TestListedNamesOnly: the listed instance forwards only listed names,
// each exactly, and fills only the sets of the lists that name it; a
// device without internet has no set, and nothing names the edge.
// Catches a resolver that forwards any name or fills the wrong set.
func TestListedNamesOnly(t *testing.T) {
	f := generate(t)
	has := func(file, line string) bool { return strings.Contains("\n"+file, "\n"+line+"\n") }
	for _, l := range []string{
		"server=/core.example/198.51.100.53#53",
		"local=/*.core.example/",
		"nftset=/core.example/4#inet#enforcer#core_4,6#inet#enforcer#core_6",
		"nftset=/updates.core.example/4#inet#enforcer#core_4,6#inet#enforcer#core_6",
		"nftset=/tv.example/4#inet#enforcer#d101_4,6#inet#enforcer#d101_6",
		"nftset=/cdn.example/4#inet#enforcer#d101_4,6#inet#enforcer#d101_6,4#inet#enforcer#d103_4,6#inet#enforcer#d103_6",
		"cache-size=0",
		"interface=core0", "interface=ap0.101", "interface=ap0.102", "interface=ap0.108",
	} {
		if !has(f.Listed, l) {
			t.Errorf("listed.conf lacks %q", l)
		}
	}
	for _, s := range []string{"speaker.example", "old.example", "server=198", "edge0", "wan0", "apm0", "own0", "gst0", "log-queries", "dhcp"} {
		if strings.Contains(f.Listed, s) {
			t.Errorf("listed.conf has %q", s)
		}
	}
	for _, s := range []string{"nftset", "edge0", "wan0", "apm0", "core0", "ap0.", "log-queries", "dhcp"} {
		if strings.Contains(f.People, s) {
			t.Errorf("people.conf has %q", s)
		}
	}
	for _, s := range []string{"edge0", "wan0", "apm0", "log-"} {
		if strings.Contains(f.DHCP, s) {
			t.Errorf("dhcp.conf has %q", s)
		}
	}
	if !has(f.DHCP, "port=0") {
		t.Error("the DHCP instance answers DNS")
	}
	// No line of any file comes from anything but the generator's own
	// words, the layout, the setup and checked names.
	for _, file := range []string{f.Listed, f.People, f.DHCP} {
		if strings.ContainsAny(file, "\r\t\"'") {
			t.Errorf("a file holds a quoting character:\n%s", file)
		}
	}
}

func TestGenerateRefuses(t *testing.T) {
	l := fixtureLayout()
	for name, mod := range map[string]func(*policy.Document, *Setup){
		"edge DHCP":      func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.Edge },
		"WAN DHCP":       func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.WAN },
		"AP mgmt DHCP":   func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.APMgmt },
		"unknown iface":  func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = "eth9" },
		"trunk itself":   func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.Trunk },
		"bad VLAN":       func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.Trunk + ".0101" },
		"net twice":      func(_ *policy.Document, s *Setup) { s.Nets[1].Iface = s.Nets[0].Iface },
		"public prefix":  func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix4 = netip.MustParsePrefix("203.0.113.0/24") },
		"unmasked":       func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix4 = netip.MustParsePrefix("10.10.0.1/24") },
		"tiny prefix":    func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix4 = netip.MustParsePrefix("10.10.0.0/30") },
		"v6 not /64":     func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix6 = netip.MustParsePrefix("fd00:10::/56") },
		"no upstream":    func(_ *policy.Document, s *Setup) { s.Upstream = nil },
		"private up":     func(_ *policy.Document, s *Setup) { s.Upstream[0] = netip.MustParseAddrPort("192.168.1.1:53") },
		"loopback up":    func(_ *policy.Document, s *Setup) { s.Upstream[0] = netip.MustParseAddrPort("127.0.0.1:53") },
		"lease relative": func(_ *policy.Document, s *Setup) { s.LeaseFile = "dhcp.leases" },
		"lease quoting":  func(_ *policy.Document, s *Setup) { s.LeaseFile = "/var/lib/a b" },
		"name upper":     func(d *policy.Document, _ *Setup) { d.Destinations = []string{"Core.example"} },
		"name wildcard":  func(d *policy.Document, _ *Setup) { d.Destinations = []string{"*.core.example"} },
		"name hash":      func(d *policy.Document, _ *Setup) { d.Devices[0].Allow = []string{"tv.example#53"} },
		"name comma":     func(d *policy.Document, _ *Setup) { d.Devices[0].Allow = []string{"a.example,b.example"} },
		"name one label": func(d *policy.Document, _ *Setup) { d.Devices[0].Allow = []string{"localhost"} },
		"name non-ASCII": func(d *policy.Document, _ *Setup) { d.Devices[0].Allow = []string{"tv.exämple"} },
		"name empty lbl": func(d *policy.Document, _ *Setup) { d.Devices[0].Allow = []string{"tv..example"} },
		"name trail dot": func(d *policy.Document, _ *Setup) { d.Devices[0].Allow = []string{"tv.example."} },
		"name long label": func(d *policy.Document, _ *Setup) {
			d.Devices[0].Allow = []string{strings.Repeat("a", 64) + ".example"}
		},
		"bad layout": func(_ *policy.Document, _ *Setup) {},
	} {
		d, s := fixturePolicy(), fixtureSetup()
		ll := l
		if name == "bad layout" {
			ll.Edge = ll.Core
		}
		mod(&d, &s)
		if _, err := Generate(d, ll, s); err == nil {
			t.Errorf("%s: generated", name)
		} else if name != "bad layout" && !strings.HasPrefix(name, "name") && !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A name the policy accepts but this package refuses still refuses a
	// whole version, so the previous configuration stays.
	d := fixturePolicy()
	d.Devices[1].Allow = []string{"Speaker.example"} // on a device with no set: not reached
	if _, err := Generate(d, l, fixtureSetup()); err != nil {
		t.Errorf("a name on a device with no allow set is never written: %v", err)
	}
}

func TestHostname(t *testing.T) {
	// The character ranges' ends, and the longest name, are accepted.
	longest := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61) // 253 bytes
	for _, ok := range []string{"a.b", "z.z", "0.9", "a0z9.b-c", "core.example", "x-1.y2.example", strings.Repeat("a", 63) + ".example", longest} {
		if !Hostname(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "a", "-a.b", "`.b", "{.b", "/.b", ":.b", longest + "a", "a-.b", "a..b", ".a.b", "a.b.", "A.b", "a_b.c", "a/b.c", "a#b.c", "a b.c", "a,b.c", "*.a.b", "a.b\n", strings.Repeat("a.", 127) + "aa"} {
		if Hostname(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestDnsmasqAccepts: dnsmasq's own syntax check passes each file.
// TestSetupBounds: the ends of what check accepts.
func TestSetupBounds(t *testing.T) {
	l := fixtureLayout()
	try := func(mod func(*Setup)) error {
		s := fixtureSetup()
		mod(&s)
		_, err := Generate(fixturePolicy(), l, s)
		return err
	}
	for bits, ok := range map[int]bool{15: false, 16: true, 28: true, 29: false} {
		p := netip.PrefixFrom(netip.MustParseAddr("10.0.0.0"), bits)
		if err := try(func(s *Setup) { s.Nets[0].Prefix4 = p }); (err == nil) != ok {
			t.Errorf("IPv4 /%d: %v", bits, err)
		}
	}
	for path, ok := range map[string]bool{"/AZ/az/09/a-b_c.d": true, "/a@b": false, "/a[b": false, "/a`b": false, "/a{b": false, "/a:b": false, "/a,b": false, "/a/../b": false} {
		if err := try(func(s *Setup) { s.LeaseFile = path }); (err == nil) != ok {
			t.Errorf("lease file %q: %v", path, err)
		}
	}
}

func TestDnsmasqAccepts(t *testing.T) {
	bin := dnsmasq(t)
	f := generate(t)
	dir := t.TempDir()
	for name, text := range map[string]string{"listed": f.Listed, "people": f.People, "dhcp": f.DHCP} {
		path := filepath.Join(dir, name+".conf")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "--test", "-C", path).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// required is true in CI, where a missing tool or kernel feature fails the
// test instead of skipping it.
func required() bool { return os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1" }

func dnsmasq(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/usr/sbin/dnsmasq", "/sbin/dnsmasq"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("dnsmasq"); err == nil {
		return p
	}
	if required() {
		t.Fatal("dnsmasq missing")
	}
	t.Skip("dnsmasq missing")
	return ""
}
