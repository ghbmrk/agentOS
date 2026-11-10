package dns

// REQ: NET-2, NET-3

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/internal/netnstest"
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
		Caps:         map[string]uint64{"core.example": 1 << 40, "updates.core.example": 1 << 40},
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
	// The plug's and the isolated TV's VLANs are served with no DHCP.
	nets := []Net{
		{Iface: "own0", Prefix4: netip.MustParsePrefix("10.10.0.0/24"), Prefix6: netip.MustParsePrefix("fd00:10::/64"), DHCP: true},
		{Iface: "hh0", Prefix4: netip.MustParsePrefix("10.20.0.0/24"), DHCP: true},
		{Iface: "gst0", Prefix4: netip.MustParsePrefix("10.30.0.0/24"), DHCP: true},
		{Iface: "adm0", Prefix4: netip.MustParsePrefix("10.40.0.0/24"), DHCP: true},
		{Iface: "core0", Prefix4: netip.MustParsePrefix("10.50.0.0/24"), DHCP: true},
		{Iface: "ap0.101", Prefix4: netip.MustParsePrefix("10.101.0.0/24"), DHCP: true},
		{Iface: "ap0.102", Prefix4: netip.MustParsePrefix("10.102.0.0/24"), DHCP: true},
		{Iface: "ap0.103", Prefix4: netip.MustParsePrefix("10.103.0.0/24")},
		{Iface: "ap0.108", Prefix4: netip.MustParsePrefix("10.108.0.0/24")},
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

// TestGolden: the fixture's files, byte for byte, one per listed view.
// Read the diff when it changes: these lines are what decides which names
// resolve and which sets they fill.
func TestGolden(t *testing.T) {
	f := generate(t)
	files := map[string]string{"people.conf": f.People, "dhcp.conf": f.DHCP}
	for _, v := range f.Listed {
		files["listed-"+v.Iface+".conf"] = v.Conf
	}
	if !*update {
		have, err := filepath.Glob(filepath.Join("testdata", "*.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if len(have) != len(files) {
			t.Errorf("testdata holds %d files, the fixture makes %d", len(have), len(files))
		}
	}
	for name, got := range files {
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

func has(file, line string) bool { return strings.Contains("\n"+file, "\n"+line+"\n") }

// fillSpec is the sets an answer for name fills in allow set a, per
// family: the allow set, the name's own set and the fresh set (nft
// ENF-set-ttl-1).
func fillSpec(a nft.AllowSet, name string) string {
	p := "#inet#" + nft.Table + "#"
	return "4" + p + a.Set4 + ",4" + p + a.Named(name, false) + ",4" + p + a.Fresh(false) +
		",6" + p + a.Set6 + ",6" + p + a.Named(name, true) + ",6" + p + a.Fresh(true)
}

// fills is the nftset line that puts name's answers in the allow set set4
// (and its IPv6 twin) of the fixture and in name's own sets there.
func fills(t *testing.T, name, set4 string) string {
	t.Helper()
	sets, err := nft.AllowSets(fixturePolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range sets {
		if a.Set4 == set4 {
			return "nftset=/" + name + "/" + fillSpec(a, name)
		}
	}
	t.Fatalf("no allow set %s", set4)
	return ""
}

// TestListedNameOnce: a name a list holds twice is written once, so a
// view's configuration is the same whatever repeats the list carries.
func TestListedNameOnce(t *testing.T) {
	d := fixturePolicy()
	d.Devices[0].Allow = []string{"tv.example", "cdn.example", "tv.example"}
	f, err := Generate(d, fixtureLayout(), fixtureSetup())
	if err != nil {
		t.Fatal(err)
	}
	want := generate(t).Listed
	if len(f.Listed) != len(want) {
		t.Fatalf("%d views, want %d", len(f.Listed), len(want))
	}
	for i := range want {
		if f.Listed[i] != want[i] {
			t.Errorf("%s with a repeated name:\n%s\nwant\n%s", want[i].Iface, f.Listed[i].Conf, want[i].Conf)
		}
	}
}

// TestListedNamesOnly: each listed view answers on its own interface
// alone and forwards only its own list's names, each exactly, filling only
// its own list's set; a device without internet resolves nothing, and
// nothing names the edge. Catches a resolver that forwards any name, one
// that answers a device with another list's names (ENF-f-4), or one that
// fills the wrong set.
func TestListedNamesOnly(t *testing.T) {
	f := generate(t)
	var ifaces []string
	for _, v := range f.Listed {
		ifaces = append(ifaces, v.Iface)
	}
	if want := []string{"core0", "ap0.101", "ap0.102", "ap0.103", "ap0.108"}; !slices.Equal(ifaces, want) {
		t.Fatalf("views %v, want %v", ifaces, want)
	}
	core, d101, d102, d103, d108 := f.Listed[0].Conf, f.Listed[1].Conf, f.Listed[2].Conf, f.Listed[3].Conf, f.Listed[4].Conf
	for conf, lines := range map[string][]string{
		core: {
			"interface=core0",
			"server=/core.example/198.51.100.53#53",
			"local=/*.core.example/",
			fills(t, "core.example", "core_4"),
			fills(t, "updates.core.example", "core_4"),
		},
		d101: {
			"interface=ap0.101",
			fills(t, "tv.example", "d101_4"),
			fills(t, "cdn.example", "d101_4"),
		},
		d102: {"interface=ap0.102"},
		d103: {
			"interface=ap0.103",
			fills(t, "plug.example", "d103_4"),
			fills(t, "cdn.example", "d103_4"),
		},
		d108: {"interface=ap0.108"},
	} {
		for _, l := range append(lines, "cache-size=0", "max-ttl=300", "no-resolv") {
			if !has(conf, l) {
				t.Errorf("listed view lacks %q:\n%s", l, conf)
			}
		}
		if n := strings.Count(conf, "\ninterface="); n != 1 {
			t.Errorf("listed view answers on %d interfaces:\n%s", n, conf)
		}
	}
	for conf, absent := range map[string][]string{
		core: {"tv.example", "cdn.example", "plug.example", "d10"},
		d101: {"core.example", "plug.example", "core_", "d103", "d102", "d108"},
		d102: {"server=", "nftset", "speaker.example"},
		d103: {"core.example", "tv.example", "core_", "d101"},
		d108: {"server=", "nftset", "old.example"},
	} {
		for _, s := range append(absent, "server=198", "edge0", "wan0", "apm0", "own0", "gst0", "log-queries", "dhcp") {
			if strings.Contains(conf, s) {
				t.Errorf("listed view has %q:\n%s", s, conf)
			}
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
	for _, file := range append(confs(f), f.People, f.DHCP) {
		if strings.ContainsAny(file, "\r\t\"'") {
			t.Errorf("a file holds a quoting character:\n%s", file)
		}
	}
}

func confs(f Files) []string {
	var out []string
	for _, v := range f.Listed {
		out = append(out, v.Conf)
	}
	return out
}

// TestViewsAreOwnLists: for any home of devices whose lists overlap, each
// device's view forwards exactly its own list's names, filling only its
// own set, and the core's view exactly the core's list. Catches a view
// that leaks a name between lists, whichever devices a home has (ENF-f-4).
func TestViewsAreOwnLists(t *testing.T) {
	named := 0
	pool := []string{"a.example", "b.example", "c.example", "d.example", "core.example"}
	for seed := range 64 {
		d := policy.Document{Version: 1, Destinations: []string{pool[seed%5], pool[(seed+2)%5]}}
		want := map[string][]string{"core0": d.Destinations}
		sets := map[string]string{"core0": nft.CoreSet(false) + "," + nft.CoreSet(true)}
		s := fixtureSetup()
		for i := range 1 + seed%4 {
			var allow []string
			for j, n := range pool {
				if (seed>>j+i)%3 == 0 {
					allow = append(allow, n)
				}
			}
			vlan := 200 + i
			id := "dev" + strconv.Itoa(i)
			dev := policy.Device{ID: id, Network: policy.NetDevices, WiFi: "vlan" + strconv.Itoa(vlan), Allow: allow, VendorCloud: true, Everyday: true}
			d.Devices = append(d.Devices, dev)
			iface := "ap0." + strconv.Itoa(vlan)
			s.Nets = append(s.Nets, Net{Iface: iface, Prefix4: netip.MustParsePrefix("10." + strconv.Itoa(vlan) + ".0.0/24")})
			if len(allow) > 0 {
				want[iface] = allow
				sets[iface] = nft.DeviceSet(vlan, false) + "," + nft.DeviceSet(vlan, true)
			}
		}
		f, err := Generate(d, fixtureLayout(), s)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		all, err := nft.AllowSets(d, fixtureLayout())
		if err != nil {
			t.Fatal(err)
		}
		setOf := map[string]nft.AllowSet{}
		for _, a := range all {
			setOf[a.Set4+","+a.Set6] = a
		}
		if len(f.Listed) != 1+len(d.Devices) {
			t.Fatalf("seed %d: %d views for %d devices", seed, len(f.Listed), len(d.Devices))
		}
		for _, v := range f.Listed {
			var got []string
			for _, ln := range strings.Split(v.Conf, "\n") {
				if rest, ok := strings.CutPrefix(ln, "nftset=/"); ok {
					name, spec, _ := strings.Cut(rest, "/")
					got = append(got, name)
					named++
					a := setOf[sets[v.Iface]]
					if spec != fillSpec(a, name) {
						t.Errorf("seed %d: %s fills %q", seed, v.Iface, spec)
					}
				}
			}
			w := slices.Clone(want[v.Iface])
			slices.Sort(w)
			if w = slices.Compact(w); !slices.Equal(got, w) {
				t.Errorf("seed %d: %s resolves %v, want %v", seed, v.Iface, got, w)
			}
		}
	}
	if named < 200 {
		t.Errorf("only %d names across every view: the homes test too little", named)
	}
}

func TestGenerateRefuses(t *testing.T) {
	l := fixtureLayout()
	type mod = func(*policy.Document, *Setup)
	// Each case names the text of the check that must refuse it, so a
	// case cannot pass on some other refusal.
	host := func(n string) string { return fmt.Sprintf("%q is not a DNS host name", n) }
	allow := func(n string) mod { return func(d *policy.Document, _ *Setup) { d.Devices[0].Allow = []string{n} } }
	// The core's list, with the cap the policy requires of a destination.
	dest := func(n string) mod {
		return func(d *policy.Document, _ *Setup) {
			d.Destinations = []string{n}
			d.Caps = map[string]uint64{n: 1 << 40}
		}
	}
	long := strings.Repeat("a", 64) + ".example"
	for name, c := range map[string]struct {
		want string
		mod  mod
	}{
		"edge DHCP":     {`"edge0" is not a served network`, func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.Edge }},
		"WAN DHCP":      {`"wan0" is not a served network`, func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.WAN }},
		"AP mgmt DHCP":  {`"apm0" is not a served network`, func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.APMgmt }},
		"unknown iface": {`"eth9" is not a served network`, func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = "eth9" }},
		"trunk itself":  {`"ap0" is not a served network`, func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.Trunk }},
		"bad VLAN":      {`"ap0.0101" is not a served network`, func(_ *policy.Document, s *Setup) { s.Nets[0].Iface = l.Trunk + ".0101" }},
		"net twice":     {`network "own0" twice`, func(_ *policy.Document, s *Setup) { s.Nets[1].Iface = s.Nets[0].Iface }},
		"public prefix": {"own0: IPv4 prefix 203.0.113.0/24", func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix4 = netip.MustParsePrefix("203.0.113.0/24") }},
		"unmasked":      {"own0: IPv4 prefix 10.10.0.1/24", func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix4 = netip.MustParsePrefix("10.10.0.1/24") }},
		"tiny prefix":   {"own0: IPv4 prefix 10.10.0.0/30", func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix4 = netip.MustParsePrefix("10.10.0.0/30") }},
		"v6 not /64":    {"own0: IPv6 prefix fd00:10::/56", func(_ *policy.Document, s *Setup) { s.Nets[0].Prefix6 = netip.MustParsePrefix("fd00:10::/56") }},
		"no upstream":   {"no upstream resolver", func(_ *policy.Document, s *Setup) { s.Upstream = nil }},
		"no DHCP": {"no network is served DHCP", func(_ *policy.Document, s *Setup) {
			for i := range s.Nets {
				s.Nets[i].DHCP = false
			}
		}},
		"private up":  {"upstream 192.168.1.1:53", func(_ *policy.Document, s *Setup) { s.Upstream[0] = netip.MustParseAddrPort("192.168.1.1:53") }},
		"loopback up": {"upstream 127.0.0.1:53", func(_ *policy.Document, s *Setup) { s.Upstream[0] = netip.MustParseAddrPort("127.0.0.1:53") }},
		"served v6 up": {"upstream [2001:db8:101::53]:53 is on ap0.101", func(_ *policy.Document, s *Setup) {
			s.Nets[5].Prefix6 = netip.MustParsePrefix("2001:db8:101::/64")
			s.Upstream = append(s.Upstream, netip.MustParseAddrPort("[2001:db8:101::53]:53"))
		}},
		"lease relative":  {`lease file "dhcp.leases"`, func(_ *policy.Document, s *Setup) { s.LeaseFile = "dhcp.leases" }},
		"lease quoting":   {`lease file "/var/lib/a b"`, func(_ *policy.Document, s *Setup) { s.LeaseFile = "/var/lib/a b" }},
		"name upper":      {host("Core.example"), dest("Core.example")},
		"name wildcard":   {host("*.core.example"), dest("*.core.example")},
		"name hash":       {host("tv.example#53"), allow("tv.example#53")},
		"name comma":      {host("a.example,b.example"), allow("a.example,b.example")},
		"name one label":  {host("localhost"), allow("localhost")},
		"name non-ASCII":  {host("tv.exämple"), allow("tv.exämple")},
		"name empty lbl":  {host("tv..example"), allow("tv..example")},
		"name trail dot":  {host("tv.example."), allow("tv.example.")},
		"name long label": {host(long), allow(long)},
		"bad layout":      {"bad layout", func(_ *policy.Document, _ *Setup) {}},
	} {
		d, s := fixturePolicy(), fixtureSetup()
		ll := l
		if name == "bad layout" {
			ll.Edge = ll.Core
		}
		c.mod(&d, &s)
		_, err := Generate(d, ll, s)
		switch {
		case err == nil:
			t.Errorf("%s: generated", name)
		case name != "bad layout" && !errors.Is(err, ErrConfig):
			t.Errorf("%s: not this package's refusal: %v", name, err)
		case !strings.Contains(err.Error(), c.want):
			t.Errorf("%s: refused by another check: %v, want %q", name, err, c.want)
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

// TestUpstreamOnEveryServedNet: an upstream inside any served network's
// prefix is refused, whether or not the network has DHCP, and a setup that
// leaves out any interface an instance answers on is refused, so no
// served prefix escapes the check. Catches an upstream reached through a
// served segment, where the reverse-path filter cannot tell its answers
// from a forger's (NET-2 Segments, ENF-f-5).
func TestUpstreamOnEveryServedNet(t *testing.T) {
	l := fixtureLayout()
	nets, leased := 0, 0
	for i, n := range fixtureSetup().Nets {
		s := fixtureSetup()
		s.Nets[i].Prefix6 = netip.MustParsePrefix("2001:db8:" + strconv.Itoa(i) + "::/64")
		if _, err := Generate(fixturePolicy(), l, s); err != nil {
			t.Fatalf("%s with a global /64: %v", n.Iface, err)
		}
		s.Upstream = append(s.Upstream, netip.MustParseAddrPort("[2001:db8:"+strconv.Itoa(i)+"::53]:53"))
		if _, err := Generate(fixturePolicy(), l, s); !errors.Is(err, ErrConfig) {
			t.Errorf("upstream on %s (DHCP %v): %v", n.Iface, n.DHCP, err)
		}
		s = fixtureSetup()
		s.Nets = slices.Delete(s.Nets, i, i+1)
		if _, err := Generate(fixturePolicy(), l, s); !errors.Is(err, ErrConfig) {
			t.Errorf("setup without %s: %v", n.Iface, err)
		}
		nets++
		if n.DHCP {
			leased++
		}
	}
	if nets == leased || leased == 0 {
		t.Fatalf("the fixture has %d networks, %d with DHCP: it needs both kinds", nets, leased)
	}
}

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
	// An upstream just outside a served IPv6 prefix is accepted, one at
	// either end of it is not (ENF-f-5).
	for up, ok := range map[string]bool{"2001:db8:100:ffff:ffff:ffff:ffff:ffff": true, "2001:db8:101::": false, "2001:db8:101::ffff:ffff:ffff:ffff": false, "2001:db8:102::": true} {
		err := try(func(s *Setup) {
			s.Nets[5].Prefix6 = netip.MustParsePrefix("2001:db8:101::/64")
			s.Upstream = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr(up), 53)}
		})
		if (err == nil) != ok {
			t.Errorf("upstream %s: %v", up, err)
		}
	}
	for path, ok := range map[string]bool{"/AZ/az/09/a-b_c.d": true, "/a@b": false, "/a[b": false, "/a`b": false, "/a{b": false, "/a:b": false, "/a,b": false, "/a/../b": false} {
		if err := try(func(s *Setup) { s.LeaseFile = path }); (err == nil) != ok {
			t.Errorf("lease file %q: %v", path, err)
		}
	}
}

// TestDnsmasqAccepts: dnsmasq's own syntax check passes each file.
func TestDnsmasqAccepts(t *testing.T) {
	bin := dnsmasq(t)
	f := generate(t)
	dir := t.TempDir()
	files := map[string]string{"people": f.People, "dhcp": f.DHCP}
	for _, v := range f.Listed {
		files["listed-"+v.Iface] = v.Conf
	}
	for name, text := range files {
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
func required() bool { return netnstest.Required() }

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

// leaseSeconds reads a dnsmasq lease time: a number of seconds, or a
// number with an m, h, d or w suffix; "infinite" and anything else is -1.
func leaseSeconds(s string) int {
	if s == "" {
		return -1
	}
	unit := map[byte]int{'m': 60, 'h': 3600, 'd': 86400, 'w': 604800}[s[len(s)-1]]
	if unit != 0 {
		s = s[:len(s)-1]
	} else {
		unit = 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return -1
	}
	return n * unit
}

// TestLeaseCoversHold (#4702): every lease the DHCP instance writes, IPv4
// and IPv6, is at least twice nft.ClaimTimeout, so a departed host's hold
// on a shared segment has run out before its address can be leased to
// another host (ENF-shared-src-1). It reads the generated lines, not the
// constant, so a lease edited in either place fails here.
func TestLeaseCoversHold(t *testing.T) {
	var v4, v6 int
	for _, l := range strings.Split(generate(t).DHCP, "\n") {
		r, ok := strings.CutPrefix(l, "dhcp-range=")
		if !ok {
			continue
		}
		f := strings.Split(r, ",")
		if strings.Contains(f[0], ":") {
			v6++
		} else {
			v4++
		}
		if got := leaseSeconds(f[len(f)-1]); got < 2*nft.ClaimTimeout {
			t.Errorf("%s: lease %ds is under twice the %ds hold", l, got, nft.ClaimTimeout)
		}
	}
	if v4 == 0 || v6 == 0 {
		t.Fatalf("fixture leases %d IPv4 and %d IPv6 ranges; want both", v4, v6)
	}
	if leaseSeconds("11h") != 39600 || leaseSeconds("600") != 600 || leaseSeconds("infinite") != -1 || leaseSeconds("") != -1 {
		t.Fatal("leaseSeconds misreads dnsmasq lease times")
	}
}
