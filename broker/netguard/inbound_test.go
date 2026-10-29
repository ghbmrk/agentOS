package netguard

// REQ: DEV-2, REV-5, DEV-net-e

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// pkt is one inbound packet, as the rendered rules see it.
type pkt struct {
	iif         string
	src         netip.Addr
	proto       string // tcp, udp, icmpv6
	sport       uint16
	dport       uint16
	established bool
	icmp6       string
	hop         uint8 // IPv6 hop limit as received
}

func inList(s, v string) bool {
	s = strings.TrimSpace(strings.Trim(s, "{} "))
	for _, e := range strings.Split(s, ",") {
		if strings.TrimSpace(e) == v {
			return true
		}
	}
	return false
}

// exemptSet returns the interfaces the rendered exempt set lists.
func exemptSet(t *testing.T, rules string) map[string]bool {
	t.Helper()
	i := strings.Index(rules, "elements = {")
	if i < 0 {
		t.Fatalf("no exempt set:\n%s", rules)
	}
	rest := rules[i+len("elements = {"):]
	rest = rest[:strings.Index(rest, "}")]
	m := map[string]bool{}
	for _, e := range strings.Split(rest, ",") {
		m[strings.Trim(strings.TrimSpace(e), `"`)] = true
	}
	return m
}

// verdict parses the rendered input chain and returns the verdict of the
// first rule whose matches all hold, or accept when none does (the chain
// policy). page is the page set's content, as InboundPageAdmit loads it
// (empty as rendered). It understands only the forms InboundRules renders
// and fails on any other.
func verdict(t *testing.T, rules string, p pkt, page ...string) string {
	t.Helper()
	return linkVerdict(t, rules, p, nil, page...)
}

// linkVerdict is verdict with link as the link set's content, as the link's
// units load it (empty as rendered).
func linkVerdict(t *testing.T, rules string, p pkt, link []string, page ...string) string {
	t.Helper()
	ex := exemptSet(t, rules)
	pg, lk := map[string]bool{}, map[string]bool{}
	for _, u := range page {
		pg[u] = true
	}
	for _, u := range link {
		lk[u] = true
	}
	in := false
	for _, ln := range strings.Split(rules, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "type filter hook input") {
			in = true
			continue
		}
		if !in || ln == "" {
			continue
		}
		if ln == "}" {
			break
		}
		verdictWord := ln[strings.LastIndex(ln, " ")+1:]
		body := strings.TrimSpace(strings.TrimSuffix(ln, verdictWord))
		ok := true
		for body != "" && ok {
			switch {
			case strings.HasPrefix(body, "iifname @exempt"):
				ok = ex[p.iif]
				body = strings.TrimSpace(strings.TrimPrefix(body, "iifname @exempt"))
			case strings.HasPrefix(body, "ct state established,related"):
				ok = p.established
				body = strings.TrimSpace(strings.TrimPrefix(body, "ct state established,related"))
			case strings.HasPrefix(body, "ip6 saddr fe80::/10"):
				ok = p.src.Is6() && netip.MustParsePrefix("fe80::/10").Contains(p.src)
				body = strings.TrimSpace(strings.TrimPrefix(body, "ip6 saddr fe80::/10"))
			case strings.HasPrefix(body, "ip6 hoplimit 255"):
				ok = p.src.Is6() && p.hop == 255
				body = strings.TrimSpace(strings.TrimPrefix(body, "ip6 hoplimit 255"))
			case strings.HasPrefix(body, "icmpv6 type "):
				set := body[len("icmpv6 type "):]
				ok = p.proto == "icmpv6" && inList(set, p.icmp6)
				body = ""
			case strings.HasPrefix(body, "udp sport "):
				f := strings.Fields(body)
				ok = p.proto == "udp" && f[2] == strconv.Itoa(int(p.sport))
				body = strings.TrimSpace(strings.TrimPrefix(body, "udp sport "+f[2]))
			case strings.HasPrefix(body, "udp dport "):
				f := strings.Fields(body)
				ok = p.proto == "udp" && f[2] == strconv.Itoa(int(p.dport))
				body = strings.TrimSpace(strings.TrimPrefix(body, "udp dport "+f[2]))
			case strings.HasPrefix(body, "iifname @link"):
				ok = lk[p.iif]
				body = strings.TrimSpace(strings.TrimPrefix(body, "iifname @link"))
			case strings.HasPrefix(body, "iifname @page"):
				ok = pg[p.iif]
				body = strings.TrimSpace(strings.TrimPrefix(body, "iifname @page"))
			case strings.HasPrefix(body, "ip saddr { "):
				set, rest, _ := strings.Cut(strings.TrimPrefix(body, "ip saddr { "), " }")
				ok = false
				for _, e := range strings.Split(set, ",") {
					if pre := netip.MustParsePrefix(strings.TrimSpace(e)); p.src.Is4() && pre.Contains(p.src) {
						ok = true
					}
				}
				body = strings.TrimSpace(rest)
			case strings.HasPrefix(body, "ip saddr "), strings.HasPrefix(body, "ip6 saddr "):
				f := strings.Fields(body)
				ok = p.src == netip.MustParseAddr(f[2])
				body = strings.TrimSpace(strings.TrimPrefix(body, f[0]+" "+f[1]+" "+f[2]))
			case strings.HasPrefix(body, "tcp dport "):
				set := strings.TrimSpace(strings.TrimPrefix(body, "tcp dport "))
				ok = p.proto == "tcp" && inList(set, strconv.Itoa(int(p.dport)))
				body = ""
			default:
				t.Fatalf("rule form not understood: %q", ln)
			}
		}
		if ok {
			return verdictWord
		}
	}
	return "accept"
}

func render(t *testing.T, c Inbound) string {
	t.Helper()
	r, err := InboundRules(c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A14 acceptance 1: an unlisted source and port from the home network is
// dropped; replies and the host's own link configuration pass.
func TestInboundDropsUnlistedSourceAndPort(t *testing.T) {
	r := render(t, Inbound{})
	lan := netip.MustParseAddr("192.168.1.50")
	for _, port := range []uint16{22, 80, 443, 8080, 5353, 1900, 5540, 18789} {
		for _, proto := range []string{"tcp", "udp"} {
			if v := verdict(t, r, pkt{iif: "eth0", src: lan, proto: proto, sport: 40000, dport: port}); v != "drop" {
				t.Errorf("%s/%d from the LAN: %s, want drop", proto, port, v)
			}
		}
	}
	if v := verdict(t, r, pkt{iif: "eth0", src: lan, proto: "icmpv6", icmp6: "echo-request"}); v != "drop" {
		t.Errorf("echo request: %s", v)
	}
	// Replies pass.
	if v := verdict(t, r, pkt{iif: "eth0", src: lan, proto: "tcp", sport: 443, dport: 40000, established: true}); v != "accept" {
		t.Errorf("established reply: %s", v)
	}
	// Link configuration passes, from the right source and port only.
	ll := netip.MustParseAddr("fe80::1")
	if v := verdict(t, r, pkt{iif: "eth0", src: ll, proto: "icmpv6", icmp6: "nd-router-advert", hop: 255}); v != "accept" {
		t.Errorf("router advert: %s", v)
	}
	if v := verdict(t, r, pkt{iif: "eth0", src: netip.MustParseAddr("2001:db8::9"), proto: "icmpv6", icmp6: "nd-router-advert", hop: 255}); v != "drop" {
		t.Errorf("router advert from a global source: %s", v)
	}
	if v := verdict(t, r, pkt{iif: "eth0", src: lan, proto: "udp", sport: 67, dport: 68}); v != "accept" {
		t.Errorf("dhcp reply: %s", v)
	}
	if v := verdict(t, r, pkt{iif: "eth0", src: lan, proto: "udp", sport: 67, dport: 5353}); v != "drop" {
		t.Errorf("udp from port 67 to another port: %s", v)
	}
	if v := verdict(t, r, pkt{iif: "eth0", src: ll, proto: "udp", sport: 547, dport: 546}); v != "accept" {
		t.Errorf("dhcpv6 reply: %s", v)
	}
}

// DEV-net-e 2a: an interface nobody listed (a USB tether, a second NIC, a
// renamed wlan) gets the same drop; only loopback and named exemptions pass.
func TestInboundDropsOnUnlistedInterfaces(t *testing.T) {
	lan := netip.MustParseAddr("192.168.1.50")
	r := render(t, Inbound{})
	for _, iif := range []string{"eth0", "eth1", "usb0", "wlan0", "enp3s0", "wwan0"} {
		if v := verdict(t, r, pkt{iif: iif, src: lan, proto: "tcp", dport: 22}); v != "drop" {
			t.Errorf("%s: %s, want drop", iif, v)
		}
	}
	if v := verdict(t, r, pkt{iif: "lo", src: netip.MustParseAddr("127.0.0.1"), proto: "tcp", dport: 22}); v != "accept" {
		t.Errorf("loopback: %s", v)
	}
	r = render(t, Inbound{Exempt: []string{"wlan0"}})
	if v := verdict(t, r, pkt{iif: "wlan0", src: lan, proto: "tcp", dport: 22}); v != "accept" {
		t.Errorf("exempt access point: %s (agentos_ap governs it)", v)
	}
	if v := verdict(t, r, pkt{iif: "usb0", src: lan, proto: "tcp", dport: 22}); v != "drop" {
		t.Errorf("usb0 with wlan0 exempt: %s", v)
	}
}

// DEV-net-e 2a: neighbour discovery from a global source passes, so the box
// keeps IPv6 on links whose router solicits from its global address; nothing
// that was routed (hop limit below 255) passes as neighbour discovery.
func TestInboundNeighbourDiscovery(t *testing.T) {
	r := render(t, Inbound{})
	glob := netip.MustParseAddr("2a02:aaaa:bbbb:cc00::1")
	for _, ty := range []string{"nd-neighbor-solicit", "nd-neighbor-advert"} {
		if v := verdict(t, r, pkt{iif: "eth0", src: glob, proto: "icmpv6", icmp6: ty, hop: 255}); v != "accept" {
			t.Errorf("%s from a global source: %s", ty, v)
		}
		if v := verdict(t, r, pkt{iif: "eth0", src: netip.MustParseAddr("fe80::1"), proto: "icmpv6", icmp6: ty, hop: 255}); v != "accept" {
			t.Errorf("%s from link-local: %s", ty, v)
		}
		if v := verdict(t, r, pkt{iif: "eth0", src: glob, proto: "icmpv6", icmp6: ty, hop: 64}); v != "drop" {
			t.Errorf("%s with hop limit 64: %s", ty, v)
		}
	}
	if v := verdict(t, r, pkt{iif: "eth0", src: netip.MustParseAddr("fe80::1"), proto: "icmpv6", icmp6: "nd-router-advert", hop: 64}); v != "drop" {
		t.Errorf("router advert with hop limit 64: %s", v)
	}
	for _, s := range []string{"ip6 hoplimit 255 icmpv6 type nd-router-advert", "ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert }"} {
		if !strings.Contains(r, s) {
			t.Errorf("rules lack %q:\n%s", s, r)
		}
	}
}

func TestInboundHooksAdmitOnlyWhatIsListed(t *testing.T) {
	dev := netip.MustParseAddr("192.168.1.60")
	r := render(t, Inbound{
		Devices:   []DeviceAllow{{Addr: dev, TCPPorts: []uint16{8443}}},
		Discovery: []DiscoveryPort{DiscoverMDNS},
	})
	cases := []struct {
		p    pkt
		want string
	}{
		{pkt{iif: "eth0", src: dev, proto: "tcp", dport: 8443}, "accept"},
		{pkt{iif: "eth1", src: dev, proto: "tcp", dport: 8443}, "accept"},
		{pkt{iif: "eth0", src: dev, proto: "tcp", dport: 22}, "drop"},
		{pkt{iif: "eth0", src: netip.MustParseAddr("192.168.1.61"), proto: "tcp", dport: 8443}, "drop"},
		{pkt{iif: "eth0", src: dev, proto: "udp", dport: 8443}, "drop"},
		{pkt{iif: "eth0", src: netip.MustParseAddr("192.168.1.61"), proto: "udp", dport: 5353}, "accept"},
		{pkt{iif: "eth0", src: dev, proto: "udp", dport: 1900}, "drop"},
	}
	for _, c := range cases {
		if got := verdict(t, r, c.p); got != c.want {
			t.Errorf("%+v: %s, want %s", c.p, got, c.want)
		}
	}
}

func TestInboundHooksEmptyAtRelease(t *testing.T) {
	r := render(t, Inbound{})
	for _, w := range []string{"5353", "1900", "5540", "tcp dport"} {
		if strings.Contains(r, w) {
			t.Errorf("default rules mention %q:\n%s", w, r)
		}
	}
	if !strings.Contains(r, "    drop\n  }") {
		t.Errorf("no final drop:\n%s", r)
	}
	if ex := exemptSet(t, r); len(ex) != 1 || !ex["lo"] {
		t.Errorf("default exempt set %v, want only lo", ex)
	}
}

func TestInboundValidation(t *testing.T) {
	ok := netip.MustParseAddr("192.168.1.60")
	bad := []Inbound{
		{Exempt: []string{`wlan0"; accept`}},
		{Exempt: []string{""}},
		{Devices: []DeviceAllow{{Addr: ok}}},
		{Devices: []DeviceAllow{{Addr: ok, TCPPorts: []uint16{0}}}},
		{Devices: []DeviceAllow{{Addr: netip.IPv4Unspecified(), TCPPorts: []uint16{80}}}},
		{Devices: []DeviceAllow{{Addr: netip.MustParseAddr("224.0.0.251"), TCPPorts: []uint16{80}}}},
		{Discovery: []DiscoveryPort{"telnet"}},
	}
	for i, c := range bad {
		if _, err := InboundRules(c); err == nil {
			t.Errorf("case %d: accepted", i)
		}
	}
	if _, err := InboundRules(Inbound{}); err != nil {
		t.Errorf("zero value: %v", err)
	}
}

// When nft is usable here, it must accept what is rendered. The syntax
// check needs no privilege on most hosts and is skipped where it fails.
func TestInboundRulesAreValidNft(t *testing.T) {
	path, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	r := render(t, Inbound{
		Exempt:    []string{"wlan0"},
		Devices:   []DeviceAllow{{Addr: netip.MustParseAddr("192.168.1.60"), TCPPorts: []uint16{8443, 8444}}, {Addr: netip.MustParseAddr("2001:db8::60"), TCPPorts: []uint16{80}}},
		Discovery: []DiscoveryPort{DiscoverMDNS, DiscoverSSDP, DiscoverMatter},
		Page:      true,
		Link:      true,
	})
	admit, err := InboundPageAdmit("enp1s0")
	if err != nil {
		t.Fatal(err)
	}
	r += admit + InboundPageClose
	f := filepath.Join(t.TempDir(), "in.nft")
	if err := os.WriteFile(f, []byte(r), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(path, "-c", "-f", f).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "Permission denied") {
			t.Skipf("nft cannot run here: %s", out)
		}
		t.Fatalf("nft -c: %v\n%s\n%s", err, out, r)
	}
}

// imageRules is the file the image loads at boot (agentos-inbound.service).
const imageRules = "../../image/mkosi/mkosi.extra/usr/lib/agentos/inbound.nft"

// DEV-net-e 2a: the image loads exactly the rules of Image (the zero value,
// the owner page's ports, WIFI-del-a3, and the edge link's port,
// EDGE-link-core c2c), after its header comment.
// Regenerate with AGENTOS_WRITE_INBOUND=1 go test ./netguard.
func TestInboundImageFileIsTheDefault(t *testing.T) {
	if Image.Devices != nil || Image.Discovery != nil || Image.Exempt != nil || !Image.Page || !Image.Link {
		t.Fatalf("the image's rules are not the zero value, the page and the link: %+v", Image)
	}
	want := render(t, Image)
	if os.Getenv("AGENTOS_WRITE_INBOUND") == "1" {
		hdr := "#!/usr/sbin/nft -f\n" +
			"# Generated from broker/netguard InboundRules(Image); TestInboundImageFileIsTheDefault\n" +
			"# checks it. agentos-inbound.service loads it before any network or listener (DEV-net-e 2a).\n"
		if err := os.WriteFile(imageRules, []byte(hdr+want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(imageRules)
	if err != nil {
		t.Fatal(err)
	}
	var body []string
	for _, ln := range strings.SplitAfter(string(b), "\n") {
		if len(body) == 0 && strings.HasPrefix(ln, "#") {
			continue
		}
		body = append(body, ln)
	}
	if got := strings.Join(body, ""); got != want {
		t.Errorf("%s differs from InboundRules(Image); regenerate it.\ngot:\n%s\nwant:\n%s", imageRules, got, want)
	}
}

// REQ: DEV-2, DEV-net-g
func TestInboundExemptRemoveIsAnIdempotentDelete(t *testing.T) {
	got, err := InboundExemptRemove("ap0")
	if err != nil {
		t.Fatal(err)
	}
	// The add makes the delete succeed when the element is already gone, in
	// one transaction, so a second removal is not an error and nothing else
	// in the set (agent-machine links) is touched.
	want := "add element inet agentos_inbound exempt { \"ap0\" }\n" +
		"delete element inet agentos_inbound exempt { \"ap0\" }\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	for _, bad := range []string{"", "lo", "wl;x", "wl\"x", "abcdefghijklmnop"} {
		if s, err := InboundExemptRemove(bad); err == nil {
			t.Errorf("%q accepted: %q", bad, s)
		}
	}
}

// forwardVerdict parses the forward chain of the rendered table of the
// given family and returns the verdict for a packet routed (inet) or
// bridged (bridge) from iif to oif: the first rule whose matches hold, else
// the chain policy. Like verdict, it understands only what InboundRules
// renders.
func forwardVerdict(t *testing.T, rules, family, iif, oif string) string {
	t.Helper()
	ex := exemptSet(t, rules)
	tbl, inTable, inChain, policy := "table "+family+" "+InboundTable+" {", false, false, ""
	for _, ln := range strings.Split(rules, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == tbl:
			inTable = true
			continue
		case !inTable:
			continue
		case strings.HasPrefix(ln, "type filter hook forward priority filter; policy "):
			inChain, policy = true, strings.TrimSuffix(strings.TrimPrefix(ln, "type filter hook forward priority filter; policy "), ";")
			continue
		case !inChain:
			continue
		case ln == "}":
			return policy
		case ln == "iifname @exempt accept":
			if ex[iif] {
				return "accept"
			}
		case ln == "oifname @exempt accept":
			if ex[oif] {
				return "accept"
			}
		default:
			t.Fatalf("forward rule form not understood: %q", ln)
		}
	}
	t.Fatalf("no %s forward chain:\n%s", family, rules)
	return ""
}

// REQ: DEV-2, CH-9
// I21 (#2824): the box routes nothing. Whatever turns forwarding on (a
// NetworkManager shared or access-point profile written by a compromised
// netjoin helper, a sysctl), a packet routed or bridged between the home
// network's links, or onto an interface nobody named, is dropped. Only a
// packet entering or leaving an exempt interface is left to the table that
// governs it (agentos_ap, whose passthrough must still work).
func TestInboundDropsEveryForwardedPacket(t *testing.T) {
	zero := render(t, Inbound{})
	for _, l := range [][2]string{{"eth0", "usb0"}, {"wlsta0", "wlsta0"}, {"wlsta0", "eth0"}, {"usb0", "wlan1"}} {
		if v := forwardVerdict(t, zero, "inet", l[0], l[1]); v != "drop" {
			t.Errorf("inet %s -> %s: %s, want drop", l[0], l[1], v)
		}
		if v := forwardVerdict(t, zero, "bridge", l[0], l[1]); v != "drop" {
			t.Errorf("bridge %s -> %s: %s, want drop", l[0], l[1], v)
		}
	}
	ap := render(t, Inbound{Exempt: []string{"ap0"}})
	for _, l := range [][2]string{{"ap0", "eth0"}, {"eth0", "ap0"}} {
		if v := forwardVerdict(t, ap, "inet", l[0], l[1]); v != "accept" {
			t.Errorf("exempt ap0, inet %s -> %s: %s, want accept (agentos_ap governs it)", l[0], l[1], v)
		}
	}
	for _, l := range [][2]string{{"eth0", "usb0"}, {"wlsta0", "eth0"}} {
		if v := forwardVerdict(t, ap, "inet", l[0], l[1]); v != "drop" {
			t.Errorf("exempt ap0, inet %s -> %s: %s, want drop", l[0], l[1], v)
		}
	}
	for _, l := range [][2]string{{"ap0", "eth0"}, {"eth0", "ap0"}} {
		if v := forwardVerdict(t, ap, "bridge", l[0], l[1]); v != "drop" {
			t.Errorf("exempt ap0, bridge %s -> %s: %s, want drop (nothing on the box bridges)", l[0], l[1], v)
		}
	}
}

// admitted is the page set's content after script, a run of
// InboundPageAdmit or InboundPageClose on a set that held before: it
// understands only a flush of the page set and an add of one element.
func admitted(t *testing.T, before []string, script string) []string {
	t.Helper()
	set := append([]string(nil), before...)
	for _, ln := range strings.Split(strings.TrimSpace(script), "\n") {
		switch {
		case ln == "flush set inet agentos_inbound page":
			set = nil
		case strings.HasPrefix(ln, "add element inet agentos_inbound page { \"") && strings.HasSuffix(ln, "\" }"):
			set = append(set, strings.TrimSuffix(strings.TrimPrefix(ln, "add element inet agentos_inbound page { \""), "\" }"))
		default:
			t.Fatalf("script line not understood: %q", ln)
		}
	}
	return set
}

// HW12-port1-set (CH-9, HW-15, D-178): with Page, the inbound table admits
// the owner page's two ports from private IPv4 sources only on the
// interface the page set holds, port 1, since the enforcer routes the
// Owner network to it from another subnet. Every other link drops them at
// the firewall, Ethernet-named ones too (the edge's USB cable, a dongle,
// Thunderbolt, a second fixed port), as do the access point, radios, a
// public, IPv6 or CGNAT source, another TCP port and UDP; the empty set,
// as the image boots, and the zero value admit none of it. A port 1 with
// a kernel eth* name is admitted once the set names it (#3350 release).
// REQ: CH-9, HW-15, HW-12
func TestInboundAdmitsThePagePortsOnlyOnPort1(t *testing.T) {
	r := render(t, Inbound{Page: true})
	zero := render(t, Inbound{})
	admit, err := InboundPageAdmit("enp1s0")
	if err != nil {
		t.Fatal(err)
	}
	port1 := admitted(t, []string{"eth0"}, admit)
	if len(port1) != 1 || port1[0] != "enp1s0" {
		t.Fatalf("the page set holds %q after admitting enp1s0", port1)
	}
	for _, c := range []struct {
		p    pkt
		want string
	}{
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("10.8.0.23"), proto: "tcp", dport: 80}, "accept"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("172.16.4.9"), proto: "tcp", dport: 443}, "accept"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("192.168.50.77"), proto: "tcp", dport: 443}, "accept"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("172.32.0.1"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("100.64.0.9"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("203.0.113.5"), proto: "tcp", dport: 443}, "drop"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("fd00::5"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("10.8.0.23"), proto: "tcp", dport: 22}, "drop"},
		{pkt{iif: "enp1s0", src: netip.MustParseAddr("10.8.0.23"), proto: "udp", dport: 443}, "drop"},
		{pkt{iif: "enx001122334455", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 443}, "drop"},
		{pkt{iif: "enp0s20f0u1", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "eno1", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 443}, "drop"},
		{pkt{iif: "enp1s0f1", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "eth0", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "usb0", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 443}, "drop"},
		{pkt{iif: "wlsta0", src: netip.MustParseAddr("192.168.77.1"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "wlan0", src: netip.MustParseAddr("10.42.0.23"), proto: "tcp", dport: 443}, "drop"},
		{pkt{iif: "ap0", src: netip.MustParseAddr("10.42.0.23"), proto: "tcp", dport: 80}, "drop"},
		{pkt{iif: "ap0", src: netip.MustParseAddr("192.168.4.2"), proto: "tcp", dport: 443}, "drop"},
	} {
		if v := verdict(t, r, c.p, port1...); v != c.want {
			t.Errorf("%+v: %s, want %s", c.p, v, c.want)
		}
		if v := verdict(t, r, c.p); v != "drop" {
			t.Errorf("the empty page set admits %+v: %s", c.p, v)
		}
		if v := verdict(t, zero, c.p, port1...); v != "drop" {
			t.Errorf("zero value admits %+v: %s", c.p, v)
		}
	}
	eth, err := InboundPageAdmit("eth0")
	if err != nil {
		t.Fatal(err)
	}
	p := pkt{iif: "eth0", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 443}
	if v := verdict(t, r, p, admitted(t, port1, eth)...); v != "accept" {
		t.Errorf("a port 1 named eth0, admitted: %s, want accept", v)
	}
	if v := verdict(t, r, pkt{iif: "enp1s0", src: p.src, proto: "tcp", dport: 443}, admitted(t, port1, eth)...); v != "drop" {
		t.Errorf("the previous port 1 still admitted after eth0 replaced it: %s", v)
	}
	if got := admitted(t, port1, InboundPageClose); len(got) != 0 {
		t.Errorf("closing left %q in the page set", got)
	}
	if strings.Contains(r, `"en*"`) || strings.Contains(r, "*\"") {
		t.Errorf("the page rule still matches a wildcard interface name:\n%s", r)
	}
}

// HW12-port1-set (CH-9): admitting port 1 replaces the page set's content
// with exactly one name in one transaction, and refuses names no interface
// may carry or that the page must never serve on.
// REQ: CH-9
func TestInboundPageAdmitHoldsOneName(t *testing.T) {
	s, err := InboundPageAdmit("enp1s0")
	if err != nil {
		t.Fatal(err)
	}
	want := "flush set inet agentos_inbound page\nadd element inet agentos_inbound page { \"enp1s0\" }\n"
	if s != want {
		t.Errorf("script %q, want %q", s, want)
	}
	for _, bad := range []string{"", "lo", "enp1s0 }", "a\"b", "x;flush ruleset", "abcdefghijklmnop"} {
		if _, err := InboundPageAdmit(bad); err == nil {
			t.Errorf("admitted %q", bad)
		}
	}
	if InboundPageClose != "flush set inet agentos_inbound page\n" {
		t.Errorf("close script %q", InboundPageClose)
	}
}

// EDGE-link-core c2c (HW-15, HW-16): the edge link's port is accepted only
// on the interface in the link set, and nothing else on that interface is:
// another port, UDP, a router advertisement, a DHCP reply, the page's
// ports even if that interface were in the page set, or anything if it
// were exempt. Replies and neighbour discovery on it pass, so the link
// works. The port is dropped on every other interface, and everywhere
// while the set is empty (as the image boots, and once the link's unit
// stops) or the rule is not rendered. agentos-link binds the same port to
// the same interface (its TestListensOnTheLinkInterfaceOnly), so the two
// checks hold the link to one port on one cable.
// Revert mutants: dropping the "iifname @link drop" line admits the RA,
// the DHCP reply and the page's ports on the link; moving the link block
// after "iifname @exempt accept" admits everything on an exempt link;
// dropping "iifname @link" from the port rule admits the port on eth0.
// REQ: HW-15, HW-16
func TestInboundLinkPortOnTheLinkOnly(t *testing.T) {
	r := render(t, Image)
	link := []string{"agentos-link"}
	ll := netip.MustParseAddr("fe80::2")
	for _, c := range []struct {
		p    pkt
		want string
	}{
		{pkt{iif: "agentos-link", src: ll, proto: "tcp", dport: LinkPort}, "accept"},
		{pkt{iif: "agentos-link", src: netip.MustParseAddr("169.254.0.2"), proto: "tcp", dport: LinkPort}, "accept"},
		// No replies: conntrack is not per interface, so the edge could forge one for another flow.
		{pkt{iif: "agentos-link", src: ll, proto: "tcp", sport: 80, dport: 51000, established: true}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "icmpv6", icmp6: "nd-neighbor-solicit", hop: 255}, "accept"},
		{pkt{iif: "agentos-link", src: ll, proto: "icmpv6", icmp6: "nd-neighbor-advert", hop: 255}, "accept"},
		{pkt{iif: "agentos-link", src: ll, proto: "icmpv6", icmp6: "nd-neighbor-solicit", hop: 64}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "icmpv6", icmp6: "nd-router-advert", hop: 255}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "icmpv6", icmp6: "echo-request", hop: 64}, "drop"},
		{pkt{iif: "agentos-link", src: netip.MustParseAddr("169.254.0.2"), proto: "udp", sport: 67, dport: 68}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "udp", sport: 547, dport: 546}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "tcp", dport: LinkPort + 1}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "tcp", dport: 22}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "udp", dport: LinkPort}, "drop"},
		{pkt{iif: "agentos-link", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 443}, "drop"},
		{pkt{iif: "agentos-link", src: ll, proto: "udp", dport: 5353}, "drop"},
		{pkt{iif: "eth0", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: LinkPort}, "drop"},
		{pkt{iif: "enp1s0", src: ll, proto: "tcp", dport: LinkPort}, "drop"},
		{pkt{iif: "usb0", src: ll, proto: "tcp", dport: LinkPort}, "drop"},
	} {
		if v := linkVerdict(t, r, c.p, link); v != c.want {
			t.Errorf("%+v: %s, want %s", c.p, v, c.want)
		}
		if c.p.established {
			continue
		}
		if v := linkVerdict(t, r, c.p, nil); c.p.iif == "agentos-link" && c.p.dport == LinkPort && c.p.proto == "tcp" && v != "drop" {
			t.Errorf("the empty link set admits %+v: %s", c.p, v)
		}
		if v := linkVerdict(t, render(t, Inbound{Page: true}), c.p, link); c.p.dport == LinkPort && v != "drop" {
			t.Errorf("without Link, %+v: %s", c.p, v)
		}
	}
	// The page set or the exempt set naming the link opens nothing more on it.
	page := pkt{iif: "agentos-link", src: netip.MustParseAddr("192.168.1.9"), proto: "tcp", dport: 443}
	if v := linkVerdict(t, r, page, link, "agentos-link"); v != "drop" {
		t.Errorf("the page's port on the link, with the link in the page set: %s", v)
	}
	ex := render(t, Inbound{Page: true, Link: true, Exempt: []string{"agentos-link"}})
	if v := linkVerdict(t, ex, pkt{iif: "agentos-link", src: ll, proto: "tcp", dport: 22}, link); v != "drop" {
		t.Errorf("port 22 on an exempt link: %s", v)
	}
	if !strings.Contains(r, "  set link {\n    type ifname\n  }\n") {
		t.Errorf("the link set is not rendered empty:\n%s", r)
	}
}
