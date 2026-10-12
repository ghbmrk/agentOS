package netguard

// REQ: DEV-2, REV-5

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

// verdict parses the rendered text and returns the verdict of the first
// rule whose matches all hold, or accept when none does (the chain policy).
// It understands only the forms InboundRules renders and fails on any other.
func verdict(t *testing.T, rules string, p pkt) string {
	t.Helper()
	for _, ln := range strings.Split(rules, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "iifname ") {
			continue
		}
		rest := strings.TrimPrefix(ln, "iifname ")
		iif, rest, _ := strings.Cut(rest, " ")
		verdictWord := rest[strings.LastIndex(rest, " ")+1:]
		if strings.Trim(iif, `"`) != p.iif {
			continue
		}
		body := strings.TrimSuffix(strings.TrimSuffix(rest, verdictWord), " ")
		ok := true
		for body != "" && ok {
			switch {
			case strings.HasPrefix(body, "ct state established,related"):
				ok = p.established
				body = strings.TrimSpace(strings.TrimPrefix(body, "ct state established,related"))
			case strings.HasPrefix(body, "ip6 saddr fe80::/10"):
				ok = p.src.Is6() && netip.MustParsePrefix("fe80::/10").Contains(p.src)
				body = strings.TrimSpace(strings.TrimPrefix(body, "ip6 saddr fe80::/10"))
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
	r := render(t, Inbound{Uplinks: []string{"eth0"}})
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
	if v := verdict(t, r, pkt{iif: "eth0", src: ll, proto: "icmpv6", icmp6: "nd-router-advert"}); v != "accept" {
		t.Errorf("router advert: %s", v)
	}
	if v := verdict(t, r, pkt{iif: "eth0", src: netip.MustParseAddr("2001:db8::9"), proto: "icmpv6", icmp6: "nd-router-advert"}); v != "drop" {
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
	// Another interface is CH-9's, not this table's.
	if v := verdict(t, r, pkt{iif: "wlan0", src: lan, proto: "tcp", dport: 22}); v != "accept" {
		t.Errorf("other interface: %s", v)
	}
}

func TestInboundHooksAdmitOnlyWhatIsListed(t *testing.T) {
	dev := netip.MustParseAddr("192.168.1.60")
	r := render(t, Inbound{
		Uplinks:   []string{"eth0", "eth1"},
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
	r := render(t, Inbound{Uplinks: []string{"eth0"}})
	for _, w := range []string{"5353", "1900", "5540", "tcp dport"} {
		if strings.Contains(r, w) {
			t.Errorf("default rules mention %q:\n%s", w, r)
		}
	}
	if !strings.Contains(r, `iifname "eth0" drop`) {
		t.Errorf("no final drop:\n%s", r)
	}
}

func TestInboundValidation(t *testing.T) {
	ok := netip.MustParseAddr("192.168.1.60")
	bad := []Inbound{
		{},
		{Uplinks: []string{`eth0"; accept`}},
		{Uplinks: []string{"eth0"}, Devices: []DeviceAllow{{Addr: ok}}},
		{Uplinks: []string{"eth0"}, Devices: []DeviceAllow{{Addr: ok, TCPPorts: []uint16{0}}}},
		{Uplinks: []string{"eth0"}, Devices: []DeviceAllow{{Addr: netip.IPv4Unspecified(), TCPPorts: []uint16{80}}}},
		{Uplinks: []string{"eth0"}, Devices: []DeviceAllow{{Addr: netip.MustParseAddr("224.0.0.251"), TCPPorts: []uint16{80}}}},
		{Uplinks: []string{"eth0"}, Discovery: []DiscoveryPort{"telnet"}},
	}
	for i, c := range bad {
		if _, err := InboundRules(c); err == nil {
			t.Errorf("case %d: accepted", i)
		}
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
		Uplinks:   []string{"eth0"},
		Devices:   []DeviceAllow{{Addr: netip.MustParseAddr("192.168.1.60"), TCPPorts: []uint16{8443, 8444}}, {Addr: netip.MustParseAddr("2001:db8::60"), TCPPorts: []uint16{80}}},
		Discovery: []DiscoveryPort{DiscoverMDNS, DiscoverSSDP, DiscoverMatter},
	})
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
