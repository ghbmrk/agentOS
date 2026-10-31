package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
)

// The netns tests run real dnsmasq and the real ruleset in network
// namespaces, as nft's do: the test re-runs itself as root of a fresh user
// and network namespace (unshare -rn), which is the enforcer, and gives
// the ISP side, the core, the edge and each device a namespace of its own
// joined to it by a veth pair. dnsmasq runs in debug mode (-d), which keeps
// it in the foreground and as the namespace's root, since a user namespace
// cannot drop to another user; its configuration is the generated one.

const childEnv = "AGENTOS_DNS_NETNS"

func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv(childEnv) == "1" {
		return true
	}
	for _, tool := range []string{"unshare", "nsenter", "ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			if required() {
				t.Fatalf("%s missing", tool)
			}
			t.Skipf("%s missing", tool)
		}
	}
	dnsmasq(t)
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		if required() {
			t.Fatalf("no unprivileged user namespaces: %v", err)
		}
		t.Skipf("no unprivileged user namespaces: %v", err)
	}
	args := []string{"-rn", "--", os.Args[0], "-test.run", "^" + t.Name() + "$", "-test.count=1"}
	if testing.Verbose() {
		args = append(args, "-test.v")
	}
	cmd := exec.Command("unshare", args...)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("in the enforcer's namespace:\n%s", out)
	if err != nil {
		t.Fatalf("netns run failed: %v", err)
	}
	return false
}

type host struct {
	name string
	pid  int
}

type home struct {
	t     *testing.T
	hosts map[string]*host
	// v6 is whether the kernel has IPv6; each link then also gets a
	// global /64 (see link) and its link-local addresses.
	v6 bool
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (h *home) newHost(name string) *host {
	t := h.t
	cmd := exec.Command("unshare", "-n", "sleep", "3600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	self, _ := os.Readlink("/proc/self/ns/net")
	for i := 0; ; i++ {
		ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
		if err == nil && ns != self {
			break
		}
		if i > 200 {
			t.Fatalf("%s: namespace never appeared", name)
		}
		time.Sleep(10 * time.Millisecond)
	}
	x := &host{name: name, pid: cmd.Process.Pid}
	h.hosts[name] = x
	h.in(x, "ip", "link", "set", "lo", "up")
	if h.v6 {
		h.in(x, "sh", "-c", noDAD)
	}
	return x
}

// noDAD turns duplicate address detection off in a namespace, so every
// IPv6 address, link-local ones included, is usable at once.
const noDAD = "echo 0 > /proc/sys/net/ipv6/conf/all/accept_dad && echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad"

// has6 reports whether the IPv6 checks can run; in CI a kernel with no
// IPv6 fails the test instead.
func (h *home) has6() bool {
	h.t.Helper()
	if !h.v6 {
		if required() {
			h.t.Fatal("the kernel has no IPv6")
		}
		h.t.Log("the kernel has no IPv6: the IPv6 checks do not run")
	}
	return h.v6
}

// global6 is the enforcer's global IPv6 address on the link whose IPv4
// prefix is 10.n.0.0/24: 2001:db8:n::1, its host's ::2.
func global6(p netip.Prefix) netip.Prefix {
	return netip.MustParsePrefix(fmt.Sprintf("2001:db8:%d::/64", p.Addr().As4()[1]))
}

// linkLocal is the enforcer's link-local address on ifc.
func (h *home) linkLocal(ifc string) string {
	h.t.Helper()
	i, err := net.InterfaceByName(ifc)
	if err != nil {
		h.t.Fatal(err)
	}
	as, err := i.Addrs()
	if err != nil {
		h.t.Fatal(err)
	}
	for _, a := range as {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.IsLinkLocalUnicast() && ip.IP.To4() == nil {
			return ip.IP.String()
		}
	}
	h.t.Fatalf("%s has no link-local address", ifc)
	return ""
}

func (h *home) in(x *host, args ...string) string {
	h.t.Helper()
	return run(h.t, "nsenter", append([]string{"-t", strconv.Itoa(x.pid), "-n", "--"}, args...)...)
}

// link joins x to the enforcer: the enforcer's end is ifc with the
// prefix's first host, x's end is eth0 with its second, routed through
// the enforcer.
func (h *home) link(x *host, ifc string, p netip.Prefix) {
	enf, xa := p.Addr().Next(), p.Addr().Next().Next()
	bits := "/" + strconv.Itoa(p.Bits())
	run(h.t, "ip", "link", "add", ifc, "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(x.pid))
	run(h.t, "ip", "addr", "add", enf.String()+bits, "dev", ifc)
	run(h.t, "ip", "link", "set", ifc, "up")
	h.in(x, "ip", "addr", "add", xa.String()+bits, "dev", "eth0")
	h.in(x, "ip", "link", "set", "eth0", "up")
	h.in(x, "ip", "route", "add", "default", "via", enf.String())
	if h.v6 && p.Addr().As4()[0] == 10 {
		g := global6(p)
		enf6, x6 := g.Addr().Next(), g.Addr().Next().Next()
		run(h.t, "ip", "addr", "add", enf6.String()+"/64", "dev", ifc, "nodad")
		h.in(x, "ip", "addr", "add", x6.String()+"/64", "dev", "eth0", "nodad")
		h.in(x, "ip", "-6", "route", "add", "default", "via", enf6.String())
	}
}

// within runs f with the calling thread in x's network namespace (nil:
// the enforcer's).
func within(t *testing.T, x *host, f func()) {
	if x == nil {
		f()
		return
	}
	runtime.LockOSThread()
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	target, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", x.pid))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Fatalf("setns %s: %v", x.name, err)
	}
	f()
	if unix.Setns(int(self.Fd()), unix.CLONE_NEWNET) != nil {
		return // the thread stays locked and exits with this goroutine
	}
	runtime.UnlockOSThread()
}

// The internet: the upstream resolver and the addresses it hands out,
// each a TCP listener on port 80 behind the ISP router. They are global
// addresses, since the instances refuse an answer that points into a
// private or documentation block (stop-dns-rebind).
const (
	ispRouter  = "192.168.1.1"
	enfWAN     = "192.168.1.2"
	coreAddr   = "11.0.0.30" // core.example
	subAddr    = "11.0.0.32" // sub.core.example: a subdomain of a listed name
	otherAddr  = "11.0.0.31" // unlisted.example
	tvAddr     = "11.0.0.10" // tv.example
	plugAddr   = "11.0.0.11" // plug.example
	cdnAddr    = "11.0.0.40" // cdn.example and updates.core.example
	speakerOut = "11.0.0.12" // speaker.example, on an offline device's list
)

var internet = []string{upstreamAddr, coreAddr, subAddr, otherAddr, tvAddr, plugAddr, cdnAddr, speakerOut}

const upstreamConf = `no-resolv
no-hosts
bind-interfaces
listen-address=` + upstreamAddr + `
address=/core.example/` + coreAddr + `
address=/sub.core.example/` + subAddr + `
address=/unlisted.example/` + otherAddr + `
address=/tv.example/` + tvAddr + `
address=/plug.example/` + plugAddr + `
address=/speaker.example/` + speakerOut + `
host-record=cdn.example,` + cdnAddr + `
address=/updates.core.example/` + cdnAddr + `
`

// build makes the home, loads the fixture's ruleset unless bare, and
// starts the upstream resolver.
func build(t *testing.T, bare bool) *home {
	h := &home{t: t, hosts: map[string]*host{}}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
		h.v6 = true
		run(t, "sh", "-c", noDAD)
	}
	run(t, "ip", "link", "set", "lo", "up")
	isp := h.newHost("isp")
	run(t, "ip", "link", "add", "wan0", "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(isp.pid))
	run(t, "ip", "addr", "add", enfWAN+"/24", "dev", "wan0")
	run(t, "ip", "link", "set", "wan0", "up")
	run(t, "ip", "route", "add", "default", "via", ispRouter)
	h.in(isp, "ip", "addr", "add", ispRouter+"/24", "dev", "eth0")
	h.in(isp, "ip", "link", "set", "eth0", "up")
	for _, a := range internet {
		h.in(isp, "ip", "addr", "add", a+"/32", "dev", "lo")
	}
	h.listen(isp, 80)
	l := fixtureLayout()
	for _, n := range fixtureSetup().Nets {
		h.link(h.newHost(n.Iface), n.Iface, n.Prefix4)
	}
	edge := h.newHost("edge0")
	h.link(edge, l.Edge, netip.MustParsePrefix("10.60.0.0/24"))
	if !bare {
		text, err := nft.Compile(fixturePolicy(), l)
		if err != nil {
			t.Fatal(err)
		}
		if err := (load.Loader{Bin: lookPath(t, "nft")}).Load(context.Background(), text); err != nil {
			t.Fatal(err)
		}
	}
	h.dnsmasq(isp, "upstream", upstreamConf)
	return h
}

func lookPath(t *testing.T, name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// dnsmasq starts one instance from text in x's namespace (nil: the
// enforcer's) and waits until it is up.
func (h *home) dnsmasq(x *host, name, text string) {
	t := h.t
	path := filepath.Join(t.TempDir(), name+".conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{dnsmasq(t), "-d", "-C", path}
	if x != nil {
		args = append([]string{"nsenter", "-t", strconv.Itoa(x.pid), "-n", "--"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	var log strings.Builder
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("dnsmasq %s:\n%s", name, log.String())
		}
	})
	time.Sleep(300 * time.Millisecond)
}

// listed starts every listed view.
func (h *home) listed(f Files) {
	for _, v := range f.Listed {
		h.dnsmasq(nil, "listed-"+v.Iface, v.Conf)
	}
}

func (h *home) listen(x *host, port int) {
	within(h.t, x, func() {
		ln, err := net.Listen("tcp4", ":"+strconv.Itoa(port))
		if err != nil {
			h.t.Fatal(err)
		}
		h.t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	})
}

// reaches reports whether host from completes a TCP connection to addr:80.
func (h *home) reaches(from, addr string) bool {
	ok := false
	within(h.t, h.hosts[from], func() {
		c, err := net.DialTimeout("tcp4", net.JoinHostPort(addr, "80"), 700*time.Millisecond)
		if err == nil {
			c.Close()
			ok = true
		}
	})
	return ok
}

// noAnswer is the rcode resolve reports when nothing answered.
const noAnswer = -1

// resolve asks server for name's A records from host from over UDP, and
// gives the reply's rcode and addresses.
func (h *home) resolve(from, server, name string) (int, []string) {
	return h.ask(from, "udp", server, name)
}

// ask asks server (an IPv6 one may carry a zone) for name's A records from
// host from over network, udp or tcp, and gives the reply's rcode and
// addresses.
func (h *home) ask(from, network, server, name string) (int, []string) {
	rcode, addrs := noAnswer, []string(nil)
	within(h.t, h.hosts[from], func() {
		c, err := net.DialTimeout(network, net.JoinHostPort(server, "53"), time.Second)
		if err != nil {
			return
		}
		defer c.Close()
		q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, lb := range strings.Split(name, ".") {
			q = append(append(q, byte(len(lb))), lb...)
		}
		q = append(q, 0, 0, 1, 0, 1)
		c.SetDeadline(time.Now().Add(time.Second))
		r := make([]byte, 1500)
		var n int
		if network == "tcp" {
			// RFC 1035 4.2.2: each message is preceded by its length.
			if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
				return
			}
			if _, err := io.ReadFull(c, r[:2]); err != nil {
				return
			}
			n = int(binary.BigEndian.Uint16(r))
			if _, err := io.ReadFull(c, r[:n]); err != nil {
				return
			}
		} else {
			c.Write(q)
			if n, err = c.Read(r); err != nil {
				return
			}
		}
		if n < 12 {
			return
		}
		r = r[:n]
		rcode = int(r[3] & 0xf)
		off := len(q) // the question is echoed
		for an := binary.BigEndian.Uint16(r[6:8]); an > 0 && off+12 <= len(r); an-- {
			off += 2 // a compressed name
			typ, rdlen := binary.BigEndian.Uint16(r[off:]), int(binary.BigEndian.Uint16(r[off+8:]))
			off += 10
			if off+rdlen > len(r) {
				break
			}
			if typ == 1 && rdlen == 4 {
				addrs = append(addrs, net.IP(r[off:off+4]).String())
			}
			off += rdlen
		}
	})
	return rcode, addrs
}

// set is the addresses an allow set holds.
func (h *home) set(name string) []string {
	out := run(h.t, "nft", "-j", "list", "set", "inet", nft.Table, name)
	var addrs []string
	for _, a := range internet {
		if strings.Contains(out, `"`+a+`"`) {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

const (
	coreDNS = "10.50.0.1"
	tvDNS   = "10.101.0.1"
	spkDNS  = "10.102.0.1"
)

// TestOnlyResolvedAddressesAllowed: the core and a device reach a listed
// name's address only once the enforcer's own resolver returned it; an
// address it did not return, a subdomain, an unlisted name, another
// list's name and an offline device's list open nothing; another list's
// name is not even answered; and a device's port-53 traffic to an outside
// resolver is answered by its own view.
// Catches a core dialing an unlisted address under a listed name (NET-2
// The core's list, NET-3).
func TestOnlyResolvedAddressesAllowed(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t, false)
	f := generate(t)
	h.listed(f)
	h.dnsmasq(nil, "people", f.People)

	// Before any answer, nothing is open: the sets start empty.
	for from, addr := range map[string]string{"core0": coreAddr, "ap0.101": tvAddr, "ap0.103": plugAddr} {
		if h.reaches(from, addr) {
			t.Errorf("%s reaches %s before resolving it", from, addr)
		}
	}
	expectOn := func(network, from, server, name string, rcode int, addrs ...string) {
		t.Helper()
		got, gotAddrs := h.ask(from, network, server, name)
		if got != rcode || !slices.Equal(gotAddrs, addrs) {
			t.Errorf("%s asks %s for %s over %s: rcode %d %v, want %d %v", from, server, name, network, got, gotAddrs, rcode, addrs)
		}
	}
	expect := func(from, server, name string, rcode int, addrs ...string) {
		t.Helper()
		expectOn("udp", from, server, name, rcode, addrs...)
	}
	const refused, nxdomain = 5, 3
	// Over IPv6 too, before any answer fills a set: another view's global
	// address, or the core's, reaches the device's own view through the
	// redirect, which refuses the name; another view's link-local address
	// is on another link, so nothing answers; and the core gets nothing
	// from a device's view. Over UDP and TCP alike (ENF-f-4).
	if h.has6() {
		tvLL, plugLL, coreLL := h.linkLocal("ap0.101"), h.linkLocal("ap0.103"), h.linkLocal("core0")
		for _, nw := range []string{"udp", "tcp"} {
			expectOn(nw, "ap0.101", "2001:db8:103::1", "plug.example", refused)
			expectOn(nw, "ap0.101", "2001:db8:50::1", "core.example", refused)
			expectOn(nw, "ap0.101", plugLL+"%eth0", "plug.example", noAnswer)
			expectOn(nw, "ap0.101", coreLL+"%eth0", "core.example", noAnswer)
			expectOn(nw, "core0", "2001:db8:103::1", "plug.example", noAnswer)
			expectOn(nw, "core0", "2001:db8:101::1", "tv.example", noAnswer)
			expectOn(nw, "core0", tvLL+"%eth0", "tv.example", noAnswer)
		}
		for _, set := range []string{nft.CoreSet(false), nft.DeviceSet(101, false), nft.DeviceSet(103, false)} {
			if got := h.set(set); len(got) != 0 {
				t.Errorf("IPv6 queries from another view filled %s: %v", set, got)
			}
		}
		// Control: the TV's own view answers on both its addresses.
		for _, nw := range []string{"udp", "tcp"} {
			expectOn(nw, "ap0.101", "2001:db8:101::1", "tv.example", 0, tvAddr)
			expectOn(nw, "ap0.101", tvLL+"%eth0", "tv.example", 0, tvAddr)
		}
	}
	expect("core0", coreDNS, "core.example", 0, coreAddr)
	expect("core0", coreDNS, "unlisted.example", refused)
	expect("core0", coreDNS, "sub.core.example", nxdomain)
	expect("core0", coreDNS, "updates.core.example", 0, cdnAddr)
	expect("ap0.101", tvDNS, "tv.example", 0, tvAddr)
	expect("ap0.101", tvDNS, "cdn.example", 0, cdnAddr)
	expect("core0", tvDNS, "tv.example", noAnswer)
	// Another list's name is refused in a device's own view, and in
	// another device's, which the redirect makes its own, so it neither
	// learns that list's address nor fills that list's set (ENF-f-4).
	for _, nw := range []string{"udp", "tcp"} {
		expectOn(nw, "ap0.101", tvDNS, "plug.example", refused)
		expectOn(nw, "ap0.101", "10.103.0.1", "plug.example", refused)
		expectOn(nw, "ap0.101", tvDNS, "core.example", refused)
		expectOn(nw, "ap0.101", coreDNS, "core.example", refused)
		expectOn(nw, "core0", coreDNS, "tv.example", refused)
		expectOn(nw, "core0", tvDNS, "tv.example", noAnswer)
	}
	if got := h.set(nft.DeviceSet(103, false)); len(got) != 0 {
		t.Errorf("another device's queries filled the plug's set: %v", got)
	}
	expect("ap0.101", tvDNS, "unlisted.example", refused)
	// Port 53 to an outside resolver is the enforcer's answer.
	expect("ap0.103", "9.9.9.9", "cdn.example", 0, cdnAddr)
	expect("ap0.103", "9.9.9.9", "plug.example", 0, plugAddr)
	expect("ap0.103", upstreamAddr, "unlisted.example", refused)
	// An offline device's list is never resolved: it has no set.
	expect("ap0.102", spkDNS, "speaker.example", refused)
	// The edge's segment has no resolver.
	expect("edge0", "10.60.0.1", "core.example", noAnswer)

	for _, c := range []struct {
		from, addr string
		want       bool
		why        string
	}{
		{"core0", coreAddr, true, "returned for a listed name"},
		{"core0", cdnAddr, true, "returned for a listed name"},
		{"core0", subAddr, false, "a subdomain's address, never returned"},
		{"core0", otherAddr, false, "an unlisted name's address"},
		{"core0", tvAddr, false, "a device's name, not the core's"},
		{"ap0.101", tvAddr, true, "returned for its listed name"},
		{"ap0.101", plugAddr, false, "another device's name"},
		{"ap0.101", coreAddr, false, "the core's name"},
		{"ap0.101", cdnAddr, true, "returned for its listed name"},
		{"ap0.103", cdnAddr, true, "returned, through the redirect"},
		{"ap0.103", plugAddr, true, "returned for its listed name, through the redirect"},
		{"ap0.102", speakerOut, false, "an offline device"},
	} {
		if got := h.reaches(c.from, c.addr); got != c.want {
			t.Errorf("%s -> %s: %v, want %v (%s)", c.from, c.addr, got, c.want, c.why)
		}
	}
	for set, want := range map[string][]string{
		nft.CoreSet(false):        {coreAddr, cdnAddr},
		nft.DeviceSet(101, false): {tvAddr, cdnAddr},
		nft.DeviceSet(103, false): {plugAddr, cdnAddr},
	} {
		got := h.set(set)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("set %s holds %v, want %v", set, got, want)
		}
	}
}

// TestNoServiceOnEdge: with no ruleset loaded at all, the instances still
// answer neither DNS nor DHCP on the edge's segment, and no listed view
// answers a query that arrives on another view's interface, while a
// device gets a lease (NET-2 Segments, Hardening: DNS and DHCP only on the
// networks the enforcer serves). Catches a listener on the edge's segment
// that only the firewall hides.
func TestNoServiceOnEdge(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t, true)
	// IPv4 leases only: the links' IPv6 addresses are the harness's own
	// (link), and TestDnsmasqAccepts checks the IPv6 lease lines.
	s := fixtureSetup()
	for i := range s.Nets {
		s.Nets[i].Prefix6 = netip.Prefix{}
	}
	f, err := Generate(fixturePolicy(), fixtureLayout(), s)
	if err != nil {
		t.Fatal(err)
	}
	h.listed(f)
	h.dnsmasq(nil, "people", f.People)
	h.dnsmasq(nil, "dhcp", strings.Replace(f.DHCP, fixtureSetup().LeaseFile, filepath.Join(t.TempDir(), "leases"), 1))

	if rcode, _ := h.resolve("edge0", "10.60.0.1", "core.example"); rcode != noAnswer {
		t.Errorf("the edge's segment got a DNS answer (rcode %d)", rcode)
	}
	// Each view answers only on its own interface, even with no ruleset
	// to redirect a query: one sent to another view's address arriving on
	// a different interface gets nothing, over UDP or TCP, and over IPv6
	// at another view's global or link-local address (ENF-f-4).
	silent := [][3]string{{"core0", tvDNS, "tv.example"}, {"ap0.101", "10.103.0.1", "plug.example"}, {"ap0.101", coreDNS, "core.example"}}
	answers := [][3]string{{"ap0.101", tvDNS, "tv.example"}, {"core0", coreDNS, "core.example"}}
	if h.has6() {
		tvLL, plugLL, coreLL, edgeLL := h.linkLocal("ap0.101"), h.linkLocal("ap0.103"), h.linkLocal("core0"), h.linkLocal("edge0")
		silent = append(silent,
			[3]string{"edge0", "2001:db8:60::1", "core.example"},
			[3]string{"edge0", edgeLL + "%eth0", "core.example"},
			[3]string{"core0", "2001:db8:101::1", "tv.example"},
			[3]string{"core0", tvLL + "%eth0", "tv.example"},
			[3]string{"ap0.101", "2001:db8:103::1", "plug.example"},
			[3]string{"ap0.101", plugLL + "%eth0", "plug.example"},
			[3]string{"ap0.101", "2001:db8:50::1", "core.example"},
			[3]string{"ap0.101", coreLL + "%eth0", "core.example"})
		answers = append(answers,
			[3]string{"ap0.101", "2001:db8:101::1", "tv.example"},
			[3]string{"ap0.101", tvLL + "%eth0", "tv.example"},
			[3]string{"core0", "2001:db8:50::1", "core.example"},
			[3]string{"core0", coreLL + "%eth0", "core.example"})
	}
	for _, nw := range []string{"udp", "tcp"} {
		for _, c := range silent {
			if rcode, _ := h.ask(c[0], nw, c[1], c[2]); rcode != noAnswer {
				t.Errorf("%s asked %s's view for %s over %s: rcode %d", c[0], c[1], c[2], nw, rcode)
			}
		}
		for _, c := range answers {
			if rcode, _ := h.ask(c[0], nw, c[1], c[2]); rcode != 0 {
				t.Errorf("control: %s asked %s for %s over %s: rcode %d", c[0], c[1], c[2], nw, rcode)
			}
		}
	}
	// dnsmasq checks an address is free (a ping) before it offers it, so
	// each offer waits seconds, one after another; the probes run together.
	offers := map[string]bool{"edge0": false, "ap0.101": true, "own0": true, "core0": true}
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]bool{}
	for from := range offers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := h.dhcp(from)
			mu.Lock()
			got[from] = ok
			mu.Unlock()
		}()
	}
	wg.Wait()
	for from, want := range offers {
		if got[from] != want {
			t.Errorf("DHCP offer to %s: %v, want %v", from, got[from], want)
		}
	}
	// No dnsmasq socket is bound to any of the edge's addresses or to a
	// wildcard address on the DNS port.
	out := run(t, "ss", "-Hlntup")
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "10.60.0.1:") || strings.Contains(ln, "2001:db8:60::1]") || strings.Contains(ln, "%edge0") ||
			strings.Contains(ln, "0.0.0.0:53 ") || strings.Contains(ln, "[::]:53 ") || strings.Contains(ln, "*:53 ") {
			t.Errorf("listener: %s", ln)
		}
	}
}

// dhcp reports whether a DHCPDISCOVER broadcast from host from gets an
// offer.
func (h *home) dhcp(from string) bool {
	got := false
	within(h.t, h.hosts[from], func() {
		lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) {
				serr = errors.Join(unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1),
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))
			})
			return serr
		}}
		pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:68")
		if err != nil {
			h.t.Fatal(err)
		}
		defer pc.Close()
		ifi, err := net.InterfaceByName("eth0")
		if err != nil {
			h.t.Fatal(err)
		}
		m := make([]byte, 240)
		m[0], m[1], m[2] = 1, 1, 6 // BOOTREQUEST, Ethernet
		copy(m[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
		m[10] = 0x80 // broadcast reply
		copy(m[28:34], ifi.HardwareAddr)
		copy(m[236:240], []byte{99, 130, 83, 99})
		m = append(m, 53, 1, 1, 255) // DHCPDISCOVER
		pc.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := pc.WriteTo(m, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
			h.t.Fatal(err)
		}
		r := make([]byte, 1500)
		for {
			n, _, err := pc.ReadFrom(r)
			if err != nil {
				return
			}
			if n >= 240 && r[0] == 2 && string(r[4:8]) == "\xde\xad\xbe\xef" {
				got = true
				return
			}
		}
	})
	return got
}
