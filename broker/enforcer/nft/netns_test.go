package nft

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
)

// The netns tests run the compiled ruleset in network namespaces: the test
// re-runs itself as root of a fresh user and network namespace (unshare
// -rn), which is the enforcer, and gives every other box, segment and
// device its own namespace joined to it by veth pairs and, on the device
// trunk, VLANs. No host root is needed, only unprivileged user namespaces,
// which CI turns on for the Go tests (ci.yml, "Subordinate ids").

const childEnv = "AGENTOS_NFT_NETNS"

// required is true in CI, where a missing tool or kernel feature fails the
// test instead of skipping it.
func required() bool { return os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1" }

func haveNetns(t *testing.T) bool {
	t.Helper()
	for _, tool := range []string{"unshare", "nsenter", "ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			if required() {
				t.Fatalf("%s missing", tool)
			}
			t.Skipf("%s missing", tool)
			return false
		}
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		if required() {
			t.Fatalf("no unprivileged user namespaces: %v", err)
		}
		t.Skipf("no unprivileged user namespaces: %v", err)
		return false
	}
	return true
}

// inNetns runs the calling test inside a fresh user and network namespace
// and reports whether this process is that child. The parent returns false
// after relaying the child's result.
func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv(childEnv) == "1" {
		return true
	}
	if !haveNetns(t) {
		return false
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

// host is one namespace: a box, a segment's stand-in host, or a device.
type host struct {
	name string
	pid  int
}

// home is the fixture home built around the enforcer's namespace (this
// process).
type home struct {
	t     *testing.T
	hosts map[string]*host
	vlans bool // device links are real VLANs on a trunk
	v6    bool // the kernel has IPv6
	procs []*exec.Cmd
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
	h.procs = append(h.procs, cmd)
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
	return x
}

// in runs a command in host x's namespace.
func (h *home) in(x *host, args ...string) string {
	h.t.Helper()
	return run(h.t, "nsenter", append([]string{"-t", strconv.Itoa(x.pid), "-n", "--"}, args...)...)
}

// link joins host x to the enforcer: the enforcer's end is ifc with addr,
// x's end is eth0 with xaddr and a default route through the enforcer.
func (h *home) link(x *host, ifc, addr, xaddr string, addr6, xaddr6 string) {
	t := h.t
	run(t, "ip", "link", "add", ifc, "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(x.pid))
	h.address(x, ifc, addr, xaddr, addr6, xaddr6)
}

func (h *home) address(x *host, ifc, addr, xaddr, addr6, xaddr6 string) {
	t := h.t
	run(t, "ip", "addr", "add", addr, "dev", ifc)
	run(t, "ip", "link", "set", ifc, "up")
	h.in(x, "ip", "addr", "add", xaddr, "dev", "eth0")
	h.in(x, "ip", "link", "set", "eth0", "up")
	gw, _, _ := strings.Cut(addr, "/")
	h.in(x, "ip", "route", "add", "default", "via", gw)
	if addr6 != "" && h.v6 {
		run(t, "ip", "addr", "add", addr6, "dev", ifc, "nodad")
		h.in(x, "ip", "addr", "add", xaddr6, "dev", "eth0", "nodad")
		gw6, _, _ := strings.Cut(addr6, "/")
		h.in(x, "ip", "-6", "route", "add", "default", "via", gw6)
	}
}

// Fixture addresses. The internet is three hosts behind the ISP router.
const (
	ispRouter = "192.168.1.1"
	enfWAN    = "192.168.1.2"
	netAllow  = "203.0.113.10" // in a device's allow set
	netOther  = "203.0.113.20" // on no list
	netCore   = "203.0.113.30" // on the core's list
	netDoH    = "1.1.1.1"
	net6Allow = "2001:db8:ff::10"
	net6Other = "2001:db8:ff::20"
)

func devAddr(vlan int) string   { return fmt.Sprintf("10.%d.0.2", vlan) }
func devAddr6(vlan int) string  { return fmt.Sprintf("fd00:%d::2", vlan) }
func enfAddr(seg string) string { return segNets[seg] + ".1" }

var segNets = map[string]string{"owner": "10.10.0", "household": "10.20.0", "guest": "10.30.0", "admin": "10.40.0", "core": "10.50.0", "edge": "10.60.0", "apm": "10.70.0"}

// listenPorts are opened on every host and on the enforcer, so a blocked
// probe is a drop and not a closed port.
var listenPorts = []int{22, 53, 67, 80, 123, 443, 547, 5353, 7443, 8443}

// build makes the fixture home and loads the fixture policy's ruleset.
func build(t *testing.T) *home {
	h := &home{t: t, hosts: map[string]*host{}}
	t.Cleanup(func() {
		for _, c := range h.procs {
			c.Process.Kill()
			c.Wait()
		}
	})
	_, err := os.Stat("/proc/sys/net/ipv6")
	h.v6 = err == nil
	if !h.v6 && required() {
		t.Fatal("the kernel has no IPv6")
	} else if !h.v6 {
		t.Log("no IPv6 here: the IPv6 probes are skipped")
	}
	forward := []string{"net/ipv4/ip_forward"}
	if h.v6 {
		forward = append(forward, "net/ipv6/conf/all/forwarding")
	}
	for _, k := range forward {
		if err := os.WriteFile("/proc/sys/"+k, []byte("1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	run(t, "ip", "link", "set", "lo", "up")
	isp := h.newHost("isp")
	run(t, "ip", "link", "add", "wan0", "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(isp.pid))
	run(t, "ip", "addr", "add", enfWAN+"/24", "dev", "wan0")
	run(t, "ip", "link", "set", "wan0", "up")
	run(t, "ip", "route", "add", "default", "via", ispRouter)
	h.in(isp, "ip", "addr", "add", ispRouter+"/24", "dev", "eth0")
	h.in(isp, "ip", "link", "set", "eth0", "up")
	for _, a := range []string{netAllow, netOther, netCore, netDoH} {
		h.in(isp, "ip", "addr", "add", a+"/32", "dev", "lo")
	}
	// The ISP router routes the enforcer's segments back to it, as an
	// attacker on the internet side would try (no NAT on the way in).
	h.in(isp, "ip", "route", "add", "10.0.0.0/8", "via", enfWAN)
	if h.v6 {
		run(t, "ip", "addr", "add", "2001:db8:1::2/64", "dev", "wan0", "nodad")
		run(t, "ip", "-6", "route", "add", "default", "via", "2001:db8:1::1")
		h.in(isp, "ip", "addr", "add", "2001:db8:1::1/64", "dev", "eth0", "nodad")
		for _, a := range []string{net6Allow, net6Other} {
			h.in(isp, "ip", "addr", "add", a+"/128", "dev", "lo", "nodad")
		}
		h.in(isp, "ip", "-6", "route", "add", "fd00::/8", "via", "2001:db8:1::2")
	}

	l := fixtureLayout()
	for seg, ifc := range map[string]string{"owner": l.Owner, "household": l.Household, "guest": l.Guests, "admin": l.Admin, "core": l.Core, "edge": l.Edge} {
		x := h.newHost(seg)
		h.link(x, ifc, enfAddr(seg)+"/24", segNets[seg]+".2/24", "", "")
	}
	apm := h.newHost("apm")
	h.link(apm, l.APMgmt, enfAddr("apm")+"/24", "10.70.0.2/24", "", "")

	// The access point: a trunk with one VLAN per device, each VLAN's far
	// end moved into that device's namespace.
	ap := h.newHost("ap")
	run(t, "ip", "link", "add", l.Trunk, "type", "veth", "peer", "name", "trunk", "netns", strconv.Itoa(ap.pid))
	run(t, "ip", "link", "set", l.Trunk, "up")
	h.in(ap, "ip", "link", "set", "trunk", "up")
	h.vlans = exec.Command("ip", "link", "add", "link", l.Trunk, "name", l.Trunk+".4000", "type", "vlan", "id", "4000").Run() == nil
	if h.vlans {
		run(t, "ip", "link", "del", l.Trunk+".4000")
	} else if required() {
		t.Fatal("the kernel has no 802.1Q VLAN support")
	} else {
		t.Log("no 802.1Q support here: each device VLAN is a veth named as its VLAN interface")
	}
	for _, vlan := range []int{101, 102, 103, 104, 105, 106, 107, 108} {
		h.device(ap, vlan)
	}
	h.loadFixture()
	for _, x := range h.hosts {
		h.listen(x)
	}
	h.listen(nil)
	return h
}

// device adds a device on its own VLAN; its namespace is named after the
// VLAN number.
func (h *home) device(ap *host, vlan int) *host {
	t := h.t
	l := fixtureLayout()
	x := h.newHost(strconv.Itoa(vlan))
	ifc := fmt.Sprintf("%s.%d", l.Trunk, vlan)
	if h.vlans {
		run(t, "ip", "link", "add", "link", l.Trunk, "name", ifc, "type", "vlan", "id", strconv.Itoa(vlan))
		h.in(ap, "ip", "link", "add", "link", "trunk", "name", "v", "type", "vlan", "id", strconv.Itoa(vlan))
		h.in(ap, "ip", "link", "set", "v", "netns", strconv.Itoa(x.pid))
		h.in(x, "ip", "link", "set", "v", "name", "eth0")
	} else {
		run(t, "ip", "link", "add", ifc, "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(x.pid))
	}
	h.address(x, ifc, fmt.Sprintf("10.%d.0.1/24", vlan), devAddr(vlan)+"/24", fmt.Sprintf("fd00:%d::1/64", vlan), devAddr6(vlan)+"/64")
	return x
}

func (h *home) loadFixture() {
	text, err := Compile(fixturePolicy(), fixtureLayout())
	if err != nil {
		h.t.Fatal(err)
	}
	h.load(text)
	// Slice f's resolver fills these from DNS; here they are filled
	// directly, which is what "the sentences that need no DNS" means. The
	// DoH address is in the TV's set to show the DNS block comes first.
	run(h.t, "nft", "add", "element", "inet", Table, DeviceSet(101, false), "{ "+netAllow+", "+netDoH+" }")
	if h.v6 {
		run(h.t, "nft", "add", "element", "inet", Table, DeviceSet(101, true), "{ "+net6Allow+" }")
	}
	run(h.t, "nft", "add", "element", "inet", Table, DeviceSet(103, false), "{ "+netAllow+" }")
	run(h.t, "nft", "add", "element", "inet", Table, CoreSet(false), "{ "+netCore+" }")
}

func (h *home) load(text string) {
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		h.t.Fatal(err)
	}
	if err := (load.Loader{Bin: nftBin}).Load(context.Background(), text); err != nil {
		h.t.Fatal(err)
	}
}

// within runs f with the calling thread in host x's network namespace
// (nil: the enforcer's), so the sockets f opens live there.
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
	if err := setns(target); err != nil {
		t.Fatalf("setns %s: %v", x.name, err)
	}
	f()
	if err := setns(self); err != nil {
		return // the thread stays locked and exits with this goroutine
	}
	runtime.UnlockOSThread()
}

func setns(f *os.File) error { return unix.Setns(int(f.Fd()), unix.CLONE_NEWNET) }

// listen opens an echo listener on every listen port, TCP and UDP, IPv4
// and IPv6, in x's namespace (nil: the enforcer's).
func (h *home) listen(x *host) {
	within(h.t, x, func() {
		for _, p := range listenPorts {
			for _, nw := range h.nets("tcp") {
				ln, err := net.Listen(nw, ":"+strconv.Itoa(p))
				if err != nil {
					h.t.Fatalf("listen %s %d: %v", nw, p, err)
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
			}
			for _, nw := range h.nets("udp") {
				pc, err := net.ListenPacket(nw, ":"+strconv.Itoa(p))
				if err != nil {
					h.t.Fatalf("listen %s %d: %v", nw, p, err)
				}
				if x == nil && nw == "udp6" && p == 547 {
					h.joinDHCPv6(pc)
				}
				h.t.Cleanup(func() { pc.Close() })
				go func() {
					buf := make([]byte, 1500)
					for {
						n, from, err := pc.ReadFrom(buf)
						if err != nil {
							return
						}
						pc.WriteTo(buf[:n], from)
					}
				}()
			}
		}
	})
}

func (h *home) nets(proto string) []string {
	if h.v6 {
		return []string{proto + "4", proto + "6"}
	}
	return []string{proto + "4"}
}

// outcome of one probe: connected (or answered), refused (a reply that
// says no), or silent (dropped).
type outcome int

const (
	silent outcome = iota
	refused
	connected
)

func (o outcome) String() string { return [...]string{"silent", "refused", "connected"}[o] }

const probeWait = 700 * time.Millisecond

func (h *home) tcp(from string, addr string, port int) outcome {
	var o outcome
	within(h.t, h.hosts[from], func() {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), probeWait)
		switch {
		case err == nil:
			c.Close()
			o = connected
		case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
			o = refused
		}
	})
	return o
}

func (h *home) udp(from string, addr string, port int) outcome {
	var o outcome
	within(h.t, h.hosts[from], func() {
		c, err := net.Dial("udp", net.JoinHostPort(addr, strconv.Itoa(port)))
		if err != nil {
			o = refused
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(probeWait))
		c.Write([]byte("probe"))
		buf := make([]byte, 16)
		if _, err := c.Read(buf); err == nil {
			o = connected
		} else if errors.Is(err, syscall.ECONNREFUSED) {
			o = refused
		}
	})
	return o
}

// expect checks a batch of probes, run concurrently.
type probe struct {
	from, addr string
	port       int
	udp        bool
	want       outcome
	why        string
}

func (h *home) expect(ps ...probe) {
	h.t.Helper()
	got := make([]outcome, len(ps))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 256) // each probe holds an OS thread
	if !h.v6 {
		ps = slices.DeleteFunc(slices.Clone(ps), func(p probe) bool { return strings.Contains(p.addr, ":") })
		got = got[:len(ps)]
	}
	for i, p := range ps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			if p.udp {
				got[i] = h.udp(p.from, p.addr, p.port)
			} else {
				got[i] = h.tcp(p.from, p.addr, p.port)
			}
		}()
	}
	wg.Wait()
	for i, p := range ps {
		if got[i] != p.want {
			proto := "tcp"
			if p.udp {
				proto = "udp"
			}
			h.t.Errorf("%s -> %s %s/%d: %v, want %v (%s)", p.from, p.addr, proto, p.port, got[i], p.want, p.why)
		}
	}
}

var packets = regexp.MustCompile(`packets (\d+)`)

// counter is a named counter's packet count.
func (h *home) counter(name string) int {
	out := run(h.t, "nft", "list", "counter", "inet", Table, name)
	m := packets.FindStringSubmatch(out)
	if m == nil {
		h.t.Fatalf("counter %s: %s", name, out)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// joinDHCPv6 makes the enforcer's echo listener on port 547 a member of
// All_DHCP_Relay_Agents_and_Servers (ff02::1:2) on the core's and the
// edge's segments, as a DHCPv6 server would be, so a Solicit reaches it
// unless the ruleset drops it.
func (h *home) joinDHCPv6(pc net.PacketConn) {
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		h.t.Fatal(err)
	}
	l := fixtureLayout()
	for _, name := range []string{l.Core, l.Edge} {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			h.t.Fatal(err)
		}
		mreq := &unix.IPv6Mreq{Interface: uint32(ifi.Index)}
		copy(mreq.Multiaddr[:], net.ParseIP("ff02::1:2").To16())
		var serr error
		if err := raw.Control(func(fd uintptr) {
			serr = unix.SetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq)
		}); err != nil || serr != nil {
			h.t.Fatalf("join ff02::1:2 on %s: %v %v", name, err, serr)
		}
	}
}

// settled waits until no IPv6 address is tentative in x's namespace (nil:
// the enforcer's), so a link-local probe has a source and a reply has a
// sender.
func (h *home) settled(x *host) {
	for i := 0; ; i++ {
		var out string
		if x == nil {
			out = run(h.t, "ip", "-6", "addr", "show", "tentative")
		} else {
			out = h.in(x, "ip", "-6", "addr", "show", "tentative")
		}
		if strings.TrimSpace(out) == "" {
			return
		}
		if i > 100 {
			h.t.Fatalf("addresses still tentative: %s", out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
