package mdns

// REQ: NET-3

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
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
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

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

// The fixture: a Household laptop paired with the printer, two paired
// sensors, an unpaired TV, and an isolated device whose pair is dead.
func fixturePolicy() policy.Document {
	return policy.Document{
		Version: 7,
		Devices: []policy.Device{
			{ID: "tv", Network: policy.NetDevices, WiFi: "vlan101", Allow: []string{"tv.example"}, VendorCloud: true, Everyday: true},
			{ID: "printer", Network: policy.NetDevices, WiFi: "vlan105", Everyday: true},
			{ID: "sensor-a", Network: policy.NetDevices, WiFi: "vlan106", Class: policy.ClassSensor},
			{ID: "sensor-b", Network: policy.NetDevices, WiFi: "vlan107", Class: policy.ClassSensor},
			{ID: "old-tv", Network: policy.NetDevices, WiFi: "vlan108", Everyday: true, Isolated: true},
			{ID: "laptop", Network: policy.NetHousehold, Everyday: true},
			{ID: "phone", Network: policy.NetOwner, Everyday: true},
		},
		Pairs: []policy.Pair{{A: "laptop", B: "printer"}, {A: "sensor-a", B: "sensor-b"}, {A: "old-tv", B: "phone"}},
	}
}

func plan(t *testing.T) Plan {
	t.Helper()
	paths, err := nft.Paths(fixturePolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	return NewPlan(paths)
}

func header(response bool) []byte {
	h := make([]byte, 12)
	if response {
		h[2] = 0x84 // QR, AA
	}
	return h
}

// TestPlanFollowsPairs: the plan, without sockets.
func TestPlanFollowsPairs(t *testing.T) {
	p := plan(t)
	q, r := header(false), header(true)
	for _, c := range []struct {
		iface string
		pkt   []byte
		port  uint16
		want  []string
	}{
		{"hh0", q, 5353, []string{"ap0.105"}},
		{"ap0.105", r, 5353, []string{"hh0"}},
		{"ap0.105", q, 5353, nil}, // a device's query stays on its VLAN
		{"hh0", r, 5353, nil},     // the network's announcements stay there
		{"ap0.106", q, 5353, []string{"ap0.107"}},
		{"ap0.106", r, 5353, []string{"ap0.107"}},
		{"ap0.107", r, 5353, []string{"ap0.106"}},
		{"ap0.101", r, 5353, nil}, // unpaired
		{"own0", q, 5353, nil},    // the phone's only pair is with an isolated device
		{"ap0.108", r, 5353, nil},
		{"ap0.105", r, 5354, nil},                                    // not from mDNS's port
		{"ap0.105", r[:11], 5353, nil},                               // not a DNS message
		{"ap0.105", append([]byte{0, 0, 0x8c}, r[3:]...), 5353, nil}, // opcode 1
	} {
		if got := p.Route(c.iface, c.port, c.pkt); !slices.Equal(got, c.want) {
			t.Errorf("%s %x from port %d: %v, want %v", c.iface, c.pkt[:min(3, len(c.pkt))], c.port, got, c.want)
		}
	}
	if got, want := p.Ifaces(), []string{"ap0.105", "ap0.106", "ap0.107", "hh0"}; !slices.Equal(got, want) {
		t.Errorf("listens on %v, want %v", got, want)
	}
}

// required is true in CI, where a missing tool or kernel feature fails the
// test instead of skipping it.
func required() bool { return os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1" }

const childEnv = "AGENTOS_MDNS_NETNS"

// inNetns re-runs the calling test as root of a fresh user and network
// namespace, the enforcer's, as nft's netns tests do.
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
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		if required() {
			t.Fatalf("no unprivileged user namespaces: %v", err)
		}
		t.Skipf("no unprivileged user namespaces: %v", err)
	}
	cmd := exec.Command("unshare", "-rn", "--", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("in the enforcer's namespace:\n%s", out)
	if err != nil {
		t.Fatalf("netns run failed: %v", err)
	}
	return false
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// newHost is a namespace joined to the enforcer by a veth pair: the
// enforcer's end is ifc with 10.<n>.0.1 and fd00:<n>::1, the host's eth0
// has 10.<n>.0.2 and fd00:<n>::2.
func newHost(t *testing.T, ifc string, n int, v6 bool) int {
	cmd := exec.Command("unshare", "-n", "sleep", "3600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	pid := cmd.Process.Pid
	self, _ := os.Readlink("/proc/self/ns/net")
	for i := 0; ; i++ {
		if ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid)); err == nil && ns != self {
			break
		}
		if i > 200 {
			t.Fatalf("%s: namespace never appeared", ifc)
		}
		time.Sleep(10 * time.Millisecond)
	}
	in := func(args ...string) {
		run(t, "nsenter", append([]string{"-t", strconv.Itoa(pid), "-n", "--"}, args...)...)
	}
	run(t, "ip", "link", "add", ifc, "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(pid))
	run(t, "ip", "addr", "add", fmt.Sprintf("10.%d.0.1/24", n), "dev", ifc)
	run(t, "ip", "link", "set", ifc, "up")
	in("ip", "link", "set", "lo", "up")
	in("ip", "addr", "add", fmt.Sprintf("10.%d.0.2/24", n), "dev", "eth0")
	in("ip", "link", "set", "eth0", "up")
	in("ip", "route", "add", "default", "via", fmt.Sprintf("10.%d.0.1", n))
	if v6 {
		run(t, "ip", "addr", "add", fmt.Sprintf("fd00:%d::1/64", n), "dev", ifc, "nodad")
		in("ip", "addr", "add", fmt.Sprintf("fd00:%d::2/64", n), "dev", "eth0", "nodad")
		// The link-local addresses mDNS sends from must finish duplicate
		// address detection first.
		for i := 0; ; i++ {
			a, _ := exec.Command("ip", "-6", "addr", "show", "dev", ifc, "tentative").Output()
			b, _ := exec.Command("nsenter", "-t", strconv.Itoa(pid), "-n", "--", "ip", "-6", "addr", "show", "dev", "eth0", "tentative").Output()
			if len(a) == 0 && len(b) == 0 {
				break
			}
			if i > 500 {
				t.Fatalf("%s: addresses still tentative", ifc)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return pid
}

// within runs f with the calling thread in pid's network namespace.
func within(t *testing.T, pid int, f func()) {
	runtime.LockOSThread()
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	target, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	f()
	if unix.Setns(int(self.Fd()), unix.CLONE_NEWNET) != nil {
		return
	}
	runtime.UnlockOSThread()
}

// group is where a host sends mDNS in one family.
func group(v6 bool) *net.UDPAddr {
	if v6 {
		return &net.UDPAddr{IP: Group6.Addr().AsSlice(), Port: int(Group6.Port()), Zone: "eth0"}
	}
	return net.UDPAddrFromAddrPort(Group)
}

// mdnsSocket is a socket on a host's eth0 at the given port (the group's
// for 5353), a member of the group there, that does not hear its own
// sends.
func mdnsSocket(t *testing.T, pid int, v6 bool, port int) *net.UDPConn {
	var c *net.UDPConn
	within(t, pid, func() {
		lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
			var serr error
			rc.Control(func(fd uintptr) {
				ifi, err := net.InterfaceByName("eth0")
				if err != nil {
					serr = err
					return
				}
				s := int(fd)
				serr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if v6 {
					mreq := &unix.IPv6Mreq{Multiaddr: Group6.Addr().As16(), Interface: uint32(ifi.Index)}
					serr = errors.Join(serr, unix.SetsockoptInt(s, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255),
						unix.SetsockoptInt(s, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, 0),
						unix.SetsockoptIPv6Mreq(s, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq))
					return
				}
				mreq := &unix.IPMreqn{Multiaddr: Group.Addr().As4(), Ifindex: int32(ifi.Index)}
				serr = errors.Join(serr, unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, 255),
					unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, 0),
					unix.SetsockoptIPMreqn(s, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, mreq))
			})
			return serr
		}}
		network, addr := "udp4", "0.0.0.0:"+strconv.Itoa(port)
		if v6 {
			network, addr = "udp6", "[::]:"+strconv.Itoa(port)
		}
		pc, err := lc.ListenPacket(context.Background(), network, addr)
		if err != nil {
			t.Fatal(err)
		}
		c = pc.(*net.UDPConn)
	})
	t.Cleanup(func() { c.Close() })
	return c
}

func hasKernelIPv6() bool {
	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

// TestPairOnly: real packets between namespaces, through the loaded
// ruleset and the relay, over IPv4 and IPv6: a Devices record reaches only
// its paired device's network, never Owner, and nothing else is
// reflected. Catches a general reflector (NET-3 Casting). Of what a
// paired device says, only its own records arrive: a record naming
// another link's address, a name its paired network claims, or a service
// on a foreign host is dropped (#4069); IPv6 mDNS is relayed as IPv4 is
// (#4081).
func TestPairOnly(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) { pairOnly(t, v6) })
	}
}

func pairOnly(t *testing.T, v6 bool) {
	if !inNetns(t) {
		return
	}
	if v6 && !hasKernelIPv6() {
		if required() {
			t.Fatal("the kernel has no IPv6")
		}
		t.Skip("the kernel has no IPv6")
	}
	l := fixtureLayout()
	text, err := nft.Compile(fixturePolicy(), l)
	if err != nil {
		t.Fatal(err)
	}
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	if err := (load.Loader{Bin: nftBin}).Load(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	hosts := map[string]int{}
	socks := map[string]*net.UDPConn{}
	nets := map[string]int{}
	for i, ifc := range []string{"own0", "hh0", "ap0.101", "ap0.105", "ap0.106", "ap0.107", "ap0.108"} {
		nets[ifc] = 10 + i
		hosts[ifc] = newHost(t, ifc, nets[ifc], v6)
		socks[ifc] = mdnsSocket(t, hosts[ifc], v6, 5353)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, plan(t)) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	time.Sleep(200 * time.Millisecond)

	// addr is the host's address on ifc's link, in this run's family.
	addr := func(ifc string) string {
		if v6 {
			return fmt.Sprintf("fd00:%d::2", nets[ifc])
		}
		return fmt.Sprintf("10.%d.0.2", nets[ifc])
	}
	answer := func(ifc string, marks ...string) *message {
		var rs []record
		for _, m := range marks {
			rs = append(rs, a(m+".local", addr(ifc), 120))
		}
		return response(rs, nil)
	}
	query := func(mark string) *message {
		return &message{questions: []question{{dn(mark + ".local"), typeA, 1}}}
	}
	// The printer's answer carries, besides its own record, a record for
	// another link's address, one for a name its paired network claims,
	// and a service on a foreign host.
	printer := answer("ap0.105", "printer-answer", "core-page")
	printer.answers = append(printer.answers,
		a("laptop-spoof.local", addr("hh0"), 120),
		srv("Fake._smb._tcp.local", "laptop-spoof.local", 120))
	laptopQuery := query("laptop-query")
	laptopQuery.answers = []record{a("laptop-known.local", addr("hh0"), 120)}
	sends := []struct {
		from string
		m    *message
		port int
	}{
		{"hh0", answer("hh0", "laptop-announce", "core-page"), 5353}, // claims core-page first
		{"ap0.105", printer, 5353},
		{"hh0", laptopQuery, 5353},
		{"ap0.101", answer("ap0.101", "tv-answer"), 5353},
		{"ap0.105", query("printer-query"), 5353},
		{"own0", query("phone-query"), 5353},
		{"ap0.108", answer("ap0.108", "isolated-answer"), 5353},
		{"ap0.106", answer("ap0.106", "sensor-a-answer"), 5353},
		{"ap0.107", query("sensor-b-query"), 5353},
		{"ap0.105", answer("ap0.105", "printer-wrong-port"), 40000},
	}
	for _, s := range sends {
		c := socks[s.from]
		if s.port != 5353 {
			// Its own send must not loop back to this host's mDNS socket,
			// so a sender hearing its own mark means the relay reflected it.
			c = mdnsSocket(t, hosts[s.from], v6, s.port)
		}
		within(t, hosts[s.from], func() {
			if _, err := c.WriteToUDP(s.m.bytes(), group(v6)); err != nil {
				t.Fatal(err)
			}
		})
		time.Sleep(20 * time.Millisecond) // the claim is heard before the answer
	}
	// A flood from the printer: the rate limit passes at most a burst,
	// and what it refills while the flood is sent.
	start := time.Now()
	within(t, hosts["ap0.105"], func() {
		for range 200 {
			socks["ap0.105"].WriteToUDP(answer("ap0.105", "flood").bytes(), group(v6))
		}
	})
	sent := time.Now()
	heard := map[string][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for ifc, c := range socks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 9000)
			c.SetReadDeadline(time.Now().Add(time.Second))
			for {
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				m, ok := parse(buf[:n])
				mu.Lock()
				if !ok {
					heard[ifc] = append(heard[ifc], "malformed")
					mu.Unlock()
					continue
				}
				if len(m.authority)+len(m.additional) > 0 {
					heard[ifc] = append(heard[ifc], "extra sections")
				}
				var got []string
				for _, q := range m.questions {
					got = append(got, "?"+q.name[0])
				}
				for _, r := range m.answers {
					got = append(got, r.name[0])
				}
				heard[ifc] = append(heard[ifc], strings.Join(got, " "))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	want := map[string][]string{
		"hh0":     {"printer-answer"},
		"ap0.105": {"?laptop-query"},
		"ap0.107": {"sensor-a-answer"},
		"ap0.106": {"?sensor-b-query"},
	}
	// No socket loops its sends back, so all a host hears came from the
	// relay: a mark heard by its own sender was reflected onto the
	// interface it came in on.
	floods := 0
	for ifc := range socks {
		got := slices.DeleteFunc(slices.Clone(heard[ifc]), func(s string) bool { return s == "flood" })
		floods += len(heard[ifc]) - len(got)
		slices.Sort(got)
		if !slices.Equal(got, want[ifc]) {
			t.Errorf("%s heard %q, want %q", ifc, got, want[ifc])
		}
	}
	if most := burst + int(math.Ceil(sent.Sub(start).Seconds()*perSec)); floods == 0 || floods > most {
		t.Errorf("%d of 200 flood packets passed; want 1 to %d", floods, most)
	}
	if !slices.Contains(heard["hh0"], "printer-answer") || len(heard["own0"]) != 0 {
		t.Errorf("the Owner network heard %v", heard["own0"])
	}
}
