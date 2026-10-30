package wol

// REQ: NET-2

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

var (
	gamingPC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01} // paired, on Household
	desktop  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02} // paired, on its own Devices VLAN
	laptop   = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x03} // on Owner, not paired
)

func machines() []Machine {
	return []Machine{{MAC: gamingPC, Iface: "hh0"}, {MAC: desktop, Iface: "ap0.101"}}
}

func magic(mac net.HardwareAddr) []byte {
	return append(bytes.Repeat([]byte{0xff}, 6), bytes.Repeat(mac, 16)...)
}

func TestNewRefuses(t *testing.T) {
	l := fixtureLayout()
	for name, ms := range map[string][]Machine{
		"core":      {{MAC: gamingPC, Iface: l.Core}},
		"edge":      {{MAC: gamingPC, Iface: l.Edge}},
		"guests":    {{MAC: gamingPC, Iface: l.Guests}},
		"admin":     {{MAC: gamingPC, Iface: l.Admin}},
		"wan":       {{MAC: gamingPC, Iface: l.WAN}},
		"ap mgmt":   {{MAC: gamingPC, Iface: l.APMgmt}},
		"trunk":     {{MAC: gamingPC, Iface: l.Trunk}},
		"bad vlan":  {{MAC: gamingPC, Iface: "ap0.1"}},
		"unknown":   {{MAC: gamingPC, Iface: "eth9"}},
		"broadcast": {{MAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Iface: "hh0"}},
		"multicast": {{MAC: net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1}, Iface: "hh0"}},
		"zero":      {{MAC: make(net.HardwareAddr, 6), Iface: "hh0"}},
		"eui64":     {{MAC: net.HardwareAddr{2, 0, 0, 0, 0, 0, 0, 1}, Iface: "hh0"}},
		"twice":     {{MAC: gamingPC, Iface: "hh0"}, {MAC: gamingPC, Iface: "own0"}},
	} {
		if _, err := New(l, ms); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := l
	bad.Edge = bad.Core
	if _, err := New(bad, machines()); err == nil {
		t.Error("a bad layout was accepted")
	}
}

// TestTarget: only an exact magic packet for a machine on the list wakes
// it, at most once per interval.
func TestTarget(t *testing.T) {
	r, err := New(fixtureLayout(), machines())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	secureOn := append(magic(gamingPC), 1, 2, 3, 4, 5, 6)
	mixed := magic(gamingPC)
	copy(mixed[96:], desktop)
	for _, c := range []struct {
		why  string
		pkt  []byte
		want string
	}{
		{"paired", magic(gamingPC), "hh0"},
		{"again at once", magic(gamingPC), ""},
		{"another paired machine", magic(desktop), "ap0.101"},
		{"unpaired", magic(laptop), ""},
		{"broadcast address", magic(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}), ""},
		{"trailing byte", append(magic(desktop), 0), ""},
		{"15 repeats", magic(desktop)[:96], ""},
		{"a second address in the repeats", mixed, ""},
		{"no sync", append([]byte{0xfe}, magic(desktop)[1:]...), ""},
		{"empty", nil, ""},
	} {
		got := ""
		if m := r.Target(c.pkt); m != nil {
			got = m.Iface
		}
		if got != c.want {
			t.Errorf("%s: wakes %q, want %q", c.why, got, c.want)
		}
	}
	now = now.Add(WakeInterval)
	if m := r.Target(secureOn); m == nil || m.Iface != "hh0" {
		t.Errorf("SecureOn after the interval: %v", m)
	}
}

func required() bool { return os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1" }

const childEnv = "AGENTOS_WOL_NETNS"

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
// enforcer's end is ifc with 10.<n>.0.1, the host's eth0 has 10.<n>.0.2.
func newHost(t *testing.T, ifc string, n int) int {
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

// wolSocket is a socket on a host at the Wake-on-LAN port, as a machine's
// network card would hear it.
func wolSocket(t *testing.T, pid int) *net.UDPConn {
	var c *net.UDPConn
	within(t, pid, func() {
		pc, err := net.ListenPacket("udp4", ":"+strconv.Itoa(nft.WoLPort))
		if err != nil {
			t.Fatal(err)
		}
		c = pc.(*net.UDPConn)
	})
	t.Cleanup(func() { c.Close() })
	return c
}

// TestPairedOnly: real packets between namespaces, through the loaded
// ruleset and the relay: the core's magic packet for a paired machine
// reaches that machine's network only; one for any other machine, a
// malformed one, and one from anywhere but the core reach nothing.
// Catches a relay that wakes anything (NET-2 Segments, A18).
func TestPairedOnly(t *testing.T) {
	if !inNetns(t) {
		return
	}
	l := fixtureLayout()
	doc := policy.Document{Version: 1}
	text, err := nft.Compile(doc, l)
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
	for i, ifc := range []string{"core0", "own0", "hh0", "ap0.101", "ap0.102", "gst0"} {
		hosts[ifc] = newHost(t, ifc, 10+i)
		socks[ifc] = wolSocket(t, hosts[ifc])
	}
	r, err := New(l, machines())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	time.Sleep(200 * time.Millisecond)

	enf := func(ifc string) string {
		return fmt.Sprintf("10.%d.0.1", 10+map[string]int{"core0": 0, "own0": 1, "hh0": 2, "ap0.101": 3, "ap0.102": 4, "gst0": 5}[ifc])
	}
	sendFrom := func(ifc, to string, pkt []byte) {
		within(t, hosts[ifc], func() {
			c, err := net.Dial("udp4", net.JoinHostPort(to, strconv.Itoa(nft.WoLPort)))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write(pkt)
		})
	}
	type heard struct{ iface, mac string }
	got := map[heard]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for ifc, c := range socks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 200)
			c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			for {
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				mac := "malformed"
				if n >= 12 {
					mac = net.HardwareAddr(buf[6:12]).String()
				}
				mu.Lock()
				got[heard{ifc, mac}]++
				mu.Unlock()
			}
		}()
	}
	sendFrom("core0", enf("core0"), magic(gamingPC))
	sendFrom("core0", enf("core0"), magic(desktop))
	sendFrom("core0", enf("core0"), magic(laptop))
	sendFrom("core0", enf("core0"), append(magic(desktop)[:101], 0xff, 0xff))
	sendFrom("hh0", enf("hh0"), magic(desktop))         // not from the core
	sendFrom("own0", enf("own0"), magic(gamingPC))      // not from the core
	sendFrom("ap0.102", enf("ap0.102"), magic(desktop)) // a device asking
	wg.Wait()
	want := map[heard]int{{"hh0", gamingPC.String()}: 1, {"ap0.101", desktop.String()}: 1}
	for k, n := range got {
		if want[k] != n {
			t.Errorf("%s heard %d wake(s) for %s, want %d", k.iface, n, k.mac, want[k])
		}
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s heard %d wake(s) for %s, want %d", k.iface, got[k], k.mac, n)
		}
	}
}
