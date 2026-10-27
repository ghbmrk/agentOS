package localui

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CH-9, HW-15

// sysNet builds a sysfs tree under a temporary root: one interface per
// entry, at its device path, with its type and, for a radio, a phy80211
// link; class/net links to each as the kernel's does.
func sysNet(t *testing.T, ifaces map[string]struct {
	dev, typ string
	radio    bool
}) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "class", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, i := range ifaces {
		dir := filepath.Join(root, "devices", i.dev, "net", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "type"), []byte(i.typ+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if i.radio {
			if err := os.Mkdir(filepath.Join(dir, "phy80211"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(filepath.Join("..", "..", "devices", i.dev, "net", name), filepath.Join(root, "class", "net", name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// WIFI-del-a3 (CH-9, HW-15; L3, Security and Potency blocker on f778fcf):
// port 1 is chosen from what the hardware fixes, never from DHCP or the
// routes, so the edge's USB cable or port 2 cannot become the page's port
// by handing the box the only default route while port 1 has no lease.
// It is the PCI Ethernet port at the lowest device path; USB adapters,
// Thunderbolt networking, radios, virtual links and non-Ethernet links are
// never it. It catches a page that serves on a port a peer picked.
func TestPort1IsFixedByHardwareNotRoutes(t *testing.T) {
	type nic = struct {
		dev, typ string
		radio    bool
	}
	edge := nic{"pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0", "1", false}
	port2 := nic{"pci0000:00/0000:00:1c.4/0000:03:00.0", "1", false}
	port1 := nic{"pci0000:00/0000:00:1c.0/0000:02:00.0", "1", false}
	full := map[string]nic{
		"enx001122334455": edge,
		"enp3s0":          port2,
		"enp2s0":          port1,
		"thunderbolt0":    {"pci0000:00/0000:00:0d.2/domain0/0-0/0-1/0-1.0", "1", false},
		"wlan0":           {"pci0000:00/0000:00:14.3", "1", true},
		"veth9":           {"virtual", "1", false},
		"lo":              {"virtual", "772", false},
		"wwan0":           {"pci0000:00/0000:00:1b.0/0000:01:00.0", "65534", false},
	}
	if got, err := Port1(sysNet(t, full)); got != "enp2s0" || err != nil {
		t.Fatalf("port 1: %q, %v", got, err)
	}
	// With only the edge's USB adapter and a radio, there is no port 1.
	if got, err := Port1(sysNet(t, map[string]nic{"enx001122334455": edge, "wlan0": full["wlan0"]})); err == nil {
		t.Fatalf("a USB adapter or a radio became port 1: %q", got)
	}
	if got, err := Port1(t.TempDir()); err == nil {
		t.Fatalf("no sysfs tree named %q", got)
	}
	// The page's start-up reads sysfs, not the route table.
	src, err := os.ReadFile("../cmd/agentos-localui/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "/proc/net/route") || !strings.Contains(string(src), "localui.Port1(") {
		t.Fatal("agentos-localui does not pick port 1 with Port1")
	}
}

// reachedOn is a request whose connection reached box, from the phone at
// from.
func reachedOn(target, from string, box *net.TCPAddr) *http.Request {
	q := httptest.NewRequest("GET", target, nil)
	q.RemoteAddr = from
	if box != nil {
		q = q.WithContext(context.WithValue(q.Context(), http.LocalAddrContextKey, box))
	}
	return q
}

// WIFI-del-a3 (CH-9): the enforcer routes the Owner network to port 1
// from another subnet, so any private IPv4 source is served; nothing
// public, loopback, IPv6 or malformed is, nor any of the box's own
// addresses (the reached one or another port's), nor a request whose
// server says nothing of the address it reached.
func TestPageAdmitsOnlyPrivateHomeSources(t *testing.T) {
	r := newRig(t)
	box := &net.TCPAddr{IP: net.IPv4(192, 168, 50, 2), Port: 80}
	serve := func(q *http.Request) int {
		w := httptest.NewRecorder()
		r.srv.ServeHTTP(w, q)
		return w.Code
	}
	for _, from := range []string{"10.8.0.23:51000", "172.16.4.9:4000", "192.168.50.77:4000", "[::ffff:10.8.0.23]:51000"} {
		if c := serve(reachedOn("http://192.168.50.2/status", from, box)); c != http.StatusOK {
			t.Errorf("private source %s: %d", from, c)
		}
	}
	for _, from := range []string{"8.8.8.8:4000", "203.0.113.5:4000", "100.64.0.9:4000", "169.254.1.1:4000", "127.0.0.1:4000",
		"[::1]:4000", "[fd00::5]:4000", "192.168.50.2:4000", "172.20.0.9:4000", "[::ffff:10.42.0.1]:4000", "garbage", ""} {
		if c := serve(reachedOn("http://192.168.50.2/status", from, box)); c != http.StatusForbidden {
			t.Errorf("source %q: %d", from, c)
		}
	}
	if c := serve(reachedOn("http://192.168.50.2/status", "10.8.0.23:51000", nil)); c != http.StatusForbidden {
		t.Errorf("no reached address: %d", c)
	}
}

// WIFI-del-a3 (CH-9): plain HTTP answers the page name or the IP literal of
// the address the connection reached (with its port off 80), since the
// core's DHCP address is the only one a home network without the page
// name can use; any other address, private or not, is a misdirected
// request, as any other name is (DNS rebinding cannot forge an IP literal).
func TestPageAnswersItsNameAndTheAddressReached(t *testing.T) {
	r := newRig(t)
	from := "10.8.0.23:51000"
	on80 := &net.TCPAddr{IP: net.IPv4(192, 168, 50, 2), Port: 80}
	on8080 := &net.TCPAddr{IP: net.IPv4(192, 168, 50, 2), Port: 8080}
	for _, c := range []struct {
		host string
		box  *net.TCPAddr
		want int
	}{
		{"192.168.50.2", on80, http.StatusOK},
		{DefaultPageName, on80, http.StatusOK},
		{"192.168.50.2:8080", on8080, http.StatusOK},
		{"192.168.50.2:80", on80, http.StatusMisdirectedRequest},
		{"192.168.50.2", on8080, http.StatusMisdirectedRequest},
		{"10.42.0.1", on80, http.StatusMisdirectedRequest},
		{"192.168.50.3", on80, http.StatusMisdirectedRequest},
		{"", on80, http.StatusMisdirectedRequest},
	} {
		q := reachedOn("http://x/status", from, c.box)
		q.Host = c.host
		w := httptest.NewRecorder()
		r.srv.ServeHTTP(w, q)
		if w.Code != c.want {
			t.Errorf("Host %q on %v: %d, want %d", c.host, c.box, w.Code, c.want)
		}
	}
}

// WIFI-del-a3 (CH-9, HW-15): the page needs one named interface it can be
// bound to alone, never loopback, and a page name its authority admits.
func TestPageRefusesABadInterface(t *testing.T) {
	for _, p := range []Page{{}, {Iface: "lo"}, {Iface: "eth0 lo"}, {Iface: "a-very-long-interface"}, {Iface: "eth0", PageName: "10.42.0.1"},
		{Iface: "eth0", PageName: "internal"}} {
		if _, err := New(Config{Page: p}); err == nil {
			t.Errorf("New accepted %+v", p)
		}
		if _, err := Listen(context.Background(), p, 0); err == nil {
			t.Errorf("Listen accepted %+v", p)
		}
	}
	if _, err := New(Config{Page: Page{Iface: "enp1s0", PageName: "box.internal"}}); err != nil {
		t.Fatal(err)
	}
}
