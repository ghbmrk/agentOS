package localui

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// REQ: CH-9, HW-15

// Security blocker 1 on 713fd31: the box's own addresses are read without
// netlink, which the page's unit refuses (RestrictAddressFamilies=AF_UNIX
// AF_INET), so the real boxAddrs, not the tests' stand-in, must list
// loopback here. It catches a page that refuses every request on the box.
func TestBoxAddrsListsLoopbackWithoutNetlink(t *testing.T) {
	as, err := boxAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a == netip.MustParseAddr("127.0.0.1") {
			return
		}
	}
	t.Fatalf("loopback not among %v", as)
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
