package main

// REQ: NET-2, NET-3, NET-5, KRN-12

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/dns"
	dnsrun "github.com/ghbmrk/agentos/broker/enforcer/dns/run"
	"github.com/ghbmrk/agentos/broker/enforcer/mdns"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/enforcer/wol"
	"golang.org/x/sys/unix"
)

// TestResolverInStep (ENF-l-dns-step, #4464): every firewall load runs
// inside the resolver's Apply, which stops the instances whose lists
// change before it and starts them after, and the files are the policy
// in force's. The running table is read on the first load after a
// restart too, so the resolver's answers survive it (#4754 Potency 1).
func TestResolverInStep(t *testing.T) {
	x, _ := enrolled(t, false)
	want, err := dns.Generate(home(), x.cfg.Layout, x.cfg.DNS)
	if err != nil {
		t.Fatal(err)
	}
	if got := x.dns.last(); !slices.Equal(got.Listed, want.Listed) || got.People != want.People || got.DHCP != want.DHCP {
		t.Fatal("the resolver does not run the policy in force's files")
	}
	x.fire.mu.Lock()
	loads, applies := len(x.fire.loads), len(x.dns.applied)
	x.fire.mu.Unlock()
	if loads != applies {
		t.Fatalf("%d firewall loads, %d inside the resolver's Apply", loads, applies)
	}
	x.fire.mu.Lock()
	x.fire.listed = 0
	x.fire.mu.Unlock()
	x.restart()
	x.fire.mu.Lock()
	listed := x.fire.listed
	x.fire.mu.Unlock()
	if listed == 0 {
		t.Fatal("the first load after a restart did not read the running table")
	}
	x.enforced()
}

// TestUnservableDocumentStillLoads (ENF-l-11): a document the resolver
// cannot serve (a VLAN the setup does not name) still loads, so a
// tightening is never held back, and every resolver instance stops.
func TestUnservableDocumentStillLoads(t *testing.T) {
	x, _ := enrolled(t, false)
	doc := home()
	doc.Devices = append(doc.Devices, policy.Device{ID: "plug", Network: policy.NetDevices, WiFi: "vlan109", Everyday: true, Allow: []string{"plug.example"}})
	if _, err := dns.Generate(doc, x.cfg.Layout, x.cfg.DNS); err == nil {
		t.Fatal("fixture: the resolver serves vlan109")
	}
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), doc)
	x.d.fwMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := x.dns.last(); len(got.Listed) != 0 || got.People != "" || got.DHCP != "" {
		t.Fatal("resolver instances kept running for a document they cannot serve")
	}
	if x.fire.last() != x.fullLoad(doc) {
		t.Fatal("the document was not loaded")
	}
}

// TestPairRelayFollowsPolicy (#4397, #4531): the relay runs on the plan
// of the document loaded, built from its paths and announces in one step
// and hearing nft.Hears, and on one filter for the process's life, the
// one the page reads.
func TestPairRelayFollowsPolicy(t *testing.T) {
	x, _ := enrolled(t, false)
	x.d.net.mdnsMu.Lock()
	plan := x.d.net.mdnsPlan
	x.d.net.mdnsMu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p, f := x.mdns.last()
		if slices.Equal(p.Ifaces(), plan.Ifaces()) && f != nil {
			if f != x.d.net.filter {
				t.Fatal("the relay does not keep the filter the page reads")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay never ran on the plan loaded")
		}
		time.Sleep(5 * time.Millisecond)
	}
	hears, err := nft.Hears(home(), x.cfg.Layout)
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := nft.Paths(home(), x.cfg.Layout)
	ann, _ := nft.Announces(home(), x.cfg.Layout)
	if want := mdns.NewPlan(paths, ann).Hearing(hears).Ifaces(); !slices.Equal(plan.Ifaces(), want) {
		t.Fatalf("relay hears %v, want %v", plan.Ifaces(), want)
	}
	x.d.net.mdnsMu.Lock()
	done := x.d.net.mdnsDone
	x.d.net.mdnsMu.Unlock()
	x.advance(time.Second) // no new document: the relay is not restarted
	x.d.net.mdnsMu.Lock()
	again := x.d.net.mdnsDone
	x.d.net.mdnsMu.Unlock()
	if again != done {
		t.Fatal("the relay restarted with no new document")
	}
}

// capped adopts a document with one capped core destination.
func capped(t *testing.T) (*box, policy.Document, *authenticator) {
	x, a := enrolled(t, true)
	next := x.current()
	next.Destinations = []string{"updates.example"}
	next.Caps = map[string]uint64{"updates.example": 1000}
	next.EdgeCap = 5000
	if w := x.b.approve(a, next); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if x.current().Caps["updates.example"] != 1000 {
		t.Fatal("fixture: the capped list is not in force")
	}
	return x, x.current(), a
}

// listing is a running table as nft's JSON: the core sent n bytes to
// 203.0.113.5, which updates.example's resolver set holds.
func listing(t *testing.T, x *box, doc policy.Document, handle int, n uint64) []byte {
	t.Helper()
	return listingOf(t, x, doc, handle, n, 0, true)
}

// listingOf is listing with the edge's bytes, and with the core's
// address held by updates.example's set or by none.
func listingOf(t *testing.T, x *box, doc policy.Document, handle int, n, edge uint64, named bool) []byte {
	t.Helper()
	sets, err := nft.AllowSets(doc, x.cfg.Layout)
	if err != nil {
		t.Fatal(err)
	}
	type obj = map[string]any
	set := func(name string, elems ...any) obj {
		return obj{"set": obj{"family": "inet", "table": nft.Table, "name": name, "elem": elems}}
	}
	b, err := json.Marshal(obj{"nftables": []obj{
		{"table": obj{"family": "inet", "name": nft.Table, "handle": handle}},
		{"counter": obj{"family": "inet", "table": nft.Table, "name": nft.EdgeOut, "bytes": edge}},
		set(nft.CapSet(false), obj{"elem": obj{"val": "203.0.113.5", "counter": obj{"bytes": n}}}),
		set(nft.CapSet(true)),
	}})
	if named {
		var o map[string][]obj
		json.Unmarshal(b, &o)
		o["nftables"] = append(o["nftables"], set(sets[0].Named("updates.example", false), "203.0.113.5"))
		b, err = json.Marshal(o)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestByteCapTripsTheCore (#4376 wiring): every reading interval the
// daemon reads the counters, trips the core on a cap passed, loads the
// in-kernel drop from the new counts and saves the day; a restart
// carries the day on.
func TestByteCapTripsTheCore(t *testing.T) {
	x, doc, _ := capped(t)
	x.fire.mu.Lock()
	x.fire.listing = listing(t, x, doc, 7, 600)
	x.fire.mu.Unlock()
	x.advance(readEvery)
	if x.d.cut.Stage() != channel.Open {
		t.Fatal("tripped under the cap")
	}
	x.fire.mu.Lock()
	ups := slices.Clone(x.fire.updates)
	x.fire.mu.Unlock()
	if len(ups) == 0 || !strings.HasPrefix(ups[len(ups)-1], nft.DropHeader) {
		t.Fatal("no drop update after a reading")
	}
	if _, err := os.Stat(filepath.Join(x.dir, fileTraffic)); err != nil {
		t.Fatalf("the day was not saved: %v", err)
	}
	// A restart is a new load (a new table handle): the saved 600 count on.
	x.restart()
	x.fire.mu.Lock()
	x.fire.listing = listing(t, x, doc, 8, 500)
	x.fire.mu.Unlock()
	x.advance(readEvery)
	if x.d.cut.Stage() != channel.Tripped {
		t.Fatal("1100 bytes across a restart against a cap of 1000 did not trip the core")
	}
	x.d.cut.mu.Lock()
	why := x.d.cut.reason
	x.d.cut.mu.Unlock()
	if !strings.Contains(why, "byte cap passed") || !strings.Contains(why, "updates.example") {
		t.Errorf("the trip's reason %q does not name the cap", why)
	}
}

// TestByteCapStateUnreadable (ENF-l-14): a saved day that does not read
// back is never counted from zero: every capped send is dropped (each
// group's count is its cap), the day is not overwritten, and the
// channel's counts read is refused.
func TestByteCapStateUnreadable(t *testing.T) {
	x, doc, _ := capped(t)
	if err := os.WriteFile(filepath.Join(x.dir, fileTraffic), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.restart()
	if !x.d.net.spent {
		t.Fatal("an unreadable day was not taken as spent")
	}
	text, err := nft.Reload(doc, x.cfg.Layout, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	now := x.now
	x.mu.Unlock()
	p := traffic.NewCounter(func() time.Time { return now }, traffic.CapsOf(doc)).Drop()
	for i := range p.Groups {
		p.Groups[i].Count = p.Groups[i].Cap
	}
	// Every cap is spent, not counted, so the kernel does not cut the edge
	// at its quota (nft.Drop.EdgeHold, #5282).
	p.EdgeCount, p.Past, p.EdgeHold = p.EdgeCap, true, true
	drops, err := nft.Drops(doc, x.cfg.Layout, nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if x.fire.last() != joinRules(text, drops) {
		t.Fatal("the load after an unreadable day does not drop every capped send")
	}
	x.fire.mu.Lock()
	x.fire.listing = listing(t, x, doc, 9, 10)
	x.fire.mu.Unlock()
	x.advance(readEvery)
	if b, _ := os.ReadFile(filepath.Join(x.dir, fileTraffic)); string(b) != "{}" {
		t.Fatal("the unreadable day was overwritten")
	}
	if _, err := x.d.counts(); err == nil {
		t.Fatal("the channel's counts read answered with no day")
	}
	if !strings.Contains(x.logText(), "saved day unreadable") {
		t.Fatal("an unreadable day was not logged")
	}
}

// TestQuotaEdgeUnreadable: a kernel whose quota edge cannot be probed
// still starts, says so, and loads the drop with the edge left false, one
// byte late, which the next reading trips on (nft.Drop.Past).
func TestQuotaEdgeUnreadable(t *testing.T) {
	x, _ := enrolled(t, false)
	x.fire.mu.Lock()
	x.fire.quotaErr = errors.New("probe refused")
	x.fire.mu.Unlock()
	x.restart()
	x.mu.Lock()
	logs := strings.Join(x.log, "\n")
	x.mu.Unlock()
	if !strings.Contains(logs, "quota edge unreadable") || x.d.net.past {
		t.Fatal("an unreadable quota edge was not logged, or taken as past")
	}
}

func (x *box) logText() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return strings.Join(x.log, "\n")
}

func (x *box) setListing(b []byte) {
	x.fire.mu.Lock()
	x.fire.listing = b
	x.fire.mu.Unlock()
}

func (x *box) listed() int {
	x.fire.mu.Lock()
	defer x.fire.mu.Unlock()
	return x.fire.listed
}

// TestRunningTableUnreadable: a load whose running table cannot be read
// still loads, with no answers carried, and says so.
func TestRunningTableUnreadable(t *testing.T) {
	x, _ := enrolled(t, false)
	x.fire.mu.Lock()
	x.fire.listErr = errors.New("nft: no such table")
	x.fire.mu.Unlock()
	x.restart()
	if !strings.Contains(x.logText(), "running table unreadable") {
		t.Fatal("an unreadable running table was not logged")
	}
	// #5491 (ENF-l-15): at a restart, a table that does not read holds the
	// caps spent and shows it on home; one that is absent (ENOENT) holds
	// nothing, as after a reboot; a table this process loaded that is
	// absent is still unread.
	if !x.d.net.unread || !(pageCaps{x.d}).Day().Unread {
		t.Fatal("a first load over a table that does not read holds nothing")
	}
	x.fire.mu.Lock()
	x.fire.listErr = fmt.Errorf("load: listing enforcer: %w: Error: No such file or directory", load.ErrNoTable)
	x.fire.mu.Unlock()
	logged := x.logs("firewall: running table unreadable")
	x.restart()
	if x.d.net.unread || (pageCaps{x.d}).Day().Unread {
		t.Fatal("a first load over an absent table holds the caps")
	}
	if x.logs("firewall: running table unreadable") != logged {
		t.Fatal("an absent table at a first load was logged as unreadable")
	}
	x.enforced()
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), x.current())
	held := x.d.net.unread
	x.d.fwMu.Unlock()
	if err != nil || !held {
		t.Fatalf("a later load over a table that went absent: %v, held %v", err, held)
	}
}

// TestLoadSeedsLeases (ENF-l-23, #5295): every full load, the first after
// a restart included, seeds the shared segments' lease sets from the DHCP
// server's lease file, in the same transaction after the ruleset, so a
// reboot does not cut every leased IPv4 host off until it renews. A line
// seeds only a Guests, Owner or Household host address inside its own
// segment's subnet, on that segment; a line for another segment's subnet
// seeds that segment. Out-of-subnet, admin, core and device-VLAN
// addresses, a segment's network, broadcast or own address, malformed,
// IPv6, non-Ethernet, infinite (expiry 0) and run-out lines seed nothing.
func TestLoadSeedsLeases(t *testing.T) {
	x, _ := enrolled(t, false)
	x.mu.Lock()
	now := x.now.Unix()
	x.mu.Unlock()
	exp := func(left int64) string { return strconv.FormatInt(now+left, 10) }
	file := strings.Join([]string{
		exp(600) + " 02:00:00:00:00:01 10.30.0.20 phone 01:02:00:00:00:00:01",
		exp(700) + " 02:00:00:00:00:02 10.20.0.21 * *",
		exp(800) + " 02:00:00:00:00:03 10.10.0.22 laptop *",
		exp(100) + " 02:00:00:00:00:04 10.99.0.5 * *",        // in no subnet
		exp(100) + " 02:00:00:00:00:05 10.40.0.20 * *",       // admin
		exp(100) + " 02:00:00:00:00:06 10.50.0.20 * *",       // core
		exp(100) + " 02:00:00:00:00:07 10.101.0.20 * *",      // device VLAN
		exp(100) + " 02:00:00:00:00:08 10.30.0.0 * *",        // network
		exp(100) + " 02:00:00:00:00:15 10.30.0.9 * *",        // below the lease range
		exp(100) + " 02:00:00:00:00:09 10.30.0.255 * *",      // broadcast
		exp(100) + " 02:00:00:00:00:0a 10.30.0.21 *",         // four fields
		exp(100) + " 02:00:00:00:00:0b 10.30.0.22 * * extra", // six fields
		"later 02:00:00:00:00:0c 10.30.0.23 * *",
		"0 02:00:00:00:00:0d 10.30.0.24 * *",
		exp(-1) + " 02:00:00:00:00:0e 10.30.0.25 * *",
		exp(0) + " 02:00:00:00:00:0f 10.30.0.26 * *",
		exp(100) + " not-a-mac 10.30.0.27 * *",
		exp(100) + " 02:00:00:00:00:00:00:10 10.30.0.28 * *", // not Ethernet
		exp(100) + " 02:00:00:00:00:11 10.30.0.300 * *",
		"duid 00:01:00:01:00:00:00:00:02:00:00:00:00:12",
		exp(100) + " 1234 fd00:30::20 * 00:01",
		exp(100) + " 02:00:00:00:00:13 ::ffff:10.30.0.29 * *",
		exp(100) + " 02:00:00:00:00:14 10.30.0.1 * *", // the enforcer's
	}, "\n") + "\n"
	path := filepath.Join(t.TempDir(), "dhcp.leases")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	x.cfg.DNS.LeaseFile = path
	x.restart()
	hw := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	l := x.cfg.Layout
	seed := nft.Seed(l, []nft.Lease{
		{Iface: l.Guests, Addr: netip.MustParseAddr("10.30.0.20"), HW: hw("02:00:00:00:00:01"), Left: 600},
		{Iface: l.Household, Addr: netip.MustParseAddr("10.20.0.21"), HW: hw("02:00:00:00:00:02"), Left: 700},
		{Iface: l.Owner, Addr: netip.MustParseAddr("10.10.0.22"), HW: hw("02:00:00:00:00:03"), Left: 800},
	})
	if strings.Count(seed, "add element") != 6 {
		t.Fatalf("fixture: seed %q", seed)
	}
	if got, want := x.fire.last(), x.seededLoad(x.current(), seed); got != want {
		t.Fatalf("loaded:\n%s\nwant the ruleset, then the seed:\n%s", got, seed)
	}
	// Every full load seeds, not only the first: the lease file is read
	// again, so a lease it no longer holds is not seeded.
	if err := os.WriteFile(path, []byte(exp(900)+" 02:00:00:00:00:01 10.30.0.20 * *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), x.current())
	x.d.fwMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	seed = nft.Seed(l, []nft.Lease{{Iface: l.Guests, Addr: netip.MustParseAddr("10.30.0.20"), HW: hw("02:00:00:00:00:01"), Left: 900}})
	if got, want := x.fire.last(), x.seededLoad(x.current(), seed); got != want {
		t.Fatalf("second load:\n%s\nwant the seed:\n%s", got, seed)
	}
}

// TestLeasesOf (ENF-l-23, #5295): a lease seeds only an address in its
// one shared segment's DHCP lease range (dns.Hosts4), never the subnet's
// network, broadcast or enforcer's own address (its first host), an
// address two networks claim, or one on a shared interface DHCP does not
// serve. The fixture is a setup the daemon accepts.
func TestLeasesOf(t *testing.T) {
	c := testConfig(t)
	s := c.DNS
	for i, n := range s.Nets {
		switch n.Iface {
		case "own0":
			s.Nets[i].DHCP = false
		case "ap0.101":
			s.Nets[i].Prefix4 = netip.MustParsePrefix("10.20.0.128/25") // hh0's upper half
		}
	}
	if _, err := dns.Generate(policy.Document{}, c.Layout, s); err != nil {
		t.Fatalf("fixture: setup refused: %v", err)
	}
	file := strings.Join([]string{
		"1100 02:00:00:00:00:01 10.30.0.10 * *", // first in range
		"1100 02:00:00:00:00:02 10.30.0.9 * *",
		"1100 02:00:00:00:00:03 10.30.0.1 * *", // the enforcer's
		"1100 02:00:00:00:00:04 10.30.0.0 * *",
		"1100 02:00:00:00:00:05 10.30.0.254 * *", // last in range
		"1100 02:00:00:00:00:06 10.30.0.255 * *",
		"1100 02:00:00:00:00:07 10.10.0.20 * *", // DHCP off
		"1100 02:00:00:00:00:08 10.20.0.20 * *",
		"1100 02:00:00:00:00:09 10.20.0.130 * *", // two subnets
		"1001 02:00:00:00:00:0a 10.30.0.11 * *",
		"1000 02:00:00:00:00:0b 10.30.0.12 * *",
		"1100 02:00:00:00:00:0c 10.30.0.13 * *", // last line, no newline
	}, "\n")
	hw := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	want := []nft.Lease{
		{Iface: "gst0", Addr: netip.MustParseAddr("10.30.0.10"), HW: hw("02:00:00:00:00:01"), Left: 100},
		{Iface: "gst0", Addr: netip.MustParseAddr("10.30.0.254"), HW: hw("02:00:00:00:00:05"), Left: 100},
		{Iface: "hh0", Addr: netip.MustParseAddr("10.20.0.20"), HW: hw("02:00:00:00:00:08"), Left: 100},
		{Iface: "gst0", Addr: netip.MustParseAddr("10.30.0.11"), HW: hw("02:00:00:00:00:0a"), Left: 1},
		{Iface: "gst0", Addr: netip.MustParseAddr("10.30.0.13"), HW: hw("02:00:00:00:00:0c"), Left: 100},
	}
	got := leasesOf([]byte(file), s.Nets, c.Layout, 1000)
	if !slices.EqualFunc(got, want, func(a, b nft.Lease) bool {
		return a.Iface == b.Iface && a.Addr == b.Addr && slices.Equal(a.HW, b.HW) && a.Left == b.Left
	}) {
		t.Fatalf("leases %+v, want %+v", got, want)
	}
	if got := leasesOf(nil, s.Nets, c.Layout, 1000); len(got) != 0 {
		t.Fatalf("no file: leases %+v", got)
	}
	// An address on two lines seeds neither (#5394 item 2), whether the
	// hardware addresses differ or not; the address's neighbours seed. A
	// line that does not parse names no address and proves no clock.
	file = strings.Join([]string{
		"1100 02:00:00:00:00:01 10.30.0.10 * *",
		"1100 not-a-mac 10.30.0.10 * *",
		"later 02:00:00:00:00:09 10.30.0.10 * *",
		"99999999 02:00:00:00:00:09 10.30.0.x * *",
		"1100 02:00:00:00:00:02 10.30.0.14 * *",
		"1200 02:00:00:00:00:03 10.30.0.14 * *",
		"1100 02:00:00:00:00:04 10.30.0.15 * *",
		"1100 02:00:00:00:00:04 10.30.0.15 * *",
		"1100 02:00:00:00:00:05 10.30.0.16 * *",
	}, "\n")
	want = []nft.Lease{
		{Iface: "gst0", Addr: netip.MustParseAddr("10.30.0.10"), HW: hw("02:00:00:00:00:01"), Left: 100},
		{Iface: "gst0", Addr: netip.MustParseAddr("10.30.0.16"), HW: hw("02:00:00:00:00:05"), Left: 100},
	}
	if got = leasesOf([]byte(file), s.Nets, c.Layout, 1000); !slices.EqualFunc(got, want, func(a, b nft.Lease) bool {
		return a.Iface == b.Iface && a.Addr == b.Addr && slices.Equal(a.HW, b.HW) && a.Left == b.Left
	}) {
		t.Fatalf("duplicate addresses: leases %+v, want %+v", got, want)
	}
	// A clock behind (#5394 item 4): a lease that ends LeaseTimeout+50
	// after now was granted 50 s from now, so the clock is at least that
	// far behind, and every lease's time left counts from then: the
	// newest seeds LeaseTimeout, one ending 1100 seeds 50, and one ending
	// within those 50 s seeds nothing, even from another subnet's line.
	grant := strconv.FormatInt(1050+nft.LeaseTimeout, 10)
	file = strings.Join([]string{
		"1100 02:00:00:00:00:01 10.30.0.10 * *",
		"1050 02:00:00:00:00:02 10.30.0.11 * *",
		"1049 02:00:00:00:00:03 10.30.0.12 * *",
		grant + " 02:00:00:00:00:04 10.99.0.5 * *", // in no subnet
		"1100 02:00:00:00:00:05 10.20.0.20 * *",
	}, "\n")
	want = []nft.Lease{
		{Iface: "gst0", Addr: netip.MustParseAddr("10.30.0.10"), HW: hw("02:00:00:00:00:01"), Left: 50},
		{Iface: "hh0", Addr: netip.MustParseAddr("10.20.0.20"), HW: hw("02:00:00:00:00:05"), Left: 50},
	}
	if got = leasesOf([]byte(file), s.Nets, c.Layout, 1000); !slices.EqualFunc(got, want, func(a, b nft.Lease) bool {
		return a.Iface == b.Iface && a.Addr == b.Addr && slices.Equal(a.HW, b.HW) && a.Left == b.Left
	}) {
		t.Fatalf("clock behind: leases %+v, want %+v", got, want)
	}
	file = grant + " 02:00:00:00:00:01 10.30.0.10 * *\n1100 02:00:00:00:00:02 10.30.0.11 * *"
	if got = leasesOf([]byte(file), s.Nets, c.Layout, 1000); len(got) != 2 || got[0].Left != nft.LeaseTimeout || got[1].Left != 50 {
		t.Fatalf("clock behind, the newest grant: leases %+v", got)
	}
}

// TestLeaseFileTorn (#5394 item 1): the lease file is taken only when two
// reads in a row are equal and it ends with a whole line, up to three
// tries; a read error is the file's, and a file never read whole is an
// error, so it seeds nothing.
func TestLeaseFileTorn(t *testing.T) {
	reads := func(rs ...string) (func() ([]byte, error), *int) {
		n := new(int)
		return func() ([]byte, error) {
			r := rs[min(*n, len(rs)-1)]
			*n++
			if r == "!" {
				return nil, os.ErrPermission
			}
			return []byte(r), nil
		}, n
	}
	const whole = "1 a 10.0.0.1 * *\n2 b 10.0.0.2 * *\n"
	for _, c := range []struct {
		reads []string
		want  string
		err   error
		n     int
	}{
		{[]string{whole, whole}, whole, nil, 2},
		{[]string{"", ""}, "", nil, 2},
		{[]string{"1 a 10.0.0.1 * *\n2 b 10.0.0.", whole, whole, whole}, whole, nil, 4},
		{[]string{"x\n", "y\n", "z\n", "w\n", whole, whole}, whole, nil, 6},
		{[]string{"x\n", "y\n", "z\n", "w\n", "u\n", "v\n", whole}, "", errTorn, 6},
		{[]string{"1 a 10.0.0.1 * *"}, "", errTorn, 6},
		{[]string{"!"}, "", os.ErrPermission, 1},
		{[]string{whole, "!"}, "", os.ErrPermission, 2},
	} {
		read, n := reads(c.reads...)
		got, err := leaseFile(read)
		if string(got) != c.want || !errors.Is(err, c.err) || *n != c.n {
			t.Errorf("reads %q: %q, %v after %d reads; want %q, %v after %d", c.reads, got, err, *n, c.want, c.err, c.n)
		}
	}
}

// TestLeaseFileUnreadable (ENF-l-23, #5295): a missing lease file (a first
// boot) or an unreadable one loads the ruleset with no seed, and the load
// is taken; only the unreadable one is logged.
func TestLeaseFileUnreadable(t *testing.T) {
	x, _ := enrolled(t, false)
	x.cfg.DNS.LeaseFile = filepath.Join(t.TempDir(), "none")
	x.restart()
	x.enforced()
	if strings.Contains(x.logText(), "lease file") {
		t.Fatal("a missing lease file was logged")
	}
	if (pageResolver{x.d}).Stopped().Unseeded {
		t.Fatal("home shows a missing lease file as unreadable")
	}
	x.cfg.DNS.LeaseFile = t.TempDir() // a directory: read fails
	x.restart()
	x.enforced()
	if !strings.Contains(x.logText(), "lease file unreadable") {
		t.Fatal("an unreadable lease file was not logged")
	}
	// Home shows it (#5394 item 3) until half a lease has passed, when
	// every host the load did not seed has renewed.
	if !(pageResolver{x.d}).Stopped().Unseeded {
		t.Fatal("home does not show an unreadable lease file")
	}
	x.advance(nft.LeaseTimeout/2*time.Second - time.Second)
	if !(pageResolver{x.d}).Stopped().Unseeded {
		t.Fatal("home stops showing an unreadable lease file before every host has renewed")
	}
	x.advance(time.Second)
	if (pageResolver{x.d}).Stopped().Unseeded {
		t.Fatal("home still shows an unreadable lease file half a lease later")
	}
	// A file that does not end with a whole line is one read mid-rewrite:
	// no seed, logged, shown; a load that reads it whole clears it.
	x.cfg.DNS.LeaseFile = filepath.Join(t.TempDir(), "dhcp.leases")
	exp := strconv.FormatInt(x.nowMS()/1000+600, 10)
	if err := os.WriteFile(x.cfg.DNS.LeaseFile, []byte(exp+" 02:00:00:00:00:01 10.30.0.20 * *"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.restart()
	if got := x.fire.last(); strings.Contains(got, "add element inet enforcer lease_") || !strings.Contains(x.logText(), errTorn.Error()) || !(pageResolver{x.d}).Stopped().Unseeded {
		t.Fatalf("a torn lease file seeded, or was not logged or shown:\n%s", got)
	}
	if err := os.WriteFile(x.cfg.DNS.LeaseFile, []byte(exp+" 02:00:00:00:00:01 10.30.0.20 * *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), x.current())
	x.d.fwMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(x.fire.last(), "add element inet enforcer lease_guests_4 { 0x0a1e0014 . 0x020000000001 expires 600s }") || (pageResolver{x.d}).Stopped().Unseeded {
		t.Fatalf("a lease file read whole did not seed, or home still shows it unread:\n%s", x.fire.last())
	}
}

// TestUnservableLogged: the log says why the resolver stopped.
func TestUnservableLogged(t *testing.T) {
	x, _ := enrolled(t, false)
	doc := home()
	doc.Devices = append(doc.Devices, policy.Device{ID: "plug", Network: policy.NetDevices, WiFi: "vlan109", Everyday: true})
	x.d.fwMu.Lock()
	x.d.loadNetwork(context.Background(), doc)
	x.d.fwMu.Unlock()
	if !strings.Contains(x.logText(), "cannot be served") {
		t.Fatal("the resolver's stop was not logged")
	}
}

// TestRefusedLoadKeepsCaps: when the firewall refuses a document's load,
// the counter keeps the caps of the ruleset still in force.
func TestRefusedLoadKeepsCaps(t *testing.T) {
	x, _, a := capped(t)
	next := x.current()
	next.Caps = map[string]uint64{"updates.example": 900}
	if w := x.b.approve(a, next); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if g := x.d.net.counter.Drop().Groups; len(g) != 1 || g[0].Cap != 1000 {
		t.Fatalf("caps after a refused load: %+v, want the loaded 1000", g)
	}
}

func TestJoinRules(t *testing.T) {
	if got := joinRules("a", "b"); got != "a\nb" {
		t.Errorf("joinRules = %q", got)
	}
	if got := joinRules("a\n", "b"); got != "a\nb" {
		t.Errorf("joinRules = %q", got)
	}
}

// TestPairRelayOneAtATime: a new document stops the relay before it, a
// relay that ends on its own runs again at the next tick, and Close stops
// it and the resolver.
func TestPairRelayOneAtATime(t *testing.T) {
	x, a := enrolled(t, false)
	next := x.current()
	next.Devices = append(next.Devices, policy.Device{ID: "speaker", Network: policy.NetDevices, WiFi: "vlan102", Everyday: true})
	if w := x.b.approve(a, next); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	active := func() int { x.mdns.mu.Lock(); defer x.mdns.mu.Unlock(); return x.mdns.active }
	waitUntil(t, "one relay running", func() bool { return active() == 1 })
	x.mdns.mu.Lock()
	x.mdns.fail = true
	x.mdns.mu.Unlock()
	x.restart()
	waitUntil(t, "the failed relay seen", func() bool {
		x.d.net.mdnsMu.Lock()
		defer x.d.net.mdnsMu.Unlock()
		return x.d.net.mdnsDown
	})
	if !strings.Contains(x.logText(), "mdns: relay stopped, started again at the next tick: mdns: socket refused") {
		t.Fatalf("the relay's end was not logged: %q", x.logText())
	}
	x.advance(time.Second)
	waitUntil(t, "the relay started again", func() bool { return active() == 1 })
	x.d.Close()
	if active() != 0 {
		t.Fatal("Close left the relay running")
	}
	x.dns.mu.Lock()
	closed := x.dns.closed
	x.dns.mu.Unlock()
	if closed == 0 {
		t.Fatal("Close left the resolver running")
	}
	x.start()
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("never: " + what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestReadingCadence: the counters are read once per readEvery, a bad
// listing is logged, and a day that cannot be saved is logged.
func TestReadingCadence(t *testing.T) {
	x, doc, _ := capped(t)
	x.advance(readEvery)
	if !strings.Contains(x.logText(), "byte caps: reading") {
		t.Fatal("an unreadable listing was not logged")
	}
	x.setListing(listing(t, x, doc, 7, 10))
	x.advance(readEvery)
	n := x.listed()
	x.advance(time.Second)
	if x.listed() != n {
		t.Fatal("read again within readEvery")
	}
	x.fail(fileTraffic, true)
	x.advance(readEvery)
	if !strings.Contains(x.logText(), "byte caps: day not saved") {
		t.Fatal("an unsaved day was not logged")
	}
}

// TestDropUpdate: the drop update is the counter's day, on this kernel's
// quota edge, against the reading it was taken from (nft.Drop.Read).
func TestDropUpdate(t *testing.T) {
	x, doc, _ := capped(t)
	l := listing(t, x, doc, 7, 300)
	x.setListing(l)
	x.advance(readEvery)
	p := x.d.net.counter.Drop()
	p.Past, p.Read = true, l
	want, err := nft.Drops(doc, x.cfg.Layout, l, p)
	if err != nil {
		t.Fatal(err)
	}
	x.fire.mu.Lock()
	got := x.fire.updates[len(x.fire.updates)-1]
	x.fire.mu.Unlock()
	if got != want {
		t.Fatal("the drop update is not the counter's day against its reading")
	}
}

// TestUnresolvedBytesTrip: bytes to an address no listed name resolved to
// trip the core, and the reason says so.
func TestUnresolvedBytesTrip(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listingOf(t, x, doc, 7, 10, 0, false))
	x.advance(readEvery)
	x.d.cut.mu.Lock()
	why := x.d.cut.reason
	x.d.cut.mu.Unlock()
	if x.d.cut.Stage() != channel.Tripped || !strings.Contains(why, "no listed name") {
		t.Fatalf("stage %v, reason %q", x.d.cut.Stage(), why)
	}
}

// edgeTripRule is the cut chain's rule that drops the edge's packets once
// the kernel put it in nft.TripSet (#5282): present in every drop unless
// the edge is held (nft.Drop.EdgeHold).
const edgeTripRule = `add rule inet enforcer cut_edge iifname @edge_trip counter name "edge_cut" drop`

// TestByteCapTripsTheEdge (#5014, ENF-l-15, KRN-12): the edge past its
// cap is cut: the record says so and why, a trip alert names the edge
// and turns the light red, and the drop written at once carries the cut
// chain's drop, while the core's channel stays open. The cut survives a
// restart (the first load carries it) and further readings that day; only
// the owner's passkey on the page lifts it, which clears the trip and
// writes the drop without the cut, and the rest of that day's overrun
// does not cut again. The next day's overrun cuts again.
func TestByteCapTripsTheEdge(t *testing.T) {
	const cutRule = `add rule inet enforcer cut_edge counter name "edge_cut" drop`
	x, doc, a := capped(t)
	lastUpdate := func() string {
		x.fire.mu.Lock()
		defer x.fire.mu.Unlock()
		return x.fire.updates[len(x.fire.updates)-1]
	}
	edgeTrips := func() int {
		n := 0
		for _, r := range x.d.alerts.Status().Open {
			if r.Kind == alert.Trip && r.Device == edgeDevice {
				n++
			}
		}
		return n
	}
	x.setListing(listingOf(t, x, doc, 7, 10, 5000, true))
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); cut || strings.Contains(lastUpdate(), cutRule) {
		t.Fatal("the edge was cut at its cap, not past it")
	}
	// The kernel cuts it at the first byte past (#5282), whatever the
	// writes after it do.
	if !strings.Contains(lastUpdate(), edgeTripRule) {
		t.Fatal("the drop at the edge's cap leaves the kernel's own cut off")
	}
	x.fail(fileEdgeCut, true) // the disk refuses the trip's record
	x.setListing(listingOf(t, x, doc, 7, 10, 6000, true))
	x.advance(readEvery)
	cut, why := x.d.edge.Cut()
	if !cut || !strings.Contains(why, "byte cap passed: 6000 of 5000") {
		t.Fatalf("an edge overrun: cut %v, reason %q", cut, why)
	}
	x.advance(time.Second)
	if cut, _ := x.d.edge.Cut(); !cut || x.logs("edge cut: trip not saved, ") != 1 || x.logs("edge cut: trip still not saved: ") == 0 {
		t.Fatal("a trip the disk refused is not in force, or its refusals are not logged")
	}
	x.fail(fileEdgeCut, false)
	x.advance(time.Second)
	if x.logs("edge cut: trip saved") != 1 {
		t.Fatal("the tick did not save the unsaved trip")
	}
	if !strings.Contains(lastUpdate(), cutRule) {
		t.Fatal("the cut is not in the drop written after the trip")
	}
	if edgeTrips() != 1 || x.d.alerts.Status().Colour != alert.Red {
		t.Fatal("the edge's cut raised no trip naming the edge, or the light is not red")
	}
	if x.d.cut.Stage() != channel.Open {
		t.Fatal("an edge overrun cut the core")
	}
	if _, err := os.Stat(filepath.Join(x.dir, fileEdgeCut)); err != nil {
		t.Fatalf("the cut was not saved: %v", err)
	}

	// A restart's first load is already cut, in the same transaction.
	x.restart()
	x.fire.mu.Lock()
	first := x.fire.loads[len(x.fire.loads)-1]
	x.fire.mu.Unlock()
	if !strings.Contains(first, cutRule) {
		t.Fatal("the first load after a restart lifted the edge's cut")
	}
	x.setListing(listingOf(t, x, doc, 8, 10, 0, true))
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); !cut || !strings.Contains(lastUpdate(), cutRule) || edgeTrips() != 1 || x.logs("byte caps: edge: ") != 1 {
		t.Fatal("a reading after the restart lifted the cut or tripped again")
	}

	// Nothing but the owner's passkey lifts it.
	if w := x.b.act(newAuthenticator(t), page.ActLiftEdge, ""); w.Code == http.StatusOK {
		t.Fatal("a stranger's passkey lifted the edge's cut")
	}
	x.fail(fileEdgeCut, true)
	if w := x.b.act(a, page.ActLiftEdge, ""); w.Code == http.StatusOK {
		t.Fatal("a lift the disk refused was answered as done")
	}
	if cut, _ := x.d.edge.Cut(); !cut || !strings.Contains(lastUpdate(), cutRule) || edgeTrips() != 1 {
		t.Fatal("a lift the disk refused lifted the cut")
	}
	x.fail(fileEdgeCut, false)
	if w := x.b.act(a, page.ActLiftEdge, ""); w.Code != http.StatusOK {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	if cut, _ := x.d.edge.Cut(); cut || strings.Contains(lastUpdate(), cutRule) || edgeTrips() != 0 {
		t.Fatal("the owner's lift left the edge cut, in the record, the firewall or the alerts")
	}
	if strings.Contains(lastUpdate(), edgeTripRule) {
		t.Fatal("the owner's lift on the overrun's day leaves the kernel cutting the edge at the quota it passed")
	}
	if err := (pageEdge{x.d}).LiftEdge(); err != nil { // a second lift changes nothing
		t.Fatal(err)
	}
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("the rest of the lifted day's overrun cut the edge again")
	}
	x.restart()
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("a restart brought back a lifted cut")
	}

	x.advance(24 * time.Hour)
	if !strings.Contains(lastUpdate(), edgeTripRule) {
		t.Fatal("the day after a lift, the kernel does not cut the edge at its new quota")
	}
	x.setListing(listingOf(t, x, doc, 9, 10, 6000, true))
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); !cut {
		t.Fatal("the next day's overrun did not cut the edge")
	}

	// A lift on a later day than the overrun holds only for that one:
	// the day it is lifted on counts from nothing, so its overrun cuts.
	x.advance(24 * time.Hour)
	// The firewall cannot be read at this lift: the record lifts, and
	// the next tick's full load carries the lift.
	x.fire.mu.Lock()
	x.fire.listErr = errors.New("nft: busy")
	loads := len(x.fire.loads)
	x.fire.mu.Unlock()
	if err := (pageEdge{x.d}).LiftEdge(); err != nil {
		t.Fatal(err)
	}
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("a lift a day after the overrun left the edge cut")
	}
	x.fire.mu.Lock()
	x.fire.listErr = nil
	x.fire.mu.Unlock()
	x.advance(time.Second)
	x.fire.mu.Lock()
	reloaded := len(x.fire.loads) > loads && !strings.Contains(x.fire.loads[len(x.fire.loads)-1], cutRule)
	x.fire.mu.Unlock()
	if !reloaded || x.logs("edge cut: firewall not updated, a full load follows at the next tick: ") != 1 {
		t.Fatal("a lift the firewall did not take was not logged, or not loaded in full at the next tick")
	}
	x.setListing(listingOf(t, x, doc, 9, 10, 12000, true)) // 6000 more on the lift's day
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); !cut {
		t.Fatal("an overrun on the day of a later lift did not cut the edge")
	}
}

// TestEdgeCutRecordUnreadable (#5014): a record of the edge's cut that
// does not read back fails closed: the edge starts cut, the log says so,
// and the owner's lift writes the record whole again.
func TestEdgeCutRecordUnreadable(t *testing.T) {
	x, _, a := capped(t)
	if err := os.WriteFile(filepath.Join(x.dir, fileEdgeCut), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.restart()
	if cut, _ := x.d.edge.Cut(); !cut || !strings.Contains(x.logText(), "edge cut: "+fileEdgeCut+" unreadable") {
		t.Fatal("an unreadable record did not start the edge cut, or was not logged")
	}
	// #5399: as a missing one, it raises its own alert, which lights red.
	if !slices.ContainsFunc(x.d.alerts.Status().Open, func(r alert.Record) bool {
		return r.Kind == alert.RecordMissing && r.Device == edgeDevice
	}) || x.d.alerts.Status().Colour != alert.Red {
		t.Fatal("an unreadable record raised no missing record alert")
	}
	if w := x.b.act(a, page.ActLiftEdge, ""); w.Code != http.StatusOK {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	x.restart()
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("the lift did not write the record whole again")
	}
	// A record that cannot be read at all (not a file) fails the start.
	x.d.Close()
	path := filepath.Join(x.dir, fileEdgeCut)
	if err := os.Remove(path); err != nil || os.Mkdir(path, 0o700) != nil {
		t.Fatal("fixture: the record not made a directory")
	}
	if d, err := x.open(); err == nil {
		d.Close()
		t.Fatal("the daemon started on an edge cut record it could not read")
	}
	os.Remove(path)
	x.start()
}

// TestCutRecordsMissing (#5282, #5399 items 1 and 4): provisioning writes
// both cut records uncut, and nothing removes them, so a record missing at
// a start means root on the enforcer or lost state: the box stays cut,
// an alert of its own names it and turns the light red, and each card's
// reason says to check the enforcer, not to trust the box. The owner's
// lift and resume write the records whole and resolve the alerts. Such a
// cut carries no day, so a lift on a day the edge is already past its cap
// holds for the rest of it: the next reading does not cut it again.
func TestCutRecordsMissing(t *testing.T) {
	x, doc, a := capped(t)
	for _, name := range []string{fileCut, fileEdgeCut} {
		if b, err := os.ReadFile(filepath.Join(x.dir, name)); err != nil || string(b) != "{}" {
			t.Fatalf("provisioning did not write %s uncut: %q, %v", name, b, err)
		}
	}
	if cut, _ := x.d.edge.Cut(); cut || x.d.cut.Stage() != channel.Open {
		t.Fatal("a fresh box starts cut")
	}
	missing := func() (core, edge int) {
		for _, r := range x.d.alerts.Status().Open {
			if r.Kind == alert.RecordMissing && r.Device == coreDevice {
				core++
			}
			if r.Kind == alert.RecordMissing && r.Device == edgeDevice {
				edge++
			}
		}
		return core, edge
	}
	if c, e := missing(); c+e != 0 || x.d.alerts.Status().Colour != alert.Off {
		t.Fatal("a fresh box raised a missing record")
	}
	x.d.Close()
	for _, name := range []string{fileCut, fileEdgeCut} {
		if err := os.Remove(filepath.Join(x.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	x.start()
	cut, why := x.d.edge.Cut()
	if !cut || why != "the record of the edge's cut is missing. Someone may have tampered with the enforcer: check it before you lift the cut." ||
		strings.Contains(why, "trust the edge") || !strings.Contains(x.logText(), "edge cut: "+fileEdgeCut+" missing") {
		t.Fatalf("a missing edge record: cut %v, reason %q", cut, why)
	}
	if !strings.Contains(x.fire.last(), `add rule inet enforcer cut_edge counter name "edge_cut" drop`) {
		t.Fatal("the first load with the edge's record missing does not cut the edge")
	}
	x.d.cut.mu.Lock()
	why = x.d.cut.reason
	x.d.cut.mu.Unlock()
	if x.d.cut.Stage() != channel.Tripped || why != "the record of the core's cut is missing. Someone may have tampered with the enforcer: check it before you resume the core's channel." ||
		!strings.Contains(x.logText(), "cut: "+fileCut+" missing") {
		t.Fatalf("a missing core record: stage %v, reason %q", x.d.cut.Stage(), why)
	}
	if c, e := missing(); c != 1 || e != 1 || x.d.alerts.Status().Colour != alert.Red {
		t.Fatalf("missing records raised %d core and %d edge alerts, light %v", c, e, x.d.alerts.Status().Colour)
	}
	// The edge is past its cap today: the cut's day is unknown, so the
	// lift holds for the rest of today.
	x.setListing(listingOf(t, x, doc, 7, 10, 6000, true))
	x.advance(readEvery)
	if w := x.b.act(a, page.ActLiftEdge, ""); w.Code != http.StatusOK {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("a lift of a cut with no day cut the edge again at the next reading")
	}
	if c, e := missing(); c != 1 || e != 0 {
		t.Fatalf("after the edge's lift: %d core and %d edge alerts open", c, e)
	}
	if err := x.d.cut.Resume(); err != nil {
		t.Fatal(err)
	}
	if c, e := missing(); c+e != 0 || x.d.alerts.Status().Colour != alert.Off {
		t.Fatal("the lift and resume left a missing record's alert open or the light red")
	}
	x.restart()
	if cut, _ := x.d.edge.Cut(); cut || x.d.cut.Stage() != channel.Open {
		t.Fatal("the owner's lift and resume did not write the records again")
	}
	if c, e := missing(); c+e != 0 {
		t.Fatal("a restart with both records raised a missing record")
	}
}

// TestDayZeroLiftWithinCap (#5399 item 4, Security on #5434): the lift of
// a cut with no day (a missing record) holds for the rest of the day only
// when the edge is already past its cap. Within its cap it is not held,
// so its overrun later that day cuts it, with a trip, as any overrun does.
func TestDayZeroLiftWithinCap(t *testing.T) {
	x, doc, a := capped(t)
	x.d.Close()
	if err := os.Remove(filepath.Join(x.dir, fileEdgeCut)); err != nil {
		t.Fatal(err)
	}
	x.start()
	x.setListing(listingOf(t, x, doc, 7, 10, 5000, true)) // at the cap, not past it
	x.advance(readEvery)
	if w := x.b.act(a, page.ActLiftEdge, ""); w.Code != http.StatusOK {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	if cut, _ := x.d.edge.held(traffic.Day(x.d.dp.Now())); cut {
		t.Fatal("fixture: not lifted")
	}
	if _, lifted := x.d.edge.held(traffic.Day(x.d.dp.Now())); lifted {
		t.Fatal("a lift of a cut with no day, within the cap, holds the edge for the day")
	}
	x.setListing(listingOf(t, x, doc, 7, 10, 6000, true))
	x.advance(readEvery)
	x.advance(readEvery)
	trips := 0
	for _, r := range x.d.alerts.Status().Open {
		if r.Kind == alert.Trip && r.Device == edgeDevice {
			trips++
		}
	}
	if cut, _ := x.d.edge.Cut(); !cut || trips != 1 {
		t.Fatalf("an overrun after the lift: cut %v, %d trips", cut, trips)
	}
	// The day unreadable holds every cap spent, which counts as past. The
	// table unread does not (#5445 item 1): its spend is the drop's, and a
	// lift in that window would otherwise hold the whole day after the
	// table reads again.
	x.setListing(listingOf(t, x, doc, 7, 10, 6000, true))
	x.d.fwMu.Lock()
	c := x.d.net.counter
	x.d.net.unread = true
	x.d.net.counter = traffic.NewCounter(x.d.dp.Now, traffic.CapsOf(doc))
	x.d.fwMu.Unlock()
	unread := x.d.edgePast()
	x.d.fwMu.Lock()
	x.d.net.unread, x.d.net.counter = false, nil
	x.d.fwMu.Unlock()
	spent := x.d.edgePast()
	x.d.fwMu.Lock()
	x.d.net.counter = c
	x.d.fwMu.Unlock()
	if unread || !spent {
		t.Fatalf("past %v with the table unread (want false), %v with the day unreadable (want true)", unread, spent)
	}
}

// TestEdgeCutSavedAtClose (#5014): a trip whose write the disk refused is
// saved at a clean stop, so the restart finds the edge cut; and the cut
// is never written to the firewall before its first load.
func TestEdgeCutSavedAtClose(t *testing.T) {
	x, doc, _ := capped(t)
	x.fail(fileEdgeCut, true)
	x.setListing(listingOf(t, x, doc, 7, 10, 6000, true))
	x.advance(readEvery)
	x.fail(fileEdgeCut, false)
	x.restart()
	// The restart's first reading still finds the edge past its cap: a
	// second trip there would mean the record was not on disk.
	if cut, _ := x.d.edge.Cut(); !cut || x.logs("byte caps: edge: ") != 1 {
		t.Fatal("an unsaved trip was not saved at close")
	}
	// A running table the drop cannot be read against (nft.Drops refuses
	// it): the cut is not written, so the next tick loads in full with it.
	x.fire.mu.Lock()
	good, loads := x.fire.listing, len(x.fire.loads)
	x.fire.listing = []byte(`{"nftables": [{"quota": "unreadable"}]}`)
	x.fire.mu.Unlock()
	x.d.loadCut()
	x.d.fwMu.Lock()
	reload := x.d.net.reload
	x.d.fwMu.Unlock()
	x.fire.mu.Lock()
	x.fire.listing = good
	x.fire.mu.Unlock()
	if !reload {
		t.Fatal("a drop that could not be built asked for no full load")
	}
	x.advance(time.Second)
	x.fire.mu.Lock()
	carried := len(x.fire.loads) > loads && strings.Contains(x.fire.loads[len(x.fire.loads)-1], `add rule inet enforcer cut_edge counter name "edge_cut" drop`)
	x.fire.mu.Unlock()
	if !carried {
		t.Fatal("the full load after a drop that could not be built does not carry the cut")
	}
	d := &Enforcer{edge: x.d.edge}
	d.loadCut() // no first load yet: nothing to write, and no firewall reached
	if d.net.reload {
		t.Fatal("a cut before the first load asked for a load")
	}
}

// TestReadingBeforeLoad (Potency 6656589394): a full load starts new
// counters, so the bytes since the last reading are read from the table
// it replaces first; 600 + 300 + 200 bytes against a cap of 1000 trip,
// although a load came between the readings.
func TestReadingBeforeLoad(t *testing.T) {
	x, doc, a := capped(t)
	x.setListing(listing(t, x, doc, 7, 600))
	x.advance(readEvery)
	next := x.current()
	next.EdgeCap = 6000
	if w := x.b.approve(a, next); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	x.advance(time.Duration(policy.Wait)*time.Millisecond - 5*time.Second)
	x.setListing(listing(t, x, doc, 7, 900))
	x.advance(5 * time.Second) // the load, with no reading due
	if x.current().EdgeCap != 6000 {
		t.Fatal("fixture: the change did not land")
	}
	x.setListing(listing(t, x, next, 8, 200))
	x.advance(readEvery)
	waitUntil(t, "the core tripped at 1100 of 1000 bytes", func() bool { return x.d.cut.Stage() == channel.Tripped })
}

// TestReadingAtClose (Potency 6656589394): a clean stop takes a last
// reading, so a restart loses none of the day's bytes.
func TestReadingAtClose(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listing(t, x, doc, 7, 600))
	x.advance(readEvery)
	x.setListing(listing(t, x, doc, 7, 900))
	x.restart()
	x.setListing(listing(t, x, doc, 8, 200))
	x.advance(readEvery)
	if x.d.cut.Stage() != channel.Tripped {
		t.Fatal("bytes sent before a clean restart were lost: 1100 of 1000 did not trip")
	}
}

// TestWakeRestarts (Potency 6656589394 release): a Wake-on-LAN relay
// that stops on its own is started again.
func TestWakeRestarts(t *testing.T) {
	x, _ := enrolled(t, false)
	r, err := wol.New(x.cfg.Layout, []wol.Machine{{MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, Iface: "hh0"}})
	if err != nil {
		t.Fatal(err)
	}
	x.d.net.relay = r
	var mu sync.Mutex
	runs := 0
	x.d.dp.Wake = func(context.Context, *wol.Relay) error {
		mu.Lock()
		runs++
		mu.Unlock()
		return errors.New("socket closed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.d.ServeWake(ctx) }()
	count := func() int { mu.Lock(); defer mu.Unlock(); return runs }
	waitUntil(t, "the relay ran", func() bool { return count() >= 1 })
	time.Sleep(wakeRetry / 3)
	if n := count(); n != 1 {
		t.Fatalf("the relay ran %d times within a third of wakeRetry", n)
	}
	waitUntil(t, "the relay started again", func() bool { return count() >= 2 })
	if !strings.Contains(x.logText(), "wake: relay stopped, started again in "+wakeRetry.String()+": socket closed") {
		t.Fatalf("the relay's stop was not logged: %q", x.logText())
	}
	// Ended during the wait: it returns at once and runs no more.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(wakeRetry / 2):
		t.Fatal("ServeWake waited out its retry after its end")
	}
	if n := count(); n != 2 {
		t.Fatalf("the relay ran %d times, want 2", n)
	}
}

// TestWakeEndQuiet: a relay that ends with ServeWake's end is not logged
// as stopping on its own.
func TestWakeEndQuiet(t *testing.T) {
	x, _ := enrolled(t, false)
	r, err := wol.New(x.cfg.Layout, []wol.Machine{{MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, Iface: "hh0"}})
	if err != nil {
		t.Fatal(err)
	}
	x.d.net.relay = r
	started := make(chan struct{})
	x.d.dp.Wake = func(ctx context.Context, _ *wol.Relay) error { close(started); <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.d.ServeWake(ctx) }()
	<-started
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(x.logText(), "wake: relay stopped") {
		t.Fatal("the relay's end with ServeWake's was logged as a stop")
	}
}

// TestTrafficRead (traffic ENF-i-5): the channel's traffic read is the
// running table's summary for a device of the loaded document.
func TestTrafficRead(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listing(t, x, doc, 7, 10))
	if _, err := x.d.trafficRead("nosuch"); !errors.Is(err, traffic.ErrUnknown) {
		t.Fatalf("a device outside the policy: %v", err)
	}
	if _, err := x.d.trafficRead("nosuch"); !errors.Is(err, traffic.ErrUnknown) {
		t.Fatalf("a second read: %v", err)
	}
}

// TestServeWake: with no machine to wake the relay waits for the end.
func TestServeWake(t *testing.T) {
	x, _ := enrolled(t, false)
	var mu sync.Mutex
	runs := 0
	x.d.dp.Wake = func(ctx context.Context, _ *wol.Relay) error {
		mu.Lock()
		runs++
		mu.Unlock()
		<-ctx.Done()
		return nil
	}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		if runs != 0 {
			t.Errorf("with no machine the relay ran %d times", runs)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.d.ServeWake(ctx) }()
	select {
	case <-done:
		t.Fatal("ServeWake returned before its end")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestReadingFailuresLogged: a reading that fails before a load or at a
// clean stop is logged, and neither the load nor the stop waits on it.
func TestReadingFailuresLogged(t *testing.T) {
	x, _, a := capped(t)
	x.setListing([]byte("{}"))
	next := x.current()
	next.EdgeCap = 6000
	if w := x.b.approve(a, next); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if x.current().EdgeCap != 6000 || !strings.Contains(x.logText(), "byte caps: before the load: reading") {
		t.Fatal("a failed reading before a load was not logged, or held the load back")
	}
	x.enforced()
	x.restart()
	if !strings.Contains(x.logText(), "byte caps: at close: reading") {
		t.Fatal("a failed reading at close was not logged")
	}
}

// crash is a daemon that dies without Close (a panic, SIGKILL or OOM
// kill) and starts again on the same boot: the running table survives.
func (x *box) crash() {
	x.t.Helper()
	old := x.d
	x.start()
	x.t.Cleanup(func() {
		old.net.mdnsMu.Lock()
		old.stopMDNSLocked()
		old.net.mdnsMu.Unlock()
	})
}

// TestReadingAfterCrash (Potency 6656993166): the first load after a crash
// reads the table the dead process loaded, against the document it
// loaded (fileLoaded), so its bytes since the last reading count: 600 +
// 300 + 200 against a cap of 1000 trip across a crash.
func TestReadingAfterCrash(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listing(t, x, doc, 7, 600))
	x.advance(readEvery)
	x.setListing(listing(t, x, doc, 7, 900))
	x.crash()
	x.setListing(listing(t, x, doc, 8, 200))
	x.advance(readEvery)
	waitUntil(t, "the core tripped at 1100 of 1000 bytes across a crash", func() bool { return x.d.cut.Stage() == channel.Tripped })
}

// TestNoDoubleCountAfterStop: after a clean stop, the first load reads the
// same counters again and counts nothing twice.
func TestNoDoubleCountAfterStop(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listing(t, x, doc, 7, 900))
	x.advance(readEvery)
	x.restart()
	x.restart()
	if x.d.cut.Stage() != channel.Open {
		t.Fatal("900 bytes counted twice across clean restarts")
	}
	if g := x.d.net.counter.Drop().Groups; len(g) != 1 || g[0].Count != 900 {
		t.Fatalf("day's count %+v, want 900", g)
	}
}

// TestLoadedDocumentUnreadable: a saved loaded document that does not
// read back is logged, and the first load then reads nothing against it.
func TestLoadedDocumentUnreadable(t *testing.T) {
	x, _, _ := capped(t)
	if err := os.WriteFile(filepath.Join(x.dir, fileLoaded), []byte("not a document"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.restart()
	if x.d.net.prevDoc != nil || !strings.Contains(x.logText(), "last loaded document is unreadable") {
		t.Fatal("an unreadable loaded document was used or not logged")
	}
}

// TestCrashReadUsesLoadedDocument: the dead process's table is read
// against the document it loaded, so an address only its resolver sets
// held counts to its destination, not as bytes no listed name resolved
// to; and a loaded document that cannot be saved is logged.
func TestCrashReadUsesLoadedDocument(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listing(t, x, doc, 7, 600))
	x.advance(readEvery)
	x.setListing(bytes.ReplaceAll(listing(t, x, doc, 7, 500), []byte("203.0.113.5"), []byte("203.0.113.9")))
	x.crash()
	waitUntil(t, "the core tripped across a crash", func() bool { return x.d.cut.Stage() == channel.Tripped })
	x.d.cut.mu.Lock()
	why := x.d.cut.reason
	x.d.cut.mu.Unlock()
	if !strings.Contains(why, "updates.example") {
		t.Fatalf("the crashed table was read against another document: %q", why)
	}
	x.fail(fileLoaded, true)
	x.restart()
	if !strings.Contains(x.logText(), "loaded document not saved") {
		t.Fatal("a loaded document that was not saved was not logged")
	}
}

// TestWakeConfigured: a configured machine runs a relay, and a machine
// list that does not read fails the start, the configuration's check
// aside.
func TestWakeConfigured(t *testing.T) {
	x, _ := enrolled(t, false)
	x.cfg.Wake = []WakeMachine{{MAC: "02:00:00:00:00:01", Iface: "hh0"}}
	x.restart()
	if x.d.net.relay == nil {
		t.Fatal("a configured machine runs no Wake-on-LAN relay")
	}
	x.d.Close()
	x.cfg.Wake = []WakeMachine{{MAC: "zz", Iface: "hh0"}}
	if d, err := x.open(); err == nil || !strings.Contains(err.Error(), "wake:") {
		if d != nil {
			d.Close()
		}
		t.Fatalf("a bad machine list started: %v", err)
	}
	x.cfg.Wake = nil
	x.start()
}

// TestTrafficStateUnreadableFailsStart: a byte-cap day that cannot be read
// at all (not one that reads back wrong) fails the start.
func TestTrafficStateUnreadableFailsStart(t *testing.T) {
	x, _ := enrolled(t, false)
	x.d.Close()
	if err := os.Mkdir(filepath.Join(x.dir, fileTraffic), 0o700); err != nil {
		t.Fatal(err)
	}
	if d, err := x.open(); err == nil || !strings.Contains(err.Error(), "byte caps:") {
		if d != nil {
			d.Close()
		}
		t.Fatalf("an unreadable day started: %v", err)
	}
	if err := os.Remove(filepath.Join(x.dir, fileTraffic)); err != nil {
		t.Fatal(err)
	}
	x.start()
}

// TestFirewallContextsEnd: the quota probe's and a reading's timeouts are
// released when each is done.
func TestFirewallContextsEnd(t *testing.T) {
	x, doc, _ := capped(t)
	x.fire.mu.Lock()
	qctx := x.fire.quotaCtx
	x.fire.mu.Unlock()
	if qctx == nil || qctx.Err() == nil {
		t.Fatal("the quota probe's context outlived the start")
	}
	x.setListing(listing(t, x, doc, 7, 10))
	x.advance(readEvery)
	x.fire.mu.Lock()
	lctx := x.fire.listCtx
	x.fire.mu.Unlock()
	if lctx == nil || lctx.Err() == nil {
		t.Fatal("a reading's context outlived the reading")
	}
}

// TestRefusedFirstLoadStopsResolver: a start whose first load is refused
// stops the resolver it started.
func TestRefusedFirstLoadStopsResolver(t *testing.T) {
	x, _ := enrolled(t, false)
	x.d.Close()
	x.dns.mu.Lock()
	closed := x.dns.closed
	x.dns.mu.Unlock()
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	if d, err := x.open(); err == nil {
		d.Close()
		t.Fatal("a refused first load started")
	}
	x.dns.mu.Lock()
	again := x.dns.closed
	x.dns.mu.Unlock()
	if again == closed {
		t.Fatal("a refused first load left the resolver running")
	}
	x.start()
}

// TestUnreadableTableRefusesLoad: a running table that lists but does not
// parse refuses the load, rather than loading the drop alone.
func TestUnreadableTableRefusesLoad(t *testing.T) {
	x, _ := enrolled(t, false)
	x.setListing([]byte("not a table"))
	before := x.fire.last()
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), home())
	x.d.fwMu.Unlock()
	if err == nil || x.fire.last() != before {
		t.Fatalf("a table that does not parse loaded: %v", err)
	}
}

// TestReadingStepsFail: each step of a reading that fails is logged with
// its cause, and no drop update follows a failed one.
func TestReadingStepsFail(t *testing.T) {
	x, doc, _ := capped(t)
	updates := func() int { x.fire.mu.Lock(); defer x.fire.mu.Unlock(); return len(x.fire.updates) }
	try := func(at func(int) ([]byte, error, bool), want string) {
		t.Helper()
		x.fire.mu.Lock()
		x.fire.listing, x.fire.listed, x.fire.listAt = listing(t, x, doc, 7, 10), 0, at
		x.fire.mu.Unlock()
		n, logged := updates(), len(x.logText())
		x.advance(readEvery)
		// Only the log this try added: an earlier try's line must not
		// stand in for this one's.
		if added := x.logText()[logged:]; !strings.Contains(added, want) {
			t.Fatalf("log added %q, want %q", added, want)
		}
		if updates() != n {
			t.Fatalf("a drop update followed %q", want)
		}
	}
	try(func(n int) ([]byte, error, bool) { return nil, errors.New("nft: gone"), n == 1 }, "byte caps: reading: nft: gone")
	try(func(n int) ([]byte, error, bool) { return nil, errors.New("nft: lost"), n == 2 }, "byte caps: drop: nft: lost")
	try(func(n int) ([]byte, error, bool) { return []byte("not a table"), nil, n == 2 }, "byte caps: drop: ")
	x.fire.mu.Lock()
	x.fire.listAt = nil
	x.fire.mu.Unlock()
}

// TestDropRefusedRefusesLoad (Security 6667888036 point 1): a saved day
// that restores but whose drop nft refuses (a zoned address) refuses the
// load, so no ruleset loads without its byte-cap drop.
func TestDropRefusedRefusesLoad(t *testing.T) {
	x, _, _ := capped(t)
	x.d.Close()
	x.mu.Lock()
	day := traffic.Day(x.now)
	x.mu.Unlock()
	b := []byte(`{"day":` + strconv.Itoa(int(day)) + `,"dests":{"fe80::1%eth0":["updates.example"]}}`)
	if err := os.WriteFile(filepath.Join(x.dir, fileTraffic), b, 0o600); err != nil {
		t.Fatal(err)
	}
	before := x.fire.last()
	if d, err := x.open(); err == nil {
		d.Close()
		t.Fatal("a load whose drop is refused went ahead")
	}
	if x.fire.last() != before {
		t.Fatal("a ruleset loaded without its byte-cap drop")
	}
	if err := os.Remove(filepath.Join(x.dir, fileTraffic)); err != nil {
		t.Fatal(err)
	}
	x.start()
}

var quotaLine = regexp.MustCompile(`add quota inet \S+ (q|qe)_\S+ \{ over (\d+) bytes used (\d+) bytes; \}`)

// spentIn is whether the last full load starts the core's group quota and
// the edge's quota spent (used at the limit).
func spentIn(t *testing.T, x *box) (core, edge bool) {
	t.Helper()
	n := 0
	for _, m := range quotaLine.FindAllStringSubmatch(x.fire.last(), -1) {
		n++
		spent := m[2] == m[3]
		if m[1] == "q" {
			core = spent
		} else {
			edge = spent
		}
	}
	if n != 2 {
		t.Fatalf("%d quotas in the last load, want the core's group and the edge's:\n%s", n, x.fire.last())
	}
	return core, edge
}

// TestMergingPortHeldAtItsCaps (ENF-cap-gro-fu, #5088; NET-2 Byte caps):
// the daemon asks for merging off on the core's and the edge's ports, one
// at a time. A port that stays merging does not stop the start: its caps
// are loaded spent, so every capped send it carries is dropped, and the
// other port keeps its count. Once it reads clean at a reading, a full
// load starts its quotas from the count again.
func TestMergingPortHeldAtItsCaps(t *testing.T) {
	x, _, _ := capped(t)
	core, edge := x.cfg.Layout.Core, x.cfg.Layout.Edge
	if c, e := spentIn(t, x); c || e {
		t.Fatalf("caps spent with no port merging: core %v, edge %v", c, e)
	}
	x.d.Close()
	x.mu.Lock()
	x.offloads = nil
	x.mu.Unlock()
	x.merges(core, errors.New("offload: a feature stays as it was: core0: rx-gro on"))
	x.start()
	x.mu.Lock()
	got, want := x.offloads, [][]string{{core}, {edge}}
	x.mu.Unlock()
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("asked for merging off on %v, want %v", got, want)
	}
	if c, e := spentIn(t, x); !c || e {
		t.Fatalf("the core's port merging: core spent %v (want true), edge spent %v (want false)", c, e)
	}
	if !strings.Contains(x.logText(), "byte caps: "+core+" merges segments, every capped send it carries is dropped until it stops: offload: a feature stays as it was: core0: rx-gro on") {
		t.Fatalf("not logged:\n%s", x.logText())
	}

	loads := func() int { x.fire.mu.Lock(); defer x.fire.mu.Unlock(); return len(x.fire.loads) }
	n := loads()
	x.merges(core, nil)
	x.merges(edge, errors.New("offload: edge0: no such device"))
	x.advance(readEvery)
	if loads() != n+1 {
		t.Fatalf("%d full loads when the ports changed, want 1", loads()-n)
	}
	if c, e := spentIn(t, x); c || !e {
		t.Fatalf("the edge's port merging: core spent %v (want false), edge spent %v (want true)", c, e)
	}
	// Its quota is spent, not counted, so the kernel does not cut the edge
	// at it (nft.Drop.EdgeHold, #5282).
	if strings.Contains(x.fire.last(), edgeTripRule) {
		t.Fatal("the edge's port merging: the kernel cuts the edge at a quota held spent")
	}
	x.advance(readEvery)
	if loads() != n+1 {
		t.Fatal("a full load with no port changed")
	}
	x.merges(edge, nil)
	x.advance(readEvery)
	if c, e := spentIn(t, x); c || e || !strings.Contains(x.fire.last(), edgeTripRule) {
		t.Fatalf("caps still spent once both ports read clean, or the kernel's cut of the edge not back: core %v, edge %v", c, e)
	}
	if !strings.Contains(x.logText(), "byte caps: "+edge+" merges no segments again, its caps count again") {
		t.Fatalf("the end not logged:\n%s", x.logText())
	}
}

// TestMergingReloadRetried (ENF-l-16, #5103 item 2): a port that starts
// merging asks for a full load; while that load keeps failing, a reading
// that finds the ports unchanged keeps the ask, so the load still comes
// once the firewall takes it, with the port's caps spent.
func TestMergingReloadRetried(t *testing.T) {
	x, _, _ := capped(t)
	core := x.cfg.Layout.Core
	loads := func() int { x.fire.mu.Lock(); defer x.fire.mu.Unlock(); return len(x.fire.loads) }
	refuse := func() { x.fire.mu.Lock(); x.fire.fail = true; x.fire.mu.Unlock() }
	n := loads()
	x.merges(core, errors.New("offload: core0: rx-gro on"))
	refuse()
	x.advance(readEvery)
	if loads() != n {
		t.Fatal("fixture: the load was not refused")
	}
	refuse() // the next tick's retry fails too, and the reading after it finds no change
	x.advance(readEvery)
	if loads() != n {
		t.Fatal("fixture: the retry was not refused")
	}
	x.advance(time.Second)
	if loads() != n+1 {
		t.Fatalf("%d full loads once the firewall takes one again, want 1: a reading with no change dropped the ask", loads()-n)
	}
	if c, _ := spentIn(t, x); !c {
		t.Fatal("the core's caps are not spent while its port merges")
	}
}

// TestMergeHoldOutlivesARefusedLoad (#5399 item 5, NET-2 Byte caps): the
// edge's quota held spent while its port merged segments still runs after
// the merge ends, until a full load starts it from the count. A refused
// load leaves it running, so the readings' drops keep the edge held: a
// spent quota would otherwise fill TripSet and cut an edge within its cap
// with no record to lift. The load the firewall takes ends the hold.
func TestMergeHoldOutlivesARefusedLoad(t *testing.T) {
	x, doc, _ := capped(t)
	edge := x.cfg.Layout.Edge
	x.setListing(listingOf(t, x, doc, 7, 10, 100, true))
	lastUpdate := func() string {
		x.fire.mu.Lock()
		defer x.fire.mu.Unlock()
		return x.fire.updates[len(x.fire.updates)-1]
	}
	loads := func() int { x.fire.mu.Lock(); defer x.fire.mu.Unlock(); return len(x.fire.loads) }
	refuse := func() { x.fire.mu.Lock(); x.fire.fail = true; x.fire.mu.Unlock() }
	// The merge starts and the load it asks for is refused: the edge is
	// held from the start, though its quota is not spent yet.
	n := loads()
	x.merges(edge, errors.New("offload: edge0: rx-gro on"))
	refuse()
	x.advance(readEvery)
	if loads() != n || strings.Contains(lastUpdate(), edgeTripRule) {
		t.Fatal("a merge whose load was refused leaves the edge unheld")
	}
	x.advance(time.Second)
	if _, e := spentIn(t, x); !e || strings.Contains(lastUpdate(), edgeTripRule) {
		t.Fatal("fixture: the edge's port merging is not held spent")
	}
	n = loads()
	x.merges(edge, nil)
	refuse()
	x.advance(readEvery)
	if loads() != n {
		t.Fatal("fixture: the load after the merge ended was not refused")
	}
	if strings.Contains(lastUpdate(), edgeTripRule) {
		t.Fatal("a reading after a refused load lets TripSet cut the edge while its spent quota still runs")
	}
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("the edge was cut within its cap")
	}
	x.advance(time.Second)
	if loads() != n+1 {
		t.Fatal("the full load was not retried")
	}
	if _, e := spentIn(t, x); e || !strings.Contains(x.fire.last(), edgeTripRule) {
		t.Fatal("the load the firewall took kept the edge held, or its quota spent")
	}
	x.advance(readEvery)
	if !strings.Contains(lastUpdate(), edgeTripRule) {
		t.Fatal("the reading after the load the firewall took keeps the edge held")
	}
}

// TestReadingDropRefused (#5399 item 2): a reading whose running table the
// drop cannot be built against, or whose TripSet does not read, writes no
// drop and records no cut; the reading's error says so.
func TestReadingDropRefused(t *testing.T) {
	x, doc, _ := capped(t)
	good := listingOf(t, x, doc, 7, 10, 100, true)
	var o map[string][]map[string]any
	if err := json.Unmarshal(good, &o); err != nil {
		t.Fatal(err)
	}
	o["nftables"] = append(o["nftables"], map[string]any{"set": map[string]any{
		"family": "inet", "table": nft.Table, "name": nft.TripSet, "elem": []any{7},
	}})
	badTrip, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		running []byte
		cut     bool
	}{
		{"a table the drop refuses", []byte(`{"nftables": [{"quota": "unreadable"}]}`), false},
		{"a TripSet element that is not a name", badTrip, false},
		// Cut, so the TripSet is not read: the drop's own refusal stops it.
		{"a table the drop refuses, the edge cut", []byte(`{"nftables": [{"quota": "unreadable"}]}`), true},
	} {
		x.d.edge.mu.Lock()
		x.d.edge.st.Cut = c.cut
		x.d.edge.mu.Unlock()
		x.fire.mu.Lock()
		first := x.fire.listed + 1
		x.fire.listAt = func(n int) ([]byte, error, bool) {
			if n == first {
				return good, nil, true
			}
			return c.running, nil, true
		}
		ups := len(x.fire.updates)
		x.fire.mu.Unlock()
		over, kernelCut, err := x.d.readCapsLocked(context.Background())
		x.fire.mu.Lock()
		x.fire.listAt = nil
		wrote := len(x.fire.updates) != ups
		x.fire.mu.Unlock()
		if err == nil || !strings.HasPrefix(err.Error(), "drop: ") || wrote || kernelCut != "" || len(over) != 0 {
			t.Errorf("%s: %v, update written %v, kernel cut %q", c.name, err, wrote, kernelCut)
		}
	}
}

// TestKernelCutRecorded (#5399 item 2, KRN-12): the record follows the
// kernel's cut. A reading whose running table has TripSet holding the
// edge trips the record, with its card and lift, even while the count is
// within the cap; not while the edge is held (the owner lifted it today),
// and not when the set belongs to another day's quota, which the drop
// empties.
func TestKernelCutRecorded(t *testing.T) {
	x, doc, a := capped(t)
	tripped := func(quota string) []byte {
		b := listingOf(t, x, doc, 7, 10, 100, true)
		var o map[string][]map[string]any
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		o["nftables"] = append(o["nftables"], map[string]any{"set": map[string]any{
			"family": "inet", "table": nft.Table, "name": nft.TripSet, "elem": []any{x.cfg.Layout.Edge},
		}})
		if quota != "" {
			o["nftables"] = append(o["nftables"], map[string]any{"quota": map[string]any{"family": "inet", "table": nft.Table, "name": quota}})
		}
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// Another day's edge quota running: the drop empties the set.
	x.setListing(tripped("qe_0000000000000000"))
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("a set the drop empties cut the record")
	}
	x.setListing(tripped(""))
	x.advance(readEvery)
	cut, why := x.d.edge.Cut()
	if !cut || why != "the firewall cut it at the first byte past its byte cap of 5000 bytes today. Lift the cut once you trust the edge again." {
		t.Fatalf("a kernel cut within the count: cut %v, reason %q", cut, why)
	}
	if !strings.Contains(x.logText(), "byte caps: edge: the firewall cut it") {
		t.Fatal("the kernel's cut is not logged")
	}
	if w := x.b.act(a, page.ActLiftEdge, ""); w.Code != http.StatusOK {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	x.advance(readEvery)
	if cut, _ := x.d.edge.Cut(); cut {
		t.Fatal("the set after the owner's lift today cut the record again")
	}
	// The channel's counts read follows the kernel's cut too.
	x.d.edge.mu.Lock()
	x.d.edge.st.Lifted = 0
	x.d.edge.mu.Unlock()
	if _, err := x.d.counts(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for cut, _ := x.d.edge.Cut(); !cut; cut, _ = x.d.edge.Cut() {
		if time.Now().After(deadline) {
			t.Fatal("the channel's counts read left the kernel's cut unrecorded")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestServedInterfacesHeld (ENF-net-ra-off, #4222; ENF-l-21): the served
// interfaces are set up and checked before the first load starts any
// resolver instance, and again at every reading. While the check fails
// every instance stops (the firewall still loads), the failure is logged
// once, and the instances start again on the policy's files once it
// passes; a start with the check failing runs no instance at all.
func TestServedInterfacesHeld(t *testing.T) {
	x, _ := enrolled(t, false)
	want, err := dns.Generate(home(), x.cfg.Layout, x.cfg.DNS)
	if err != nil {
		t.Fatal(err)
	}
	calls := func() int { x.mu.Lock(); defer x.mu.Unlock(); return x.served }
	loads := func() int { x.fire.mu.Lock(); defer x.fire.mu.Unlock(); return len(x.fire.loads) }
	if calls() == 0 || len(x.dns.last().Listed) == 0 {
		t.Fatalf("%d checks, files %v: the resolver runs unchecked or not at all", calls(), x.dns.last())
	}
	n, l := calls(), loads()
	x.advance(readEvery)
	if calls() != n+1 || loads() != l {
		t.Fatalf("a reading made %d checks and %d loads, want 1 and 0", calls()-n, loads()-l)
	}

	bad := "served interface own0 holds 10.99.0.1/24, outside 10.10.0.0/24"
	x.mu.Lock()
	x.servedErr = errors.New(bad)
	x.mu.Unlock()
	x.advance(readEvery)
	if loads() != l+1 {
		t.Fatalf("%d loads at the reading that found the change, want 1", loads()-l)
	}
	if got := x.dns.last(); len(got.Listed) != 0 || got.People != "" || got.DHCP != "" {
		t.Fatalf("instances still run with a served interface not as set up: %v", got)
	}
	x.advance(readEvery)
	if loads() != l+1 {
		t.Fatal("a full load with nothing changed")
	}
	if c := strings.Count(x.logText(), "dns: a served interface is not as set up, every resolver instance stops until it is: "+bad); c != 1 {
		t.Fatalf("the failure logged %d times:\n%s", c, x.logText())
	}

	x.restart()
	if got := x.dns.last(); len(got.Listed) != 0 || got.People != "" || got.DHCP != "" {
		t.Fatalf("a start with the check failing ran instances: %v", got)
	}
	x.mu.Lock()
	x.servedErr = nil
	x.mu.Unlock()
	l = loads()
	x.advance(readEvery)
	if loads() != l+1 {
		t.Fatalf("%d loads once the interfaces pass again, want 1", loads()-l)
	}
	if got := x.dns.last(); !slices.Equal(got.Listed, want.Listed) || got.People != want.People || got.DHCP != want.DHCP {
		t.Fatal("the resolver did not start again on the policy's files")
	}
	if c := strings.Count(x.logText(), "dns: the served interfaces are as set up again, the resolver starts"); c != 1 {
		t.Fatalf("the end logged %d times:\n%s", c, x.logText())
	}
}

// TestRefusedLoadKeepsResolverStopped (#5164 item 7): with a served
// interface not as set up, the instances stop before the load, so a
// refused load, which starts the stopped ones again, brings back none.
// Then (R5 a) the stray goes and the next load is refused too: at the
// Apply seam still none runs, and home still shows the stop, now by the
// firewall's refusal; once a load is taken they run and home clears.
func TestRefusedLoadKeepsResolverStopped(t *testing.T) {
	x, _ := enrolled(t, false)
	x.dns.mu.Lock()
	was := x.dns.running
	x.dns.mu.Unlock()
	if len(was.Listed) == 0 {
		t.Fatal("fixture: no instance runs")
	}
	x.mu.Lock()
	x.servedErr = errors.New("served interface own0 holds 10.99.0.1/24, outside 10.10.0.0/24")
	x.mu.Unlock()
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	x.d.fwMu.Lock()
	err := x.d.loadNetwork(context.Background(), home())
	x.d.fwMu.Unlock()
	if err == nil {
		t.Fatal("fixture: the load was not refused")
	}
	x.dns.mu.Lock()
	got := x.dns.running
	x.dns.mu.Unlock()
	if len(got.Listed) != 0 || got.People != "" || got.DHCP != "" {
		t.Fatalf("a refused load left instances running with the check failing: %v", got)
	}
	// The page reads the instances it stopped as stopped, refused load
	// or not (#5164 R1).
	if !(pageResolver{x.d}).Stopped().Stopped {
		t.Fatal("the page shows a resolver as running after its instances stopped")
	}

	x.mu.Lock()
	x.servedErr = nil
	x.mu.Unlock()
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	x.d.fwMu.Lock()
	err = x.d.loadNetwork(context.Background(), home())
	x.d.fwMu.Unlock()
	if err == nil {
		t.Fatal("fixture: the second load was not refused")
	}
	x.dns.mu.Lock()
	got = x.dns.running
	x.dns.mu.Unlock()
	if len(got.Listed) != 0 || got.People != "" || got.DHCP != "" {
		t.Fatalf("a refused load with the stray gone started instances: %v", got)
	}
	stop := (pageResolver{x.d}).Stopped()
	if !stop.Stopped || len(stop.Strays)+len(stop.Unset) != 0 || stop.Load != page.LoadFirewall {
		t.Fatalf("the page after the stray went and the load was refused: %#v", stop)
	}
	h := x.b.do(http.MethodGet, "/", nil).Body.String()
	if !strings.Contains(h, "The firewall refused the enforcer&#39;s last load of your rules; the enforcer&#39;s log has the detail.") || strings.Contains(h, "nft: refused") || strings.Contains(h, "Interface own0 holds") {
		t.Fatalf("home does not show the refused load in place of the stray:\n%s", h)
	}
	x.d.fwMu.Lock()
	err = x.d.loadNetwork(context.Background(), home())
	x.d.fwMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	x.dns.mu.Lock()
	got = x.dns.running
	x.dns.mu.Unlock()
	if !slices.Equal(got.Listed, was.Listed) || got.People != was.People || got.DHCP != was.DHCP {
		t.Fatalf("the load taken did not start the instances: %v", got)
	}
	if stop := (pageResolver{x.d}).Stopped(); stop.Stopped || stop.Load != page.LoadTaken || strings.Contains(x.b.do(http.MethodGet, "/", nil).Body.String(), "Names and addresses") {
		t.Fatalf("the load is taken and home still shows the stop: %#v", stop)
	}
}

// TestLoadStepOnPage (#5164 R5 d): a load refused because the document
// does not compile reads as that, not as the firewall's refusal, and
// one the firewall refuses as the firewall's; an error of neither kind
// is untyped. A document that does not compile never reaches the
// firewall.
func TestLoadStepOnPage(t *testing.T) {
	x, _ := enrolled(t, false)
	load := func(doc policy.Document) error {
		x.d.fwMu.Lock()
		defer x.d.fwMu.Unlock()
		return x.d.loadNetwork(context.Background(), doc)
	}
	// Stop the instances first, so the page shows the load's cause: a
	// stray, then a load the firewall refuses once the stray is gone.
	x.mu.Lock()
	x.servedErr = errors.New("served interface own0 holds 10.99.0.1/24, outside 10.10.0.0/24")
	x.mu.Unlock()
	if err := load(home()); err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	x.servedErr = nil
	x.mu.Unlock()
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	if err := load(home()); err == nil {
		t.Fatal("fixture: the load was not refused")
	}
	if stop := (pageResolver{x.d}).Stopped(); !stop.Stopped || stop.Load != page.LoadFirewall {
		t.Fatalf("the firewall's refusal on the page: %#v", stop)
	}
	bad := home()
	bad.Devices = append(bad.Devices, policy.Device{ID: "plug", Network: policy.NetDevices, WiFi: "not-a-vlan", Everyday: true})
	x.fire.mu.Lock()
	n := len(x.fire.ctxs)
	x.fire.mu.Unlock()
	err := load(bad)
	if !errors.Is(err, nft.ErrPolicy) {
		t.Fatalf("fixture: the document compiled (%v)", err)
	}
	x.fire.mu.Lock()
	reached := len(x.fire.ctxs) != n
	x.fire.mu.Unlock()
	if reached {
		t.Fatal("a document that does not compile reached the firewall")
	}
	if stop := (pageResolver{x.d}).Stopped(); !stop.Stopped || stop.Load != page.LoadCompile {
		t.Fatalf("a compile refusal on the page: %#v", stop)
	}
	h := x.b.do(http.MethodGet, "/", nil).Body.String()
	if !strings.Contains(h, "The enforcer could not make firewall rules of the policy in force, so it loaded nothing;") || strings.Contains(h, "The firewall refused") || strings.Contains(h, "not-a-vlan") {
		t.Fatalf("home words a compile refusal as the firewall's:\n%s", h)
	}
	// A running table the firewall returned that does not parse is no
	// policy that failed to compile: untyped.
	x.fire.mu.Lock()
	x.fire.listing = []byte("{not json")
	x.fire.mu.Unlock()
	err = load(home())
	if err == nil || errors.Is(err, nft.ErrPolicy) {
		t.Fatalf("fixture: an unreadable running table: %v", err)
	}
	if stop := (pageResolver{x.d}).Stopped(); stop.Load != page.LoadUntyped {
		t.Fatalf("an unreadable running table on the page: %#v", stop)
	}
	if h := x.b.do(http.MethodGet, "/", nil).Body.String(); !strings.Contains(h, "The enforcer&#39;s last load of your rules failed; its log has the detail.") || strings.Contains(h, "could not make firewall rules") || strings.Contains(h, "not json") {
		t.Fatalf("home words an unreadable running table as a compile refusal:\n%s", h)
	}
	for _, tc := range []struct {
		err  error
		want page.LoadStep
	}{
		{compileErr{nft.ErrPolicy}, page.LoadCompile},
		{compiled(fmt.Errorf("%w: device", nft.ErrPolicy)), page.LoadCompile},
		{compiled(nft.ErrLayout), page.LoadUntyped},
		{fmt.Errorf("wrapped: %w", fireErr{errors.New("nft: refused")}), page.LoadFirewall},
		{errors.New("dns/run: refused: closed"), page.LoadUntyped},
	} {
		if got := loadStep(tc.err); got != tc.want {
			t.Errorf("loadStep(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

// TestRestartingResolverOnPage (#5164 R5 b): while the instances run,
// each that keeps exiting shows on home by what it serves, with its
// exits in a row, from dns/run's Flapping; every instance name dns/run
// gives the policy's files maps to a part the page words.
func TestRestartingResolverOnPage(t *testing.T) {
	x, _ := enrolled(t, false)
	if stop := (pageResolver{x.d}).Stopped(); stop.Stopped || len(stop.Restarting) != 0 {
		t.Fatalf("fixture: %#v", stop)
	}
	x.dns.mu.Lock()
	running := x.dns.running
	x.dns.flaps = []dnsrun.Flap{{Name: "listed-" + running.Listed[0].Iface, Exits: 3}, {Name: "dhcp", Exits: 1}}
	x.dns.mu.Unlock()
	stop := (pageResolver{x.d}).Stopped()
	want := []page.Restart{{Part: page.PartListed, Iface: running.Listed[0].Iface, Exits: 3}, {Part: page.PartDHCP, Exits: 1}}
	if stop.Stopped || !slices.Equal(stop.Restarting, want) {
		t.Fatalf("restarting instances on the page: %#v", stop)
	}
	h := x.b.do(http.MethodGet, "/", nil).Body.String()
	if !strings.Contains(h, "on interface "+running.Listed[0].Iface+", which only a listed name gets, stopped or could not start 3 times in a row") || !strings.Contains(h, "The enforcer&#39;s address service, which hands out addresses on the home networks, stopped or could not start and") {
		t.Fatalf("home does not show the restarting instances:\n%s", h)
	}
	for name := range dnsrun.Names(running) {
		if restartOf(dnsrun.Flap{Name: name}).Part == page.PartUntyped {
			t.Errorf("instance %q has no part the page words", name)
		}
	}
	if r := restartOf(dnsrun.Flap{Name: "people", Exits: 2}); r != (page.Restart{Part: page.PartPeople, Exits: 2}) {
		t.Errorf("people: %#v", r)
	}
	if r := restartOf(dnsrun.Flap{Name: "other"}); r != (page.Restart{}) {
		t.Errorf("an unknown instance: %#v", r)
	}
	// Stopped, the stop alone shows: no instance runs to restart.
	x.mu.Lock()
	x.servedErr = errors.New("served interface own0 holds 10.99.0.1/24, outside 10.10.0.0/24")
	x.mu.Unlock()
	x.advance(readEvery)
	if stop := (pageResolver{x.d}).Stopped(); !stop.Stopped || len(stop.Restarting) != 0 {
		t.Fatalf("a stopped resolver with restarts: %#v", stop)
	}
}

// TestHold (ENF-net-ra-off, #4222): hold turns router advertisements and
// redirects off on each served interface there and on "default", and
// reads them back; an interface not there yet is passed; every address on
// a served interface must lie in its Net's prefixes, no wider, or be the
// kernel's IPv6 link-local one. A kernel with no IPv6 has only the IPv4
// setting. A name that would reach outside the interface's directory, or
// set every interface's value, is refused.
func TestHold(t *testing.T) {
	keys := []string{"ipv4/conf/%s/accept_redirects", "ipv6/conf/%s/accept_redirects", "ipv6/conf/%s/accept_ra"}
	box := func(v6 bool, ifaces ...string) string {
		root := t.TempDir()
		all := filepath.Join(root, "ipv4/conf/all/accept_redirects")
		if err := os.MkdirAll(filepath.Dir(all), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(all, []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, i := range append([]string{"default"}, ifaces...) {
			for _, k := range keys {
				if !v6 && strings.HasPrefix(k, "ipv6") {
					continue
				}
				p := filepath.Join(root, fmt.Sprintf(k, i))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		return root
	}
	set := func(root string, v6 bool, ifaces ...string) {
		t.Helper()
		if b, err := os.ReadFile(filepath.Join(root, "ipv4/conf/all/accept_redirects")); err != nil || string(b) != "0\n" {
			t.Fatalf("all/accept_redirects: %q %v", b, err)
		}
		for _, i := range append([]string{"default"}, ifaces...) {
			for _, k := range keys {
				if !v6 && strings.HasPrefix(k, "ipv6") {
					continue
				}
				if b, err := os.ReadFile(filepath.Join(root, fmt.Sprintf(k, i))); err != nil || string(b) != "0\n" {
					t.Fatalf("%s on %s: %q %v", k, i, b, err)
				}
			}
		}
	}
	p := netip.MustParsePrefix
	nets := []dns.Net{
		{Iface: "own0", Prefix4: p("10.10.0.0/24"), Prefix6: p("fd00:10::/64"), DHCP: true},
		{Iface: "ap0.101", Prefix4: p("10.101.0.0/24")},
		{Iface: "ap0.102", Prefix4: p("10.102.0.0/24")}, // not made yet
	}
	have := map[string][]netip.Prefix{
		"own0":    {p("10.10.0.1/24"), p("fd00:10::1/64"), p("fe80::1/64")},
		"ap0.101": {p("10.101.0.1/24"), p("10.101.0.9/32")},
	}
	addrs := func(i string) ([]netip.Prefix, error) {
		a, ok := have[i]
		if !ok {
			return nil, errors.New("asked for " + i)
		}
		return a, nil
	}
	root := box(true, "own0", "ap0.101")
	if err := hold(root, nets, addrs); err != nil {
		t.Fatal(err)
	}
	set(root, true, "own0", "ap0.101")
	if _, err := os.Stat(filepath.Join(root, "ipv4/conf/ap0.102")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an interface not there yet was made: %v", err)
	}

	root = box(false, "own0", "ap0.101")
	if err := hold(root, nets, addrs); err != nil {
		t.Fatalf("no IPv6: %v", err)
	}
	set(root, false, "own0", "ap0.101")

	// An interface not served (the WAN) keeps its own settings: its link
	// configuration sets its router advertisements (ENF-l-21).
	root = box(true, "own0", "wan0")
	wan := filepath.Join(root, "ipv6/conf/wan0/accept_ra")
	if err := os.WriteFile(wan, []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := hold(root, nets[:1], addrs); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(wan); err != nil || string(b) != "2\n" {
		t.Fatalf("an interface not served was written: %q %v", b, err)
	}

	// A setting that takes the write and reads back something else (here
	// nothing: a link to /dev/null) fails, for every key hold writes, and
	// carries the setting and interface the page names (#5284).
	causes := func(err error) (out []page.Unset) {
		errs := []error{err}
		if j, ok := err.(interface{ Unwrap() []error }); ok {
			errs = j.Unwrap()
		}
		for _, e := range errs {
			var u unsetErr
			if !errors.As(e, &u) {
				t.Errorf("an untyped failure: %v", e)
			}
			out = append(out, u.cause)
		}
		return out
	}
	set6 := map[string]page.Setting{"ipv4/conf/%s/accept_redirects": page.Redirects4, "ipv6/conf/%s/accept_redirects": page.Redirects6, "ipv6/conf/%s/accept_ra": page.RouterAds}
	want := map[string]page.Unset{"ipv4/conf/all/accept_redirects": {Kind: page.UnsetSetting, Iface: "all", Setting: page.Redirects4}}
	for k, set := range set6 {
		for _, i := range []string{"default", "own0"} {
			want[fmt.Sprintf(k, i)] = page.Unset{Kind: page.UnsetSetting, Iface: i, Setting: set}
		}
	}
	for key, cause := range want {
		root = box(true, "own0")
		path := filepath.Join(root, key)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(os.DevNull, path); err != nil {
			t.Fatal(err)
		}
		err := hold(root, nets[:1], addrs)
		if err == nil || !strings.Contains(err.Error(), path+` not set to 0 (reads "")`) {
			t.Errorf("%s linked to %s: %v", key, os.DevNull, err)
		}
		if got := causes(err); !slices.Equal(got, []page.Unset{cause}) {
			t.Errorf("%s linked to %s: causes %+v, want %+v", key, os.DevNull, got, cause)
		}
	}
	// Addresses that changed while read (a dump marked interrupted, or
	// the interface made again) and any other read failure.
	for rerr, kind := range map[error]page.UnsetKind{
		fmt.Errorf("x: %w", errDumpIntr): page.UnsetChanged,
		madeAgain{"own0", 4, 9}:          page.UnsetChanged,
		errors.New("asked for own0"):     page.UnsetAddrs,
	} {
		err := hold(box(true, "own0"), nets[:1], func(string) ([]netip.Prefix, error) { return nil, rerr })
		if got := causes(err); !slices.Equal(got, []page.Unset{{Kind: kind, Iface: "own0"}}) || !errors.Is(err, rerr) {
			t.Errorf("addresses failing with %v: %v, causes %+v", rerr, err, got)
		}
	}

	for _, tc := range []struct {
		name string
		addr netip.Prefix
		want string
	}{
		{"another prefix", p("10.99.0.1/24"), "served interface own0 holds 10.99.0.1/24, outside 10.10.0.0/24 and fd00:10::/64"},
		{"a wider prefix", p("10.10.0.1/16"), "holds 10.10.0.1/16"},
		{"another IPv6 prefix", p("2001:db8::1/64"), "holds 2001:db8::1/64"},
		{"a wider IPv6 prefix", p("fd00:10::1/48"), "holds fd00:10::1/48"},
		{"a wider link-local prefix", p("fe80::1/10"), "holds fe80::1/10"},
		{"a link-local address outside fe80::/64", p("fe80:1::1/64"), "holds fe80:1::1/64"},
	} {
		have["own0"] = []netip.Prefix{p("10.10.0.1/24"), tc.addr}
		err := hold(box(true, "own0", "ap0.101"), nets, addrs)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
		// The page names the interface and the address (#5164 R1).
		var s strayAddr
		if !errors.As(err, &s) || s != (strayAddr{"own0", tc.addr, "10.10.0.0/24 and fd00:10::/64"}) {
			t.Errorf("%s: the stray is not one the page can name: %#v", tc.name, s)
		}
	}
	have["ap0.101"] = []netip.Prefix{p("10.101.0.1/24"), p("10.102.0.1/24")}
	if err := hold(box(true, "own0", "ap0.101"), nets[1:], addrs); err == nil || !strings.Contains(err.Error(), "served interface ap0.101 holds 10.102.0.1/24, outside 10.101.0.0/24") || strings.Contains(err.Error(), " and ") {
		t.Errorf("an IPv4-only net: %v", err)
	}
	delete(have, "ap0.101")
	if err := hold(box(true, "own0", "ap0.101"), nets[1:], addrs); err == nil || !strings.Contains(err.Error(), "served interface ap0.101: addresses: asked for ap0.101") {
		t.Errorf("addresses unreadable: %v", err)
	}
	for _, name := range []string{"", ".", "..", "../x", "all", "default", "a/b", "a\x00b"} {
		err := hold(box(true), []dns.Net{{Iface: name, Prefix4: p("10.1.0.0/24")}}, addrs)
		if err == nil || !strings.Contains(err.Error(), "not an interface name") || !slices.Equal(causes(err), []page.Unset{{Kind: page.UnsetName, Iface: name}}) {
			t.Errorf("interface %q: %v", name, err)
		}
	}
	// A setting that cannot be written, and a settings tree that is not
	// one (ENOTDIR, not "not there yet").
	root = box(true, "own0")
	key := filepath.Join(root, "ipv6/conf/own0/accept_ra")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(key, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := hold(root, nets[:1], func(string) ([]netip.Prefix, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "accept_ra") || !slices.Equal(causes(err), []page.Unset{{Kind: page.UnsetSetting, Iface: "own0", Setting: page.RouterAds}}) {
		t.Errorf("an unwritable setting: %v", err)
	}
	// An interface's settings that cannot be read (a loop, ELOOP) and an
	// IPv6 tree that cannot be: each fails, never reads as "not there",
	// and the IPv6 tree's by its typed cause (#5307).
	root = box(true)
	loop := filepath.Join(root, "ipv4/conf/own0")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if err := hold(root, nets[:1], addrs); err == nil {
		t.Error("an interface whose settings cannot be read passed")
	}
	root = box(true)
	v6 := filepath.Join(root, "ipv6")
	if err := os.RemoveAll(v6); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(v6, v6); err != nil {
		t.Fatal(err)
	}
	if err := hold(root, nil, addrs); err == nil || !slices.Equal(causes(err), []page.Unset{{Kind: page.UnsetIPv6}}) || !errors.Is(err, syscall.ELOOP) {
		t.Errorf("an IPv6 tree that cannot be read: %v", err)
	}
}

// TestIfaceAddrs: the kernel's addresses with their prefix lengths, read
// from loopback; a missing interface is an error. From a dump: each local
// and peer address of the interface's messages, once; a dump marked
// interrupted (NLM_F_DUMP_INTR) is taken again once, and fails if the
// second is marked too (#5164 item 8); an end carrying an error, a short
// end, no end, or anything unreadable fails, each with its own check's
// error (#5188 item 2). The index is looked up before the dump and again
// after it, and an interface made again in between, or gone, fails
// (#5188 item 1).
func TestIfaceAddrs(t *testing.T) {
	got, err := ifaceAddrs("lo")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, netip.MustParsePrefix("127.0.0.1/8")) {
		t.Fatalf("lo: %v", got)
	}
	if got, err := ifaceAddrs("agentos-none0"); err == nil {
		t.Fatalf("a missing interface read: %v", got)
	}

	ne := binary.NativeEndian
	attr := func(typ uint16, v []byte) []byte {
		b := make([]byte, 4, 4+len(v)+3)
		ne.PutUint16(b, uint16(4+len(v)))
		ne.PutUint16(b[2:], typ)
		b = append(b, v...)
		return append(b, make([]byte, (4-len(b)%4)%4)...)
	}
	msg := func(typ, flags uint16, body []byte) []byte {
		b := make([]byte, 16, 16+len(body))
		ne.PutUint32(b, uint32(16+len(body)))
		ne.PutUint16(b[4:], typ)
		ne.PutUint16(b[6:], flags)
		return append(b, body...)
	}
	addr := func(flags uint16, family, bits byte, index uint32, attrs ...[]byte) []byte {
		b := []byte{family, bits, 0, 0, 0, 0, 0, 0}
		ne.PutUint32(b[4:], index)
		for _, a := range attrs {
			b = append(b, a...)
		}
		return msg(syscall.RTM_NEWADDR, syscall.NLM_F_MULTI|flags, b)
	}
	v4 := func(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }
	v6 := func(s string) []byte { a := netip.MustParseAddr(s).As16(); return a[:] }
	done := func(flags uint16) []byte { return msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI|flags, make([]byte, 4)) }
	join := func(ms ...[]byte) []byte { return bytes.Join(ms, nil) }
	const intr = unix.NLM_F_DUMP_INTR
	clean := join(
		addr(0, syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, v4("10.1.0.1")), attr(syscall.IFA_LOCAL, v4("10.1.0.1")), attr(syscall.IFA_LABEL, []byte("own0\x00"))),
		addr(0, syscall.AF_INET, 24, 3, attr(syscall.IFA_ADDRESS, v4("10.99.0.1"))),
		addr(0, syscall.AF_INET, 32, 2, attr(syscall.IFA_LOCAL, v4("10.1.0.2")), attr(syscall.IFA_ADDRESS, v4("10.9.0.1"))),
		addr(0, syscall.AF_INET6, 64, 2, attr(syscall.IFA_ADDRESS, v6("fe80::1"))),
		done(0),
	)
	p := netip.MustParsePrefix
	want := []netip.Prefix{p("10.1.0.1/24"), p("10.1.0.2/32"), p("10.9.0.1/32"), p("fe80::1/64")}
	dumps := func(ds ...[]byte) (func() ([]byte, error), *int) {
		n := 0
		return func() ([]byte, error) {
			n++
			if n > len(ds) {
				t.Fatal("dumped more than twice")
			}
			return ds[n-1], nil
		}, &n
	}
	for _, tc := range []struct {
		name  string
		ds    [][]byte
		calls int
		ok    bool
	}{
		{"clean", [][]byte{clean}, 1, true},
		{"interrupted, then clean", [][]byte{join(addr(intr, syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, v4("10.1.0.1"))), done(0)), clean}, 2, true},
		{"its end interrupted, then clean", [][]byte{done(intr), clean}, 2, true},
		{"interrupted twice", [][]byte{done(intr), join(addr(intr, syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, v4("10.1.0.1"))), done(0))}, 2, false},
	} {
		dump, n := dumps(tc.ds...)
		got, err := addrsOf(2, dump)
		if *n != tc.calls {
			t.Errorf("%s: %d dumps, want %d", tc.name, *n, tc.calls)
		}
		if tc.ok && (err != nil || !slices.Equal(got, want)) {
			t.Errorf("%s: %v %v, want %v", tc.name, got, err, want)
		}
		if !tc.ok && (!errors.Is(err, errDumpIntr) || got != nil) {
			t.Errorf("%s: %v %v, want the interrupted dump's error", tc.name, got, err)
		}
	}
	if _, err := addrsOf(2, func() ([]byte, error) { return nil, errors.New("netlink: refused") }); err == nil || err.Error() != "netlink: refused" {
		t.Errorf("a failed dump: %v", err)
	}
	for _, tc := range []struct {
		name, want string
		dump       []byte
	}{
		{"a short address message", "a short address message", join(msg(syscall.RTM_NEWADDR, syscall.NLM_F_MULTI, []byte{syscall.AF_INET, 24, 0, 0}), done(0))},
		{"a three-byte address", "an unreadable address 0a0100/24", join(addr(0, syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, []byte{10, 1, 0})), done(0))},
		{"a prefix longer than the address", "an unreadable address 0a010001/33", join(addr(0, syscall.AF_INET, 33, 2, attr(syscall.IFA_LOCAL, v4("10.1.0.1"))), done(0))},
		{"a message cut short", "the kernel's address dump has no end\n" + syscall.EINVAL.Error(), clean[:20]},
		{"an attribute that does not parse", syscall.EINVAL.Error(), join(addr(0, syscall.AF_INET, 24, 2, []byte{0xff, 0, 1, 0}), done(0))},
		{"an end carrying an error", "the kernel's address dump ended in error (f0ffffff)", join(addr(0, syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, v4("10.1.0.1"))), msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, []byte{0xf0, 0xff, 0xff, 0xff}))},
		{"a short end", "the kernel's address dump ended in error ()", join(addr(0, syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, v4("10.1.0.1"))), msg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, nil))},
		{"no end", "the kernel's address dump has no end", addr(0, syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, v4("10.1.0.1")))},
	} {
		b := tc.dump
		if got, err := addrsOf(2, func() ([]byte, error) { return b, nil }); err == nil || err.Error() != tc.want || got != nil {
			t.Errorf("%s read as %v, %v; want the error %q", tc.name, got, err, tc.want)
		}
	}

	// The index before the dump and after it: the same reads the dump;
	// another, or none, fails.
	gone := errors.New("route ip+net: no such network interface")
	for _, tc := range []struct {
		name  string
		after func() (int, error)
		want  string
	}{
		{"the same", func() (int, error) { return 2, nil }, ""},
		{"made again", func() (int, error) { return 7, nil }, "interface own0 was made again while its addresses were read (index 2, then 7)"},
		{"gone", func() (int, error) { return 0, gone }, gone.Error()},
	} {
		var asked []string
		index := func(name string) (int, error) {
			asked = append(asked, name)
			if len(asked) == 1 {
				return 2, nil
			}
			return tc.after()
		}
		dumped := 0
		got, err := addrsOn("own0", index, func() ([]byte, error) { dumped++; return clean, nil })
		if !slices.Equal(asked, []string{"own0", "own0"}) || dumped != 1 {
			t.Errorf("%s: looked up %q, dumped %d times; want own0 before and after one dump", tc.name, asked, dumped)
		}
		if tc.want == "" && (err != nil || !slices.Equal(got, want)) {
			t.Errorf("%s: %v %v, want %v", tc.name, got, err, want)
		}
		if tc.want != "" && (err == nil || err.Error() != tc.want || got != nil) {
			t.Errorf("%s: %v %v, want the error %q", tc.name, got, err, tc.want)
		}
	}
	// No index: no dump. A failed dump: its error, without the second look.
	n := 0
	if got, err := addrsOn("own0", func(string) (int, error) { n++; return 0, gone }, func() ([]byte, error) { t.Fatal("dumped with no index"); return nil, nil }); err != gone || got != nil || n != 1 {
		t.Errorf("no index: %v %v after %d lookups", got, err, n)
	}
	n = 0
	refused := errors.New("netlink: refused")
	if got, err := addrsOn("own0", func(string) (int, error) { n++; return 2, nil }, func() ([]byte, error) { return nil, refused }); err != refused || got != nil || n != 1 {
		t.Errorf("a failed dump: %v %v after %d lookups", got, err, n)
	}
}

// TestMergingPortSpentOnANewDay (ENF-l-16): a quota a reading starts
// while a port merges (a new day, a merge of groups) starts spent too, not
// only the ones a full load starts.
func TestMergingPortSpentOnANewDay(t *testing.T) {
	x, doc, _ := capped(t)
	x.d.Close()
	x.merges(x.cfg.Layout.Core, errors.New("offload: core0: rx-gro on"))
	x.start()
	x.setListing(listing(t, x, doc, 7, 10))
	x.advance(24 * time.Hour)
	x.fire.mu.Lock()
	var last string
	if n := len(x.fire.updates); n > 0 {
		last = x.fire.updates[n-1]
	}
	x.fire.mu.Unlock()
	m := quotaLine.FindStringSubmatch(last)
	if m == nil || m[1] != "q" {
		t.Fatalf("no new group quota at the next day's reading:\n%s", last)
	}
	if m[2] != m[3] {
		t.Fatalf("the core's new-day quota starts at %s of %s bytes while its port merges", m[3], m[2])
	}
}

// TestMergingKeptOffAtEachReading (ENF-cap-gro): before each reading the
// counted ports are asked again, so a port whose device was made again
// does not stay merging; a failure is logged once while it lasts, and its
// end once.
func TestMergingKeptOffAtEachReading(t *testing.T) {
	x, _, _ := capped(t)
	calls := func() int { x.mu.Lock(); defer x.mu.Unlock(); return len(x.offloads) }
	n := calls()
	x.advance(readEvery)
	if calls() != n+2 {
		t.Fatalf("%d calls at a reading, want one per port", calls()-n)
	}
	x.advance(time.Second)
	if calls() != n+2 {
		t.Fatal("asked again within readEvery")
	}
	edge := x.cfg.Layout.Edge
	x.merges(edge, errors.New("offload: edge0: rx-lro on"))
	x.advance(readEvery)
	x.advance(readEvery)
	bad := "byte caps: " + edge + " merges segments, every capped send it carries is dropped until it stops: offload: edge0: rx-lro on"
	if c := strings.Count(x.logText(), bad); c != 1 {
		t.Fatalf("a lasting failure logged %d times:\n%s", c, x.logText())
	}
	x.merges(edge, nil)
	x.advance(readEvery)
	x.advance(readEvery)
	if c := strings.Count(x.logText(), "byte caps: "+edge+" merges no segments again, its caps count again"); c != 1 {
		t.Fatalf("the end of a failure logged %d times", c)
	}
}

// TestAnswersRefreshed (#4453): every readEvery the daemon runs the
// resolver's step against the running table, so each answer since the
// last step takes new connections for nft.AnswerTimeout from then and no
// longer; nothing is applied when no answer is fresh, and a failing step
// is logged once while it lasts, and its end once.
func TestAnswersRefreshed(t *testing.T) {
	x, doc, _ := capped(t)
	sets, err := nft.AllowSets(doc, x.cfg.Layout)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := json.Marshal(map[string]any{"nftables": []any{
		map[string]any{"set": map[string]any{"family": "inet", "table": nft.Table, "name": sets[0].Fresh(false), "elem": []any{map[string]any{"elem": map[string]any{"val": "203.0.113.5", "expires": nft.AnswerTimeout - 10}}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := nft.Refresh(doc, x.cfg.Layout, fresh)
	if err != nil || want == "" {
		t.Fatalf("fixture: no refresh (%v)", err)
	}
	updates := func() []string { x.fire.mu.Lock(); defer x.fire.mu.Unlock(); return slices.Clone(x.fire.updates) }
	refreshes := func() int {
		n := 0
		for _, u := range updates() {
			if u == want {
				n++
			}
		}
		return n
	}

	x.setListing(listing(t, x, doc, 7, 10))
	x.advance(readEvery)
	if refreshes() != 0 {
		t.Fatal("a refresh with no fresh answer")
	}
	x.setListing(fresh)
	x.advance(readEvery)
	if refreshes() != 1 {
		t.Fatalf("%d refreshes of a fresh answer after one reading interval, want 1", refreshes())
	}

	x.fire.mu.Lock()
	x.fire.listErr = errors.New("nft: gone")
	x.fire.mu.Unlock()
	logged := len(x.logText())
	x.advance(readEvery)
	x.advance(readEvery)
	if got := strings.Count(x.logText()[logged:], "resolver answers: not refreshed"); got != 1 || !strings.Contains(x.logText()[logged:], "until one is, for at most 600 s from their first answer: nft: gone") {
		t.Fatalf("a failing step logged %d times over two intervals, want once with its cause:\n%s", got, x.logText()[logged:])
	}
	x.fire.mu.Lock()
	x.fire.listErr = nil
	x.fire.mu.Unlock()
	x.advance(readEvery)
	if !strings.Contains(x.logText()[logged:], "resolver answers: refreshed again") || refreshes() != 2 {
		t.Fatal("the step's recovery was not logged or did not refresh")
	}
}

// TestNoRefreshBeforeALoad (#4453): while no ruleset has loaded (each
// load so far refused) there are no answers to refresh, so the step reads
// nothing.
func TestNoRefreshBeforeALoad(t *testing.T) {
	x := newBox(t, false)
	x.d.fwMu.Lock()
	x.d.loaded = ""
	x.d.fwMu.Unlock()
	x.fire.mu.Lock()
	x.fire.listErr = errors.New("nft: no table")
	x.fire.mu.Unlock()
	n := x.listed()
	if err := x.d.refreshAnswers(context.Background()); err != nil || x.listed() != n {
		t.Fatalf("the step ran before any load: %v, %d lists", err, x.listed()-n)
	}
}

// TestStoppedResolverOnPage (#5164 R1; ENF-l-11, ENF-l-21): home shows a
// stopped resolver while no instance runs, with each stray address and
// its interface and every other failure of the served check apart, a
// policy in force it cannot serve, and, with none of those, the refused
// load that keeps it stopped (#5243 L3 item 1); once a load starts the
// instances, home shows nothing. A refused load leaves the policy's cause
// as it was, since the resolver keeps the old policy's files.
func TestStoppedResolverOnPage(t *testing.T) {
	x, _ := enrolled(t, false)
	view := func() string { return x.b.do(http.MethodGet, "/", nil).Body.String() }
	if h := view(); strings.Contains(h, "Names and addresses") {
		t.Fatal("home shows a running resolver as stopped")
	}
	stray := strayAddr{"own0", netip.MustParsePrefix("10.99.0.1/24"), "10.10.0.0/24"}
	unset := unsetErr{page.Unset{Kind: page.UnsetSetting, Iface: "default", Setting: page.Redirects4}, errors.New("reworded, so the page cannot read it")}
	x.mu.Lock()
	x.servedErr = errors.Join(stray, unset)
	x.mu.Unlock()
	x.advance(readEvery)
	got := (pageResolver{x.d}).Stopped()
	if want := (page.Stray{Iface: "own0", Addr: stray.addr, Nets: "10.10.0.0/24"}); !got.Stopped || len(got.Strays) != 1 || got.Strays[0] != want || !slices.Equal(got.Unset, []page.Unset{unset.cause}) || got.Policy != nil {
		t.Fatalf("stopped resolver: %#v", got)
	}
	h := view()
	for _, want := range []string{"<h2>Names and addresses</h2>", "Interface own0 holds the address 10.99.0.1/24, outside its network 10.10.0.0/24.", "<p>The enforcer could not turn off IPv4 redirects for interfaces made from now on, so a home network&#39;s interface made again could take a route the enforcer did not check. It tries again every 10 seconds.</p>"} {
		if !strings.Contains(h, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	x.mu.Lock()
	x.servedErr = errors.New("served interface own0: addresses: dump interrupted")
	x.mu.Unlock()
	x.advance(readEvery)
	if got := (pageResolver{x.d}).Stopped(); !got.Stopped || len(got.Strays) != 0 || !slices.Equal(got.Unset, []page.Unset{{}}) {
		t.Fatalf("an untyped failure is not the page's untyped cause: %#v", got)
	}
	if h := view(); !strings.Contains(h, "in a way this page has no words for") || strings.Contains(h, "dump interrupted") {
		t.Errorf("an untyped failure is not the generic line, or shows its text:\n%s", h)
	}
	// hold's own failure reaches the page by its typed cause, whatever
	// its text says (#5284).
	x.mu.Lock()
	x.servedErr = hold(t.TempDir(), []dns.Net{{Iface: "own\u202e0/x"}}, nil)
	x.mu.Unlock()
	x.advance(readEvery)
	if h := view(); !strings.Contains(h, "The enforcer&#39;s setup names &#34;own\\u202e0/x&#34; as a home network&#39;s interface") {
		t.Errorf("hold's failure is not in the page's words:\n%s", h)
	}
	// The check passes but the load that would start the instances is
	// refused: they stay stopped, and home says why (#5243 L3 item 1).
	x.mu.Lock()
	x.servedErr = nil
	x.mu.Unlock()
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	x.advance(readEvery)
	x.dns.mu.Lock()
	stopped := len(x.dns.running.Listed) == 0 && x.dns.running.People == "" && x.dns.running.DHCP == ""
	x.dns.mu.Unlock()
	if !stopped {
		t.Fatal("fixture: a refused load started the instances")
	}
	if got := (pageResolver{x.d}).Stopped(); !got.Stopped || len(got.Strays)+len(got.Unset) != 0 || got.Policy != nil || got.Load != page.LoadFirewall {
		t.Fatalf("a refused load after the check passes: %#v", got)
	}
	if h := view(); !strings.Contains(h, "<h2>Names and addresses</h2>") || !strings.Contains(h, "The firewall refused the enforcer&#39;s last load of your rules;") {
		t.Errorf("home does not show the resolver stopped by a refused load:\n%s", h)
	}
	x.fire.mu.Lock()
	x.fire.fail = false
	x.fire.mu.Unlock()
	x.advance(readEvery)
	if got := (pageResolver{x.d}).Stopped(); got.Stopped || strings.Contains(view(), "Names and addresses") {
		t.Fatalf("the load is taken and home still shows a stopped resolver: %#v", got)
	}

	doc := home()
	doc.Devices = append(doc.Devices, policy.Device{ID: "plug", Network: policy.NetDevices, WiFi: "vlan109", Everyday: true, Allow: []string{"plug.example"}})
	_, genErr := dns.Generate(doc, x.cfg.Layout, x.cfg.DNS)
	if genErr == nil {
		t.Fatal("fixture: the resolver serves vlan109")
	}
	// The page has the refusal's typed cause, never its text (#5307).
	vlan := []page.PolicyCause{{Kind: page.PolicyVLAN, Name: "plug", WiFi: "vlan109"}}
	load := func(doc policy.Document) error {
		x.d.fwMu.Lock()
		defer x.d.fwMu.Unlock()
		return x.d.loadNetwork(context.Background(), doc)
	}
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	if err := load(doc); err == nil {
		t.Fatal("fixture: the load was not refused")
	}
	if got := (pageResolver{x.d}).Stopped(); got.Stopped {
		t.Fatalf("a refused load's policy shows as the one in force: %#v", got)
	}
	x.fire.mu.Lock()
	x.fire.fail = false
	x.fire.mu.Unlock()
	if err := load(doc); err != nil {
		t.Fatal(err)
	}
	if got := (pageResolver{x.d}).Stopped(); !got.Stopped || !slices.Equal(got.Policy, vlan) || got.Load != page.LoadTaken || len(got.Strays)+len(got.Unset) != 0 {
		t.Fatalf("a policy the resolver cannot serve: %#v", got)
	}
	if h := view(); !strings.Contains(h, "The policy in force puts device plug on Wi-Fi network vlan109, and the enforcer&#39;s setup serves no names or addresses there.") || strings.Contains(h, "ap0.109") {
		t.Error("home does not show the policy the resolver cannot serve")
	}
	x.fire.mu.Lock()
	x.fire.fail = true
	x.fire.mu.Unlock()
	if err := load(home()); err == nil {
		t.Fatal("fixture: the load was not refused")
	}
	if got := (pageResolver{x.d}).Stopped(); !slices.Equal(got.Policy, vlan) {
		t.Fatalf("a refused load cleared the cause in force: %#v", got)
	}
	x.fire.mu.Lock()
	x.fire.fail = false
	x.fire.mu.Unlock()
	if err := load(home()); err != nil {
		t.Fatal(err)
	}
	if got := (pageResolver{x.d}).Stopped(); got.Stopped {
		t.Fatalf("a servable policy in force still shows a stopped resolver: %#v", got)
	}
}

// TestRefusedCause (#5307, #5352, #5405): dns.Generate's refusal of a
// compiled document reaches the page and the log as every item Generate
// refused, read from the error: each device on a Wi-Fi network the setup
// serves no network for, and each listed name that is not a DNS host
// name. With a setup fault too, the fault is its own cause, whose words
// on home carry none of its text, and the devices are still named; any
// other refusal is untyped, whatever its text (#5431). However many items
// Generate refuses, home and the log line name a bounded number and
// count the rest exactly (#5431).
func TestRefusedCause(t *testing.T) {
	x, _ := enrolled(t, false)
	l, s := x.cfg.Layout, x.cfg.DNS
	plug := func(id, wifi string) policy.Device {
		return policy.Device{ID: id, Network: policy.NetDevices, WiFi: wifi, Everyday: true, Allow: []string{id + ".example"}}
	}
	vlans := home()
	vlans.Devices = append(vlans.Devices, plug("plug", "vlan109"), plug("lamp", "vlan110"))
	both := []page.PolicyCause{{Kind: page.PolicyVLAN, Name: "plug", WiFi: "vlan109"}, {Kind: page.PolicyVLAN, Name: "lamp", WiFi: "vlan110"}}
	// Generate lists names sorted; the document lists Zed.example first.
	names := home()
	names.Destinations = []string{"updates.example", "Zed.example", "Abc.example"}
	view := func() string { return x.b.do(http.MethodGet, "/", nil).Body.String() }
	for _, tc := range []struct {
		doc  policy.Document
		want []page.PolicyCause
		said []string
	}{
		{vlans, both, []string{"plug", "lamp"}},
		{names, []page.PolicyCause{{Kind: page.PolicyName, Name: "Abc.example"}, {Kind: page.PolicyName, Name: "Zed.example"}}, []string{"Abc.example", "Zed.example"}},
	} {
		if _, err := nft.Paths(tc.doc, l); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		_, err := dns.Generate(tc.doc, l, s)
		if !errors.Is(err, dns.ErrConfig) {
			t.Fatalf("fixture: %v", err)
		}
		if got := refusedCauses(err); !slices.Equal(got, tc.want) {
			t.Errorf("refusedCauses(%v) = %+v, want %+v", err, got, tc.want)
		}
		x.mu.Lock()
		x.log = nil
		x.mu.Unlock()
		x.d.fwMu.Lock()
		err = x.d.loadNetwork(context.Background(), tc.doc)
		x.d.fwMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if got := (pageResolver{x.d}).Stopped(); !got.Stopped || !slices.Equal(got.Policy, tc.want) {
			t.Errorf("the page's causes for %v: %#v", tc.said, got)
		}
		h := view()
		x.mu.Lock()
		var logged []string
		for _, line := range x.log {
			if strings.HasPrefix(line, "dns: the policy in force cannot be served") {
				logged = append(logged, line)
			}
		}
		x.mu.Unlock()
		if len(logged) != 1 || strings.Contains(logged[0], "\n") {
			t.Errorf("the refusal is not one log line: %q", logged)
		}
		for _, said := range tc.said {
			if !strings.Contains(h, said) || !strings.Contains(strings.Join(logged, ""), strconv.Quote(said)) {
				t.Errorf("home or the log leaves out %s, which Generate refused", said)
			}
		}
	}
	// A setup fault beside the unserved devices: the fault is its own
	// cause and both devices are still named (#5405, #5431).
	bad := s
	bad.Upstream = nil
	_, err := dns.Generate(vlans, l, bad)
	setup := append([]page.PolicyCause{{Kind: page.PolicySetup}}, both...)
	if got := refusedCauses(err); !slices.Equal(got, setup) {
		t.Errorf("a setup fault beside unserved devices: %+v", got)
	}
	untyped := []page.PolicyCause{{Kind: page.PolicyUntyped}}
	for _, err := range []error{fmt.Errorf("%w: device \"plug\" vlan109 \"Upper.example\"", dns.ErrConfig), errors.New("other"), nil, dns.Refused{errors.New("no upstream resolver")}} {
		if got := refusedCauses(err); !slices.Equal(got, untyped) {
			t.Errorf("refusedCauses(%v) = %+v, want untyped", err, got)
		}
	}
	// On home, the setup fault reads in its own words, apart from an
	// untyped refusal's, and never with its text (#5431).
	x.d.net.resMu.Lock()
	x.d.net.stopPolicy = refusedCauses(err)
	x.d.net.resMu.Unlock()
	h := view()
	if !strings.Contains(h, "The network setup could not be applied") || strings.Contains(h, "upstream") || strings.Contains(h, dns.ErrConfig.Error()) || strings.Contains(h, "names something the enforcer cannot serve") || !strings.Contains(h, "plug") {
		t.Errorf("home does not word the setup fault apart, without its text:\n%s", h)
	}
	x.d.net.resMu.Lock()
	x.d.net.stopPolicy = refusedCauses(errors.New("no upstream resolver"))
	x.d.net.resMu.Unlock()
	if h := view(); strings.Contains(h, "could not be applied") || !strings.Contains(h, "names something the enforcer cannot serve") || strings.Contains(h, "upstream") {
		t.Errorf("home words an untyped refusal as a setup fault:\n%s", h)
	}
	// More refused names than either cap: home and the log line each name
	// the first ones and count the rest exactly, and stay bounded (#5431).
	many := home()
	const n = 300
	for i := range n {
		many.Destinations = append(many.Destinations, "N"+strconv.Itoa(1000+i)+".example")
	}
	x.mu.Lock()
	x.log = nil
	x.mu.Unlock()
	x.d.fwMu.Lock()
	err = x.d.loadNetwork(context.Background(), many)
	x.d.fwMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := (pageResolver{x.d}).Stopped(); len(got.Policy) != n {
		t.Fatalf("the daemon holds %d causes, want %d", len(got.Policy), n)
	}
	h = view()
	x.mu.Lock()
	var logged []string
	for _, line := range x.log {
		if strings.HasPrefix(line, "dns: the policy in force cannot be served") {
			logged = append(logged, line)
		}
	}
	x.mu.Unlock()
	if len(logged) != 1 || !strings.HasSuffix(logged[0], "; and "+strconv.Itoa(n-dns.RefusedShown)+" more") || strings.Count(logged[0], "is not a DNS host name") != dns.RefusedShown || len(logged[0]) > 4<<10 {
		t.Errorf("the log line is not bounded with the exact count: %q", logged)
	}
	if strings.Count(h, "which is not a name the enforcer can look up") != page.PolicyShown || !strings.Contains(h, "There are "+strconv.Itoa(n-page.PolicyShown)+" more reasons the policy in force cannot be served") || strings.Contains(h, "N"+strconv.Itoa(1000+page.PolicyShown)+".example") {
		t.Errorf("home is not bounded with the exact count:\n%s", h)
	}
	// Typed, wrapped, the refusal still reads as ErrConfig and keeps its
	// causes.
	for _, err := range []error{fmt.Errorf("load: %w", dns.Refused{dns.UnservedDevice{ID: "plug", WiFi: "vlan109", Iface: "ap0.109"}}), fmt.Errorf("load: %w", dns.Refused{dns.BadName{Name: "Upper.example"}})} {
		if got := refusedCauses(err); !errors.Is(err, dns.ErrConfig) || len(got) != 1 || got[0].Kind == page.PolicyUntyped {
			t.Errorf("%v: not typed", err)
		}
	}
}
