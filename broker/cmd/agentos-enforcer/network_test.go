package main

// REQ: NET-2, NET-3, NET-5

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/dns"
	"github.com/ghbmrk/agentos/broker/enforcer/mdns"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
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
	p.EdgeCount, p.Past = p.EdgeCap, true
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
	x.enforced()
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

// TestEdgeOverrun (ENF-l-15): the edge past its cap raises a trip for the
// edge and is logged, and leaves the core's channel open; an alert that
// cannot be journalled is logged too.
func TestEdgeOverrun(t *testing.T) {
	x, doc, _ := capped(t)
	x.setListing(listingOf(t, x, doc, 7, 10, 6000, true))
	x.advance(readEvery)
	if x.d.cut.Stage() != channel.Open {
		t.Fatal("an edge overrun cut the core")
	}
	edge := slices.ContainsFunc(x.d.alerts.Status().Open, func(r alert.Record) bool { return r.Kind == alert.Trip && r.Device == edgeDevice })
	if !edge || !strings.Contains(x.logText(), "byte caps: edge: byte cap passed: 6000 of 5000") {
		t.Fatal("the edge's overrun was not raised and logged")
	}
	j := filepath.Join(x.dir, fileAlerts)
	if err := os.Remove(j); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(j, 0o700); err != nil {
		t.Fatal(err)
	}
	x.setListing(listingOf(t, x, doc, 7, 10, 7000, true))
	x.advance(readEvery)
	if !strings.Contains(x.logText(), "byte caps: edge alert:") {
		t.Fatal("an edge alert that failed was not logged")
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
