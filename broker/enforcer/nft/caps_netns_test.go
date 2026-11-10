package nft_test

// REQ: NET-2, KRN-12

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/offload"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// These tests run the byte caps end to end (NET-2 Byte caps, D-255,
// ENF-cap-trip-c): the real ruleset in the netns fixture home, the core's
// and the edge's packets through it, and broker/enforcer/traffic's counter
// reading the firewall's counters, tripping, and writing the in-kernel
// drop back after every reading, as the enforcer's daemon does.

// rig is the counter beside the fixture home's firewall.
type rig struct {
	t    *testing.T
	h    *nft.Home
	d    policy.Document
	now  time.Time
	c    *traffic.Counter
	boot string
	past bool   // the kernel's quota edge (load.Loader.QuotaPast)
	last []byte // the listing of the last reading
}

// drop is the counter's drop state on this kernel, after the last reading.
func (r *rig) drop() nft.Drop {
	p := r.c.Drop()
	p.Past, p.Read = r.past, r.last
	return p
}

func loaderOf(t *testing.T) load.Loader {
	bin, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	return load.Loader{Bin: bin}
}

func newRig(t *testing.T, d policy.Document) *rig {
	boot, err := traffic.BootID()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, h: nft.Build(t), d: d, now: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), boot: boot}
	past, err := loaderOf(t).QuotaPast(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("this kernel's quota matches past N: %v", past)
	r.past = past
	r.c = traffic.NewCounter(r.clock, traffic.CapsOf(d))
	r.load()
	for _, a := range []string{nft.NetCore, nft.NetOther, nft.NetAllow, nft.NetDoH} {
		r.h.EchoUDP(a)
	}
	if r.h.V6() {
		r.h.EchoUDP(nft.Net6Other)
	}
	return r
}

func (r *rig) clock() time.Time { return r.now }

// load replaces the ruleset with d's, carrying the running answers
// (nft.Reload), and the counter's drop in the same transaction.
func (r *rig) load() {
	r.t.Helper()
	text, err := nft.Reload(r.d, nft.FixtureLayout(), r.h.List())
	if err != nil {
		r.t.Fatal(err)
	}
	drops, err := nft.Drops(r.d, nft.FixtureLayout(), nil, r.drop())
	if err != nil {
		r.t.Fatal(err)
	}
	r.h.Load(text + drops)
}

// read takes one reading into the counter and writes its drop back.
func (r *rig) read() []traffic.Overrun {
	r.t.Helper()
	over := r.reading()
	r.update()
	return over
}

// reading takes one reading into the counter, and writes nothing back.
func (r *rig) reading() []traffic.Overrun {
	r.t.Helper()
	r.last = r.h.List()
	got, err := traffic.ReadingOf(r.d, nft.FixtureLayout(), r.boot, r.last)
	if err != nil {
		r.t.Fatal(err)
	}
	return r.c.Add(got)
}

// update writes the counter's drop to the running ruleset.
func (r *rig) update() {
	r.t.Helper()
	text, err := nft.Drops(r.d, nft.FixtureLayout(), r.h.List(), r.drop())
	if err != nil {
		r.t.Fatal(err)
	}
	r.h.Update(text)
}

// answer puts addr in the core's allow set and in name's set, as the
// resolver does.
func (r *rig) answer(name, addr string) {
	set := nft.CoreSet(false)
	if net.ParseIP(addr).To4() == nil {
		set = nft.CoreSet(true)
	}
	r.h.Answer(r.d, set, name, addr)
}

func (r *rig) send(from, addr string, payload int, want bool, why string) {
	r.t.Helper()
	if got := r.h.SendUDP(from, addr, payload); got != want {
		r.t.Errorf("%s: %d payload bytes from %s to %s crossed %v, want %v", why, payload, from, addr, got, want)
	}
}

func (r *rig) expectOver(why string, got []traffic.Overrun, want ...traffic.Overrun) {
	r.t.Helper()
	if !slices.EqualFunc(got, want, func(a, b traffic.Overrun) bool {
		return a.Box == b.Box && slices.Equal(a.Dests, b.Dests) && a.Cap == b.Cap && a.Count == b.Count
	}) {
		r.t.Errorf("%s: overruns %+v, want %+v", why, got, want)
	}
}

func capDoc(caps map[string]uint64, edge uint64) policy.Document {
	d := nft.FixturePolicy()
	d.Destinations = slices.Sorted(func(yield func(string) bool) {
		for n := range caps {
			if !yield(n) {
				return
			}
		}
	})
	d.Caps, d.EdgeCap = caps, edge
	return d
}

// NET-2 Byte caps, D-255 (#4375 Security): the kernel's drop agrees with
// the trip to the byte. A core that sends exactly its cap gets every byte
// through and no trip; one byte more is dropped in the kernel's own path,
// before it leaves, and the next reading trips on it, since the counter
// rule counts the dropped byte too. The same for the edge's one cap, and
// over IPv6. A drop update between two readings keeps a group's quota and
// its count in the kernel, so the bytes since the last reading still
// count against the cap. Catches a drop at the cap rather than past it
// (an honest core cut at its edge), one a byte late, a drop that does not
// count what it drops (no trip), and an update that restarts a quota.
func TestCapDropsPastTheCapToTheByte(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"a.example": 100, "b.example": 100, "g.example": 100}, 300))
	r.answer("a.example", nft.NetCore)
	r.answer("b.example", nft.NetOther)
	r.expectOver("nothing sent", r.read())

	// IPv4 and UDP headers are 28 bytes: 22 payload bytes are 50 IP bytes.
	r.send("core", nft.NetCore, 22, true, "a: 50 of 100")
	r.send("core", nft.NetCore, 22, true, "a: 100 of 100")
	r.send("core", nft.NetOther, 22, true, "b: 50 of 100")
	r.update() // no reading: b's quota keeps its 50 bytes
	r.send("core", nft.NetOther, 23, false, "b: 101 of 100")
	r.expectOver("b one byte past", r.read(), traffic.Overrun{Box: traffic.BoxCore, Dests: []string{"b.example"}, Cap: 100, Count: 101})
	if n := r.h.Counter(nft.CapDrop); n != 1 {
		t.Errorf("cap_drop counted %d packets, want 1", n)
	}
	r.send("core", nft.NetCore, 1, false, "a: past its cap")
	r.expectOver("a past too", r.read(),
		traffic.Overrun{Box: traffic.BoxCore, Dests: []string{"a.example"}, Cap: 100, Count: 129},
		traffic.Overrun{Box: traffic.BoxCore, Dests: []string{"b.example"}, Cap: 100, Count: 101})

	// The edge: six 50-byte datagrams are its 300; the seventh is past.
	for range 6 {
		r.send("edge", nft.NetOther, 22, true, "edge within its cap")
	}
	over := r.read()
	if slices.ContainsFunc(over, func(o traffic.Overrun) bool { return o.Box == traffic.BoxEdge }) {
		t.Errorf("edge at its cap tripped: %+v", over)
	}
	r.send("edge", nft.NetOther, 22, false, "edge past its cap")
	over = r.read()
	if !slices.ContainsFunc(over, func(o traffic.Overrun) bool { return o.Box == traffic.BoxEdge && o.Cap == 300 && o.Count == 350 }) {
		t.Errorf("edge past its cap: overruns %+v, want the edge at 350 of 300", over)
	}

	if r.h.V6() {
		// IPv6 and UDP headers are 48 bytes: 2 payload bytes are 50.
		r.answer("g.example", nft.Net6Other)
		r.read()
		r.send("core", nft.Net6Other, 2, true, "g: 50 of 100 over IPv6")
		r.send("core", nft.Net6Other, 2, true, "g: 100 of 100 over IPv6")
		over = r.read()
		if slices.ContainsFunc(over, func(o traffic.Overrun) bool { return slices.Contains(o.Dests, "g.example") }) {
			t.Errorf("g at its cap tripped: %+v", over)
		}
		r.send("core", nft.Net6Other, 2, false, "g: past its cap over IPv6")
		over = r.read()
		if !slices.ContainsFunc(over, func(o traffic.Overrun) bool { return slices.Equal(o.Dests, []string{"g.example"}) && o.Count == 150 }) {
			t.Errorf("g past its cap over IPv6: overruns %+v", over)
		}
	}
}

// NET-2 Byte caps (ENF-cap-3): destinations that share an address are one
// group with one cap, the sum of theirs, in the kernel too, once the
// shared address carries bytes. Before that, its sets hold it but the
// counter keeps the two apart, so its first bytes are charged to both
// destinations' quotas; the next reading merges them and the update gives
// the group one quota from the counter's count. An honest core then sends
// the whole group cap without a drop or a trip, and the next byte is
// dropped and trips the group. Catches a drop that holds each destination
// to its own cap after the merge (an honest core cut at half its group's
// cap) or charges one packet to the merged quota twice.
func TestCapGroupSharesOneDrop(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"c.example": 60, "d.example": 60}, 1<<20))
	r.answer("c.example", nft.NetAllow)
	r.answer("d.example", nft.NetAllow)
	r.expectOver("nothing sent", r.read())
	// 32 payload bytes are 60 IP bytes.
	r.send("core", nft.NetAllow, 32, true, "60 of the group's 120, charged to both")
	r.expectOver("the shared address carries bytes", r.read())
	r.send("core", nft.NetAllow, 32, true, "120 of the group's 120")
	r.expectOver("at the group's cap", r.read())
	r.send("core", nft.NetAllow, 32, false, "past the group's cap")
	r.expectOver("past the group's cap", r.read(), traffic.Overrun{Box: traffic.BoxCore, Dests: []string{"c.example", "d.example"}, Cap: 120, Count: 180})
}

// NET-2 Byte caps (#4614, L3 R2 on #4611): bytes the core sends between
// a reading and the update after it count against the quota that update
// starts. a's and b's groups merge at a reading (b's set now holds a's
// address, which carried bytes), and before the update each old quota
// still lets its own cap through: 50 more to a's address and 100 to b's
// bring the merged group to its cap of 200 while the counter read 50. The
// merged quota starts from the 50 plus what the old ones charged since,
// so the next datagram is dropped and trips. Catches a merged quota that
// starts from the reading's count alone, letting the bytes since then
// past the merged cap once.
func TestCapMergeCarriesBytesSinceTheReading(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"a.example": 100, "b.example": 100}, 1<<20))
	r.answer("a.example", nft.NetCore)
	r.answer("b.example", nft.NetAllow)
	r.expectOver("nothing sent", r.read())
	// 22 payload bytes are 50 IP bytes, 72 are 100.
	r.send("core", nft.NetCore, 22, true, "a: 50 of 100")
	r.expectOver("a within its cap", r.read())
	r.answer("b.example", nft.NetCore)
	r.expectOver("the groups merge at 50 of 200", r.reading())
	r.send("core", nft.NetCore, 22, true, "a's old quota: 100 of 100, before the update")
	r.send("core", nft.NetAllow, 72, true, "b's old quota: 100 of 100, before the update")
	r.update()
	r.send("core", nft.NetAllow, 1, false, "the merged group past 200 after the update")
	r.expectOver("the merged group past its cap", r.read(), traffic.Overrun{Box: traffic.BoxCore, Dests: []string{"a.example", "b.example"}, Cap: 200, Count: 229})
}

// NET-2 Byte caps, ENF-cap-3 (L3 on #4611): an address two destinations'
// sets hold, carrying nothing today, never raises either one's own cap in
// the kernel. a's own address stops at a's cap, as the counter trips
// there, however much b's cap has left. Catches a drop that merges groups
// at idle held addresses, giving a's own address the cap a+b until the
// next reading.
func TestCapHeldSharedAddressRaisesNoCap(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"a.example": 100, "b.example": 100}, 1<<20))
	r.answer("a.example", nft.NetCore)
	r.answer("a.example", nft.NetAllow)
	r.answer("b.example", nft.NetAllow)
	r.expectOver("nothing sent", r.read())
	r.send("core", nft.NetCore, 22, true, "a's own address, 50 of 100")
	r.send("core", nft.NetCore, 22, true, "a's own address, 100 of 100")
	r.send("core", nft.NetCore, 22, false, "a's own address past a's cap")
	r.expectOver("a past its own cap", r.read(), traffic.Overrun{Box: traffic.BoxCore, Dests: []string{"a.example"}, Cap: 100, Count: 150})
}

// NET-2 Byte caps (Security delta on #4611): a byte to an address several
// groups' sets hold, idle today, is charged to every one of their quotas
// in the kernel itself. After 50 bytes there, a's own address takes only
// a's other 50 before the next reading, as the counter would merge the two
// groups and the kernel cannot. Catches a shared chain that charges only
// one group's quota.
func TestCapHeldSharedAddressChargesEachGroup(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"a.example": 100, "b.example": 1000}, 1<<20))
	r.answer("a.example", nft.NetCore)
	r.answer("a.example", nft.NetAllow)
	r.answer("b.example", nft.NetAllow)
	r.expectOver("nothing sent", r.read())
	r.send("core", nft.NetAllow, 22, true, "50 to the shared address")
	r.send("core", nft.NetCore, 22, true, "a's own address, 100 of a's quota")
	r.send("core", nft.NetCore, 22, false, "a's own address past a's quota before the next reading")
}

// NET-2 Byte caps (L3 R1 and Security on #4611): a load that carries no
// drop state fails closed: the core reaches nothing on the internet and
// the edge nothing either, though the core's allow set and names hold the
// address. Catches a default drop chain that passes.
func TestCapLoadWithoutDropFailsClosed(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"a.example": 1 << 20}, 1<<20))
	r.answer("a.example", nft.NetCore)
	r.read()
	r.send("core", nft.NetCore, 22, true, "with the drop state")
	r.send("edge", nft.NetOther, 22, true, "the edge with the drop state")
	text, err := nft.Reload(r.d, nft.FixtureLayout(), r.h.List())
	if err != nil {
		t.Fatal(err)
	}
	r.h.Load(text)
	r.send("core", nft.NetCore, 22, false, "a load without the drop state")
	r.send("edge", nft.NetOther, 22, false, "the edge after a load without the drop state")
}

// NET-2 Byte caps, ENF-cap-6: the day's count survives an enforcer
// restart and the ruleset load at boot. The counter is saved, restored,
// and its drop loaded with the new ruleset, so the kernel stops the core
// at the cap the day already used, not at a fresh one; the new load is a
// new Gen, so the new counters count in full. Catches a boot load that
// gives the core a second day's cap in the kernel.
func TestCapDropSurvivesRestart(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"a.example": 100}, 1<<20))
	r.answer("a.example", nft.NetCore)
	r.read()
	r.send("core", nft.NetCore, 22, true, "50 of 100 before the restart")
	r.read()
	c, err := traffic.Restore(r.clock, traffic.CapsOf(r.d), r.c.Save())
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	r.load()
	r.send("core", nft.NetCore, 22, true, "100 of 100 after the restart")
	r.expectOver("at the cap after the restart", r.read())
	r.send("core", nft.NetCore, 1, false, "past the cap after the restart")
	r.expectOver("past the cap after the restart", r.read(), traffic.Overrun{Box: traffic.BoxCore, Dests: []string{"a.example"}, Cap: 100, Count: 129})
}

// NET-2 Byte caps ("acknowledgements and retransmissions included"): a
// fake core's TCP past its cap is dropped and trips. Uploading past the
// cap, its segments past it never arrive however often it retransmits
// them, and each retransmission counts: the core's stack retransmits, and
// the firewall's count for each destination is at least every IP byte
// the core's own output hook sent there (#4614, L3 R4 on #4611).
// Downloading, its acknowledgements alone pass the cap, so the download
// stalls. Catches counting payload only, counting only what was let
// through, or counting a retransmitted segment once.
func TestCapDropsTCPWithAcksAndRetransmissions(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	const upCap, downCap = 4000, 1000
	r := newRig(t, capDoc(map[string]uint64{"up.example": upCap, "down.example": downCap}, 1<<20))
	r.answer("up.example", nft.NetDoH)
	r.answer("down.example", nft.NetCore)
	r.read()
	// The core counts what its own stack sends to each server.
	r.h.In("core", "nft", "add table ip wire; add counter ip wire up; add counter ip wire down; "+
		"add chain ip wire out { type filter hook output priority filter; }; "+
		"add rule ip wire out ip daddr "+nft.NetDoH+" counter name up; add rule ip wire out ip daddr "+nft.NetCore+" counter name down")
	retrans := func() int {
		var head []string
		for line := range strings.Lines(r.h.In("core", "cat", "/proc/net/snmp")) {
			f := strings.Fields(line)
			if len(f) == 0 || f[0] != "Tcp:" {
				continue
			}
			if head == nil {
				head = f
				continue
			}
			if i := slices.Index(head, "RetransSegs"); i > 0 && i < len(f) {
				n, _ := strconv.Atoi(f[i])
				return n
			}
		}
		t.Fatal("no RetransSegs in the core's /proc/net/snmp")
		return 0
	}
	before := retrans()
	got := make(chan int, 1)
	r.h.Serve(nft.NetDoH, 9300, func(c net.Conn) {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		got <- int(n)
	})
	r.h.Serve(nft.NetCore, 9301, func(c net.Conn) {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write(make([]byte, 64<<20))
	})
	sent := r.h.Dial("core", nft.NetDoH, 9300, 2*time.Second, func(c net.Conn) int {
		n, _ := c.Write(make([]byte, 64<<10))
		time.Sleep(1500 * time.Millisecond) // retransmissions
		return n
	})
	down := r.h.Dial("core", nft.NetCore, 9301, 2*time.Second, func(c net.Conn) int {
		n, _ := io.Copy(io.Discard, c)
		return int(n)
	})
	up := <-got
	resent := retrans() - before
	wire := map[string]uint64{}
	for _, c := range []string{"up", "down"} {
		var doc struct {
			Nftables []struct {
				Counter *struct{ Bytes uint64 } `json:"counter"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal([]byte(r.h.In("core", "nft", "-j", "list", "counter", "ip", "wire", c)), &doc); err != nil {
			t.Fatal(err)
		}
		for _, o := range doc.Nftables {
			if o.Counter != nil {
				wire[c+".example"] = o.Counter.Bytes
			}
		}
	}
	time.Sleep(50 * time.Millisecond) // the last segments cross the enforcer
	if resent == 0 {
		t.Errorf("the core retransmitted nothing")
	}
	if up >= upCap {
		t.Errorf("the server got %d bytes of an upload capped at %d IP bytes (core wrote %d)", up, upCap, sent)
	}
	if down >= 64<<20 {
		t.Errorf("a download whose acknowledgements pass the cap finished (%d bytes)", down)
	}
	over := r.read()
	t.Logf("uploaded %d of %d bytes written, downloaded %d bytes, %d segments retransmitted, the core's stack sent %v IP bytes; overruns %+v", up, sent, down, resent, wire, over)
	for _, dest := range []string{"up.example", "down.example"} {
		i := slices.IndexFunc(over, func(o traffic.Overrun) bool { return slices.Equal(o.Dests, []string{dest}) })
		switch {
		case i < 0 || over[i].Count <= over[i].Cap:
			t.Errorf("%s past its cap did not trip: %+v", dest, over)
		case over[i].Count < wire[dest]:
			t.Errorf("%s counted %d IP bytes, less than the %d the core's stack sent", dest, over[i].Count, wire[dest])
		}
	}
	if r.h.Counter(nft.CapDrop) < 2 {
		t.Errorf("cap_drop counted %d packets", r.h.Counter(nft.CapDrop))
	}
}

// NET-2 Byte caps, ENF-cap-3 (#4377 Security item 1): an address idle for
// more than a day, still in its name's resolver set, sends without a trip
// or a drop. The counter forgets its destinations at the day's end and the
// next reading gives them back from the set. Catches a stray trip (bytes
// to an address no destination holds) for a core whose name kept its
// address in the set.
func TestCapIdleAddressStillInItsSet(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"a.example": 100}, 1<<20))
	r.answer("a.example", nft.NetCore)
	r.send("core", nft.NetCore, 22, true, "a sends on the first day")
	r.expectOver("first day", r.read())
	r.now = r.now.Add(49 * time.Hour)
	r.expectOver("two days idle", r.read())
	r.send("core", nft.NetCore, 22, true, "a sends after two idle days")
	r.send("core", nft.NetCore, 22, true, "a sends its whole cap after two idle days")
	r.expectOver("after two idle days", r.read())
}

// NET-2 Byte caps, D-255, ENF-cap-gro (#4610; Security on #4611, comment
// 6572938206): with the receive offloads that merge segments off on the
// core's and the edge's ports (offload.Off, as the daemon keeps them), a
// bulk send counts every segment's IP header: each box's count is at least
// the IP bytes that left its port, segment by segment. The same send with
// GRO on is counted short, which shows the harness merges, so the test
// fails if Off leaves a port merging. The sender segments in software
// (its TCP segmentation offloads off), so what leaves its port is what a
// cable carries; its IP bytes are its port's transmitted bytes less each
// frame's Ethernet header and less what it sent anywhere but the server
// (IPv6 control, counted in its own output chain), with its gateway's
// neighbour entry fixed so no ARP is in them. The test turns the
// offloads off with CAP_NET_ADMIN in its own namespace; the daemon can
// only once ENF-m-b's unit gives it that capability in the namespace of
// the enforcer's ports (offload ASSUMPTIONS ENF-gro-4), and until then a
// port it cannot turn off has its caps held spent (daemon ENF-l-16).
func TestCapCountsEverySegmentHeader(t *testing.T) {
	if !nft.InNetns(t) {
		return
	}
	r := newRig(t, capDoc(map[string]uint64{"bulk.example": 1 << 40}, 1<<40))
	r.answer("bulk.example", nft.NetCore)
	l := nft.FixtureLayout()
	for i, tc := range []struct {
		box, port, seg, to string
		count              func(wire.Counts) uint64
	}{
		{"core", l.Core, "10.50.0.1", nft.NetCore, func(c wire.Counts) uint64 {
			for _, g := range c.Groups {
				if len(g.Dests) == 1 && g.Dests[0].Name == "bulk.example" {
					return g.Count
				}
			}
			t.Fatalf("no bulk.example group in %+v", c)
			return 0
		}},
		{"edge", l.Edge, "10.60.0.1", nft.NetOther, func(c wire.Counts) uint64 { return c.EdgeCount }},
	} {
		r.h.Within(tc.box, func() {
			if err := offload.Set("eth0", map[string]bool{"tx-tcp-segmentation": false, "tx-tcp6-segmentation": false,
				"tx-tcp-ecn-segmentation": false, "tx-tcp-mangleid-segmentation": false, "tx-generic-segmentation": false}); err != nil {
				t.Fatal(err)
			}
		})
		// The rest of what the box sends in a window (IPv6 neighbour and
		// multicast control where the kernel has IPv6, anything to another
		// address) is counted on its own and taken off.
		r.h.In(tc.box, "nft", "add table inet tx; add counter inet tx other; "+
			"add chain inet tx out { type filter hook output priority filter; }; "+
			"add rule inet tx out meta nfproto ipv6 counter name other; add rule inet tx out ip daddr != "+tc.to+" counter name other")
		other := func() uint64 {
			var doc struct {
				Nftables []struct {
					Counter *struct{ Bytes uint64 } `json:"counter"`
				} `json:"nftables"`
			}
			if err := json.Unmarshal([]byte(r.h.In(tc.box, "nft", "-j", "list", "counter", "inet", "tx", "other")), &doc); err != nil {
				t.Fatal(err)
			}
			for _, o := range doc.Nftables {
				if o.Counter != nil {
					return o.Counter.Bytes
				}
			}
			t.Fatal("no counter inet tx other")
			return 0
		}
		mac := r.h.MAC(tc.port)
		r.h.In(tc.box, "ip", "neigh", "replace", tc.seg, "lladdr", mac, "nud", "permanent", "dev", "eth0")
		port := 9400 + i
		r.h.Serve(tc.to, port, func(c net.Conn) {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			io.Copy(io.Discard, c)
		})
		// sentAndOther reads the box's IP bytes sent and its other counter
		// as one: a packet elsewhere (an MLD report, at a time the kernel
		// picks) sent between two lone reads counts in one and not the
		// other, which once read as 76 bytes the port never counted. So
		// other is read on both sides of TxIP until it holds still.
		sentAndOther := func() (tx, o uint64) {
			for range 20 {
				a := other()
				tx = r.h.TxIP(tc.box)
				if o = other(); o == a {
					return tx, o
				}
			}
			t.Fatalf("%s: its other counter never held still across a reading", tc.box)
			return 0, 0
		}
		send := func() (counted, sent uint64) {
			r.read()
			before := tc.count(r.c.Counts())
			tx, o := sentAndOther()
			r.h.Dial(tc.box, tc.to, port, 5*time.Second, func(c net.Conn) int {
				n, _ := c.Write(make([]byte, 8<<20))
				return n
			})
			time.Sleep(100 * time.Millisecond) // the last segments cross the enforcer
			tx2, o2 := sentAndOther()
			rest := o2 - o
			sent = tx2 - tx - rest
			t.Logf("%s sent %d IP bytes elsewhere in the window", tc.box, rest)
			r.read()
			return tc.count(r.c.Counts()) - before, sent
		}
		if err := offload.Set(tc.port, map[string]bool{"rx-gro": true}); err != nil {
			t.Fatal(err)
		}
		merged, sent := send()
		t.Logf("%s with GRO on: counted %d of the %d IP bytes sent", tc.box, merged, sent)
		if merged >= sent {
			t.Errorf("%s: with GRO on the count (%d) did not run under the %d IP bytes sent: the harness merges nothing, so this test proves nothing", tc.box, merged, sent)
		}
		if err := offload.Off(tc.port); err != nil {
			t.Fatal(err)
		}
		counted, sent := send()
		t.Logf("%s with merging off: counted %d of the %d IP bytes sent", tc.box, counted, sent)
		if counted < sent {
			t.Errorf("%s: counted %d IP bytes, less than the %d that left its port", tc.box, counted, sent)
		}
	}
}
