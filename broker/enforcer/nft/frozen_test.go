package nft

// REQ: NET-7, NET-5

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// frozenPolicy is the fixture with the TV's and sensor-a's firmware frozen
// and a security fix held back for the printer (NET-7).
func frozenPolicy() policy.Document {
	d := fixturePolicy()
	d.Holds = []policy.Hold{{Device: "tv", Kind: policy.HoldFirmware}, {Device: "sensor-a", Kind: policy.HoldFirmware}, {Device: "printer", Kind: policy.HoldFix}}
	return d
}

// NET-7: a frozen or held device counts as unpatched: it is isolated (no
// signed pair opens a path to or from it, nor carries its mDNS records)
// and its outbound access is cut to its allow list, while the boxes'
// control paths are unchanged. Catches a silent freeze that leaves a
// device's lateral paths open.
func TestFrozenIsolated(t *testing.T) {
	paths, err := Paths(frozenPolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		for _, ifc := range []string{"ap0.101", "ap0.105", "ap0.106"} {
			if p.From == ifc || p.To == ifc {
				t.Errorf("a path with an unpatched device: %+v", p)
			}
		}
	}
	if open, _ := Paths(fixturePolicy(), fixtureLayout()); len(open) <= len(paths) {
		t.Errorf("the holds closed no path: %+v", open)
	}
	if !inNetns(t) {
		return
	}
	h := build(t)
	h.expect(
		probe{from: "106", addr: devAddr(107), port: 80, want: connected, why: "the pair before the freeze"},
		probe{from: "household", addr: devAddr(105), port: 80, want: connected, why: "Household's pair before the hold"},
	)
	text, err := Compile(frozenPolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(text)
	run(t, "nft", "add", "element", "inet", Table, DeviceSet(101, false), "{ "+netAllow+" }")
	h.expect(
		probe{from: "106", addr: devAddr(107), port: 80, why: "a frozen device's pair"},
		probe{from: "107", addr: devAddr(106), port: 80, why: "the pair to a frozen device"},
		probe{from: "household", addr: devAddr(105), port: 80, why: "Household's pair to a held device"},
		probe{from: "101", addr: netAllow, port: 80, want: connected, why: "a frozen device keeps its allow list"},
		probe{from: "101", addr: netOther, port: 80, why: "and reaches nothing else"},
		probe{from: "101", addr: devAddr(102), port: 80, why: "nor another device"},
		probe{from: "edge", addr: devAddr(101), port: 80, want: connected, why: "the edge still reaches its control port"},
		probe{from: "core", addr: devAddr(102), port: 80, want: connected, why: "an unheld device is unchanged"},
	)
}

// NET-5: the ruleset counts each device's bytes on accepted connections,
// by address, both ways, and never counts an address it refused either
// way (out to an unlisted host, in from the internet), so a
// summary's destinations are only what the device reached. The counting
// sets read back through the loader's listing.
func TestDeviceTrafficCounted(t *testing.T) {
	// A home with no device on a VLAN has no counting map at all (nft
	// refuses an empty one).
	empty, err := Compile(policy.Document{Version: 1}, fixtureLayout())
	if err != nil || strings.Contains(empty, "vmap") || strings.Contains(empty, "_count") {
		t.Errorf("a home with no devices: counting rules present (%v)", err)
	}
	if !inNetns(t) {
		return
	}
	h := build(t)
	h.expect(
		probe{from: "101", addr: netAllow, port: 80, want: connected, why: "allow list"},
		probe{from: "101", addr: netOther, port: 80, why: "refused"},
		probe{from: "isp", addr: devAddr(101), port: 80, why: "refused inbound from the internet"},
		probe{from: "guest", addr: netOther, port: 80, want: connected, why: "a guest"},
		probe{from: "household", addr: devAddr(105), port: 80, want: connected, why: "Household casts to its paired printer"},
	)
	// An unpaired device forges an ICMP error about the edge's open
	// connection to the TV: conntrack calls it related, and it must not
	// enter either device's counts.
	var edgeConn net.Conn
	within(t, h.hosts["edge"], func() {
		var err error
		if edgeConn, err = net.DialTimeout("tcp", devAddr(101)+":80", 2*time.Second); err != nil {
			t.Fatalf("the edge to the TV's control port: %v", err)
		}
	})
	defer edgeConn.Close()
	lport := uint16(edgeConn.LocalAddr().(*net.TCPAddr).Port)
	within(t, h.hosts["102"], func() {
		c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			t.Fatalf("raw ICMP socket: %v", err)
		}
		defer c.Close()
		for range 3 {
			if _, err := c.WriteTo(icmpUnreachable(devAddr(101), segNets["edge"]+".2", 80, lport), &net.IPAddr{IP: net.ParseIP(devAddr(101))}); err != nil {
				t.Fatal(err)
			}
		}
	})
	time.Sleep(200 * time.Millisecond)
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	b, err := load.Loader{Bin: nftBin}.List(context.Background(), Table)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	counters, elems := map[string]uint64{}, map[string][]string{}
	for _, o := range doc.Nftables {
		var c struct {
			Name  string
			Bytes uint64
		}
		if raw, ok := o["counter"]; ok && json.Unmarshal(raw, &c) == nil {
			counters[c.Name] = c.Bytes
		}
		var s struct {
			Name string
			Elem []struct {
				Elem struct {
					Val     string
					Counter *struct{ Bytes uint64 }
				}
			}
		}
		if raw, ok := o["set"]; ok && json.Unmarshal(raw, &s) == nil {
			for _, e := range s.Elem {
				if e.Elem.Counter != nil && e.Elem.Counter.Bytes > 0 {
					elems[s.Name] = append(elems[s.Name], e.Elem.Val)
				}
			}
		}
	}
	if counters[TrafficOut(101)] == 0 || counters[TrafficIn(101)] == 0 {
		t.Errorf("the TV's counters: out %d, in %d", counters[TrafficOut(101)], counters[TrafficIn(101)])
	}
	if got := elems[TrafficSet(101, false)]; !slices.Equal(got, []string{netAllow}) {
		t.Errorf("the TV's destinations: %q, want only %s", got, netAllow)
	}
	for name, vals := range elems {
		if strings.HasPrefix(name, "t") && name != TrafficSet(101, false) {
			t.Errorf("set %s counted %q", name, vals)
		}
	}
	if counters[TrafficIn(102)] != 0 || counters[TrafficOut(102)] != 0 {
		t.Errorf("a forged ICMP error counted for its sender: %d %d", counters[TrafficOut(102)], counters[TrafficIn(102)])
	}
	if !strings.Contains(string(b), `"name": "t101_4"`) && !strings.Contains(string(b), `"name":"t101_4"`) {
		t.Error("the listing lacks the TV's counting set")
	}
	if _, err := (load.Loader{Bin: nftBin}).List(context.Background(), "enforcer; flush ruleset"); err == nil {
		t.Error("List took a table name that is not an identifier")
	}
}

// icmpUnreachable is an ICMP host-unreachable message about a TCP packet
// from src:sport to dst:dport, as a router on that path would send it.
func icmpUnreachable(src, dst string, sport, dport uint16) []byte {
	inner := make([]byte, 28)
	inner[0], inner[8], inner[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(inner[2:], 40)
	copy(inner[12:16], net.ParseIP(src).To4())
	copy(inner[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(inner[10:], checksum(inner[:20]))
	binary.BigEndian.PutUint16(inner[20:], sport)
	binary.BigEndian.PutUint16(inner[22:], dport)
	msg := append([]byte{3, 1, 0, 0, 0, 0, 0, 0}, inner...)
	binary.BigEndian.PutUint16(msg[2:], checksum(msg))
	return msg
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
