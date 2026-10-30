package nft

// REQ: NET-7, NET-5

import (
	"context"
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"

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
// by address, both ways, and never counts an address it refused, so a
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
		probe{from: "guest", addr: netOther, port: 80, want: connected, why: "a guest"},
	)
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
	if !strings.Contains(string(b), `"name": "t101_4"`) && !strings.Contains(string(b), `"name":"t101_4"`) {
		t.Error("the listing lacks the TV's counting set")
	}
	if _, err := (load.Loader{Bin: nftBin}).List(context.Background(), "enforcer; flush ruleset"); err == nil {
		t.Error("List took a table name that is not an identifier")
	}
}
