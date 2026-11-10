package nft

// REQ: NET-3

import (
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// TestAnnounces: each device's VLAN interface carries the mDNS names its
// device pinned, and only those (#4144). A Household device's held names,
// a VLAN-less device's names and a device that pinned none give no entry,
// so the relay passes nothing from an interface nobody pinned names for.
func TestAnnounces(t *testing.T) {
	d := fixturePolicy()
	pin := func(id string, names ...[]string) {
		for i := range d.Devices {
			if d.Devices[i].ID == id {
				d.Devices[i].MDNS = names
			}
		}
	}
	pin("printer", []string{"printer", "local"}, []string{"Office Printer", "_ipp", "_tcp", "local"})
	pin("sensor-a", []string{"sensor-a", "local"})
	pin("laptop", []string{"laptop", "local"})
	pin("lock", []string{"lock", "local"})
	got, err := Announces(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][][]string{
		"ap0.105": {{"printer", "local"}, {"Office Printer", "_ipp", "_tcp", "local"}},
		"ap0.106": {{"sensor-a", "local"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Announces = %q, want %q", got, want)
	}
	// What it returns is its own: changing it changes no document.
	got["ap0.105"][0][0] = "x"
	if d.Device("printer").MDNS[0][0] != "printer" {
		t.Error("Announces aliases the document")
	}
	// A document the policy refuses, here one name pinned twice, gives
	// nothing.
	pin("sensor-b", []string{"PRINTER", "local"})
	if _, err := Announces(d, fixtureLayout()); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), policy.ErrNameHeld.Error()) {
		t.Errorf("a name pinned twice: %v", err)
	}
}

// TestHears: the relay listens on every signed pair's ends, on every
// device's VLAN, paired or not, so it hears the names each device proves
// its own (D-266), and on the Owner and Household networks, paired or
// not, so their names hold from the start (#4411); never on an isolated device's VLAN, which reaches
// nothing, the enforcer included; and the ruleset admits mDNS from
// exactly those interfaces.
func TestHears(t *testing.T) {
	d, l := fixturePolicy(), fixtureLayout()
	got, err := Hears(d, l)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ap0.101", "ap0.102", "ap0.103", "ap0.104", "ap0.105", "ap0.106", "ap0.107", "ap0.109", "hh0", "own0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hears %q, want %q", got, want)
	}
	text, err := Compile(d, l)
	if err != nil {
		t.Fatal(err)
	}
	set := `iifname { "` + strings.Join(want, `", "`) + `" } ip daddr 224.0.0.251 udp dport 5353 accept`
	if !strings.Contains(text, set) {
		t.Errorf("the ruleset lacks %q", set)
	}
	for i := range d.Devices {
		if d.Devices[i].WiFi == "vlan101" {
			d.Devices[i].Isolated = true
		}
	}
	if got, _ := Hears(d, l); slices.Contains(got, "ap0.101") {
		t.Errorf("hears an isolated device: %q", got)
	}
	if iface, ok := l.DeviceIface("vlan109"); !ok || iface != "ap0.109" {
		t.Errorf("vlan109 is %q", iface)
	}
	// With no pair at all, both person networks are still heard.
	d.Pairs = nil
	if got, _ := Hears(d, l); !slices.Contains(got, "own0") || !slices.Contains(got, "hh0") {
		t.Errorf("unpaired, hears %q", got)
	}
	for _, c := range []struct{ network, wifi, want string }{
		{policy.NetDevices, "vlan109", "ap0.109"},
		{policy.NetOwner, "", "own0"},
		{policy.NetHousehold, "vlan109", "hh0"},
		{policy.NetGuests, "", ""},
		{policy.NetDevices, "guest", ""},
	} {
		if got, ok := l.Iface(c.network, c.wifi); got != c.want || ok != (c.want != "") {
			t.Errorf("Iface(%s, %s) = %q %v, want %q", c.network, c.wifi, got, ok, c.want)
		}
	}
	if _, ok := l.DeviceIface("guest"); ok {
		t.Error("a name that is not a VLAN has an interface")
	}
}

// TestHearsRefusesWhatCompileRefuses: the relay is given no interfaces
// from a layout the ruleset refuses.
func TestHearsRefusesWhatCompileRefuses(t *testing.T) {
	l := fixtureLayout()
	l.Trunk = ""
	if got, err := Hears(fixturePolicy(), l); !errors.Is(err, ErrLayout) {
		t.Errorf("hears %v (err %v)", got, err)
	}
}

// TestEveryPathEndIsHeard (property, #5014 from the #5238 deletion): over
// many documents drawn from the fixture's devices, plus an Owner and a
// Household device, with each device isolated or not, unpatched or not,
// and random pairs among them, every end of every path the ruleset opens
// is an interface the relay hears. Hears adds no path end of its own, so
// a pair whose end it missed would pass records nowhere (NET-3 Casting).
func TestEveryPathEndIsHeard(t *testing.T) {
	l := fixtureLayout()
	r := rand.New(rand.NewPCG(5014, 5238))
	opened := 0
	for range 4000 {
		d := fixturePolicy()
		d.Devices = append(d.Devices, policy.Device{ID: "phone", Network: policy.NetOwner}, policy.Device{ID: "tablet", Network: policy.NetHousehold})
		for i := range d.Devices {
			d.Devices[i].Isolated = r.IntN(3) == 0
		}
		d.Holds = nil
		for _, v := range d.Devices {
			if v.Network == policy.NetDevices && r.IntN(5) == 0 {
				d.Holds = append(d.Holds, policy.Hold{Device: v.ID, Kind: policy.HoldFirmware})
			}
		}
		d.Pairs = nil
		for range r.IntN(6) {
			a, b := d.Devices[r.IntN(len(d.Devices))].ID, d.Devices[r.IntN(len(d.Devices))].ID
			if a != b {
				d.Pairs = append(d.Pairs, policy.Pair{A: a, B: b})
			}
		}
		paths, err := Paths(d, l)
		if err != nil {
			continue // a document the ruleset refuses has no paths
		}
		hears, err := Hears(d, l)
		if err != nil {
			t.Fatalf("hears refused what paths took: %v", err)
		}
		for _, p := range paths {
			opened++
			for _, end := range []string{p.From, p.To} {
				if !slices.Contains(hears, end) {
					t.Fatalf("path %v: end %q not heard (hears %q) in pairs %v", p, end, hears, d.Pairs)
				}
			}
		}
	}
	if opened < 1000 {
		t.Fatalf("only %d paths drawn: the property is barely tested", opened)
	}
}
