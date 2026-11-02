package nft

// REQ: NET-3

import (
	"errors"
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

// TestHears: the relay listens on every signed pair's ends and on every
// device's VLAN, paired or not, so it hears the names each device proves
// its own (D-266); never on an isolated device's VLAN, which reaches
// nothing, the enforcer included; and the ruleset admits mDNS from
// exactly those interfaces.
func TestHears(t *testing.T) {
	d, l := fixturePolicy(), fixtureLayout()
	got, err := Hears(d, l)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ap0.101", "ap0.102", "ap0.103", "ap0.104", "ap0.105", "ap0.106", "ap0.107", "hh0"}
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
	if _, ok := l.DeviceIface("guest"); ok {
		t.Error("a name that is not a VLAN has an interface")
	}
}
