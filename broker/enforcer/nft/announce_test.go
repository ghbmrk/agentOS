package nft

// REQ: NET-3

import (
	"errors"
	"reflect"
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
