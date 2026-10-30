package policy

// REQ: NET-7, NET-4

import (
	"errors"
	"slices"
	"testing"
)

// NET-7: freezing a device's firmware and holding back a security fix are
// loosenings: neither is on the closed list, so each waits out Wait after
// the owner's assertion and can be cancelled, and lifting one waits too. A
// hold on a lock or an alarm is accepted only over a diff that names its
// risk once per hold, so the core cannot get one signed silently. Catches
// a silent freeze.
func TestFreezeIsLoosening(t *testing.T) {
	hold := func(v uint64, hs ...Hold) Document {
		return edit(v, func(d *Document) { d.Holds = append(d.Holds, hs...) })
	}
	for name, next := range map[string]Document{
		"freeze an everyday device":   hold(2, Hold{Device: "tv", Kind: HoldFirmware}),
		"hold back a fix":             hold(2, Hold{Device: "tv", Kind: HoldFix}),
		"freeze a safety-list device": hold(2, Hold{Device: "plug", Kind: HoldFirmware}),
		"unfreeze":                    edit(2, func(d *Document) { d.Holds = nil }),
	} {
		if c := Classify(home(1), next); c.Tightening {
			t.Errorf("%s classifies as a tightening: %+v", name, c)
		}
	}

	e, a, _ := opened(t)
	const t0 = 10_000_000
	out, err := a.propose(t, e, Proposal{Doc: hold(2, Hold{Device: "tv", Kind: HoldFirmware}), Diff: []byte("Freeze tv's firmware.")}, t0)
	if err != nil || out.Applied || out.Pending == "" || out.DueMS != t0+Wait {
		t.Fatalf("a freeze: %+v %v", out, err)
	}
	if e.Current().Unpatched("tv") {
		t.Fatal("the freeze applied before the wait")
	}
	if _, err := e.Tick(t0 + Wait); err != nil || !e.Current().Unpatched("tv") {
		t.Fatalf("the freeze did not apply at +10 minutes: %v", err)
	}
	if e.Current().Unpatched("speaker") || !e.Current().Unpatched("cam") {
		t.Error("Unpatched does not follow the holds")
	}

	// A lock: refused without the risk, before anything is spent, so the
	// same version then goes through over a screen that names it.
	risk := Risk(ClassLock)
	if risk == "" || Risk(ClassAlarm) == "" || Risk(ClassPlug) != "" || Risk("") != "" {
		t.Fatal("Risk names other classes than a lock and an alarm")
	}
	lock := hold(3, Hold{Device: "tv", Kind: HoldFirmware}, Hold{Device: "lock", Kind: HoldFirmware})
	for _, diff := range []string{"Freeze lock's firmware.", "Risk: " + Risk(ClassAlarm)} {
		if _, err := a.propose(t, e, Proposal{Doc: lock, Diff: []byte(diff)}, t0+Wait); !errors.Is(err, ErrRiskNotShown) {
			t.Errorf("a lock frozen over %q: %v", diff, err)
		}
	}
	two := hold(3, Hold{Device: "tv", Kind: HoldFirmware}, Hold{Device: "lock", Kind: HoldFirmware}, Hold{Device: "lock", Kind: HoldFix})
	if _, err := a.propose(t, e, Proposal{Doc: two, Diff: []byte("Freeze lock.\nRisk: " + risk)}, t0+Wait); !errors.Is(err, ErrRiskNotShown) {
		t.Errorf("one risk line for two holds on a lock: %v", err)
	}
	out, err = a.propose(t, e, Proposal{Doc: lock, Diff: []byte("Freeze lock's firmware.\nRisk of holding back lock's updates: " + risk)}, t0+Wait)
	if err != nil || out.Applied || out.Pending == "" {
		t.Fatalf("a lock frozen over the risk: %+v %v", out, err)
	}

	// An alarm added with a hold, and a held device whose class becomes a
	// lock's, need the risk too; a hold already in force on the same class
	// does not.
	alarm := Device{ID: "siren-box", Network: NetDevices, Class: ClassAlarm}
	withAlarm := edit(4, func(d *Document) {
		d.Devices = append(d.Devices, alarm)
		d.Holds = append(d.Holds, Hold{Device: alarm.ID, Kind: HoldFix})
	})
	if got := RiskHolds(home(1), withAlarm); !slices.Equal(got, []Hold{{Device: alarm.ID, Kind: HoldFix}}) {
		t.Errorf("an alarm added with a hold: %+v", got)
	}
	if err := riskShown(home(1), withAlarm, []byte(Risk(ClassAlarm))); err != nil {
		t.Errorf("the alarm's risk shown: %v", err)
	}
	plug := Document{Devices: []Device{{ID: "box", Network: NetDevices, Class: ClassPlug}}, Holds: []Hold{{Device: "box", Kind: HoldFirmware}}}
	relabelled := Document{Devices: []Device{{ID: "box", Network: NetDevices, Class: ClassLock}}, Holds: plug.Holds}
	if got := RiskHolds(plug, relabelled); len(got) != 1 {
		t.Errorf("a held plug that becomes a lock: %+v", got)
	}
	if got := RiskHolds(relabelled, relabelled); len(got) != 0 {
		t.Errorf("a hold already in force: %+v", got)
	}
}

// NET-3, NET-7: Linked is the firewall's rule for a pair's end (nft
// TestPathsFollowLinked checks the two agree): an Owner or Household
// device always, a Devices-network device only with a Wi-Fi identity,
// unisolated and unheld, anything else never. Catches a hold that leaves
// a device's pairs open, or one that cuts a whole network's.
func TestLinked(t *testing.T) {
	d := edit(2, func(d *Document) {
		d.Devices = append(d.Devices,
			Device{ID: "phone", Network: NetOwner},
			Device{ID: "laptop", Network: NetHousehold},
			Device{ID: "guest", Network: NetGuests, WiFi: "vlan107"},
			Device{ID: "old", Network: NetDevices, WiFi: "vlan106", Isolated: true})
		d.Holds = []Hold{{Device: "cam", Kind: HoldFirmware}, {Device: "laptop", Kind: HoldFix}, {Device: "phone", Kind: HoldFirmware}}
	})
	want := map[string]bool{"phone": true, "laptop": true, "tv": true, "plug": true, "cam": false, "lock": false, "guest": false, "old": false, "nobody": false}
	for id, w := range want {
		if got := d.Linked(id); got != w {
			t.Errorf("Linked(%q) = %v, want %v", id, got, w)
		}
	}
}
