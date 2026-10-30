package policy

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrRiskNotShown refuses a hold on a lock or an alarm whose rendered diff
// does not name the risk (NET-7 Freeze).
var ErrRiskNotShown = errors.New("policy: a hold on a lock or alarm needs a confirmation that names the risk")

// Unpatched reports whether the device's firmware is frozen or a security
// fix is held back for it (NET-7): either way it counts as unpatched, so
// none of its pairs has a path (Linked) while its outbound access stays
// its allow list (broker/enforcer/nft). Both holds are loosenings, so only
// the owner can set them, and lifting one is a loosening too.
func (d Document) Unpatched(device string) bool {
	for _, h := range d.Holds {
		if h.Device == device {
			return true
		}
	}
	return false
}

// Linked reports whether a pair with the device has a path at the
// device's end (NET-3, NET-7). An Owner or Household device always does,
// since that end is the whole network; a Devices-network device only with
// a Wi-Fi identity (its VLAN), not isolated and not unpatched; any other
// device never. broker/enforcer/nft compiles a pair to a path only when
// both ends are linked, and the page says when a change breaks or makes
// one.
func (d Document) Linked(device string) bool {
	dev := d.Device(device)
	switch {
	case dev == nil:
		return false
	case dev.Network == NetOwner || dev.Network == NetHousehold:
		return true
	}
	return dev.Network == NetDevices && dev.WiFi != "" && !dev.Isolated && !d.Unpatched(device)
}

// Risk is what a hold on a device of class risks, for a lock or an alarm,
// and empty for every other class (NET-7: "a lock or alarm is frozen only
// after an owner passkey assertion, verified by the enforcer, on a
// confirmation that names the risk"). The page renders it once for each
// hold RiskHolds lists; Engine.Propose refuses a diff that shows it fewer
// times.
func Risk(class string) string {
	switch class {
	case ClassLock:
		return "it is a lock, and a flaw found in its firmware stays open, which could let someone unlock it."
	case ClassAlarm:
		return "it is an alarm, and a flaw found in its firmware stays open, which could let someone silence or disarm it."
	}
	return ""
}

// RiskHolds is the holds in next whose risk the confirm screen must name:
// each hold on a lock or an alarm that old does not have, or whose
// device's class changes, so a held plug cannot become a held lock unseen.
func RiskHolds(old, next Document) []Hold {
	var out []Hold
	for _, h := range next.Holds {
		dev := next.Device(h.Device)
		if dev == nil || Risk(dev.Class) == "" {
			continue
		}
		if was := old.Device(h.Device); was != nil && was.Class == dev.Class && old.hasHold(h) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// riskShown checks that diff names the risk once for every hold RiskHolds
// lists, so one sentence cannot stand for two holds.
func riskShown(old, next Document, diff []byte) error {
	need := map[string]int{}
	for _, h := range RiskHolds(old, next) {
		need[Risk(next.Device(h.Device).Class)]++
	}
	for r, n := range need {
		if got := bytes.Count(diff, []byte(r)); got < n {
			return fmt.Errorf("%w: %d holds, the risk shown %d times", ErrRiskNotShown, n, got)
		}
	}
	return nil
}

func (d Document) hasHold(h Hold) bool {
	for _, x := range d.Holds {
		if x == h {
			return true
		}
	}
	return false
}
