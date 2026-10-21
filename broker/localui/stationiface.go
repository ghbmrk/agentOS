package localui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
)

// StationIface is the station interface the loader creates on the access
// point's radio, beside the access point (#936), for NetworkManager to
// join the home Wi-Fi on while the phone stays on the access point
// (ONB-3). It is never the access point's: Start refuses it, and the
// loader leaves it out of the radios it brings down.
const StationIface = "wlsta0"

// IfaceType is an nl80211 interface type (enum nl80211_iftype).
type IfaceType uint32

// The two interface types the station check needs, as nl80211 numbers
// them.
const (
	IfaceStation IfaceType = 2 // NL80211_IFTYPE_STATION, "managed"
	IfaceAP      IfaceType = 3 // NL80211_IFTYPE_AP
)

// IfaceLimit is one limit of an interface combination: at most Max
// interfaces of the listed types together.
type IfaceLimit struct {
	Max   uint32
	Types []IfaceType
}

// IfaceCombination is one of a radio's interface combinations
// (NL80211_ATTR_INTERFACE_COMBINATIONS): interfaces within Limits, at most
// Total of them, on at most Channels different channels.
type IfaceCombination struct {
	Limits   []IfaceLimit
	Total    uint32
	Channels uint32
}

// RadioIface is a wireless interface as nl80211 lists it. Freq is the
// channel's frequency in MHz, 0 when it is on none (a station not
// associated).
type RadioIface struct {
	Name string
	Phy  uint32
	Type IfaceType
	Freq uint32
	MAC  net.HardwareAddr
}

// Radio is the nl80211 seam the loader creates the station through. The
// loader (agentos-ap) implements it over generic netlink; tests fake it.
type Radio interface {
	// Interfaces lists every wireless interface.
	Interfaces(ctx context.Context) ([]RadioIface, error)
	// Combinations reads phy's interface combinations. A radio that
	// lists none returns none; an answer it cannot parse is an error.
	Combinations(ctx context.Context, phy uint32) ([]IfaceCombination, error)
	// NewStation creates a managed interface name on phy with mac.
	NewStation(ctx context.Context, phy uint32, name string, mac net.HardwareAddr) error
}

// StationChannels is the most channels any combination that allows an
// access point and a station together gives, or 0 when none does. A
// combination naming no channel is malformed and allows nothing.
func StationChannels(combs []IfaceCombination) uint32 {
	var best uint32
	for _, c := range combs {
		if c.Channels > best && c.Total >= 2 && apAndStation(c.Limits) {
			best = c.Channels
		}
	}
	return best
}

// apAndStation says whether one access point and one station fit limits:
// in two limits, or in one that allows two.
func apAndStation(limits []IfaceLimit) bool {
	has := func(l IfaceLimit, t IfaceType) bool {
		for _, x := range l.Types {
			if x == t {
				return true
			}
		}
		return false
	}
	for i, a := range limits {
		if a.Max < 1 || !has(a, IfaceAP) {
			continue
		}
		for j, s := range limits {
			if s.Max < 1 || !has(s, IfaceStation) {
				continue
			}
			if i != j || a.Max >= 2 {
				return true
			}
		}
	}
	return false
}

// StationMAC is the station's address: the access point's with the
// locally administered bit set, and its last bit flipped if that bit was
// already set. A station and an access point with one address cannot both
// be up on a mac80211 radio, and the same box keeps the same address on
// the home network across restarts.
func StationMAC(ap net.HardwareAddr) (net.HardwareAddr, error) {
	if len(ap) != 6 {
		return nil, fmt.Errorf("localui: the access point's address %q is not an Ethernet address", ap.String())
	}
	m := bytes.Clone(ap)
	m[0] |= 0x02
	if bytes.Equal(m, ap) {
		m[5] ^= 0x01
	}
	return m, nil
}

// StationState is what EnsureStation found or did.
type StationState int

const (
	// StationNone: there is no station, because the radio does not
	// allow an access point and a station together, or its answer could
	// not be read or parsed.
	StationNone StationState = iota
	// StationMade: EnsureStation created the station.
	StationMade
	// StationPresent: the station was already there.
	StationPresent
)

func (s StationState) String() string {
	switch s {
	case StationMade:
		return "created"
	case StationPresent:
		return "present"
	}
	return "none"
}

// EnsureStation creates StationIface on ap's radio, managed, if it is not
// there and one of the radio's interface combinations allows an access
// point and a station together. A missing, unreadable or unparsable
// answer creates nothing, so a guard never fails open into a half-working
// radio; nor does a name already taken by anything but a station on ap's
// radio, which it never touches. It never brings any interface down. With
// no Radio it does nothing. Station and StationChannels then say what it
// found.
func (l *APLoader) EnsureStation(ctx context.Context, ap string) (StationState, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.station, l.channels = false, 0
	if l.Radio == nil {
		return StationNone, nil
	}
	ifs, err := l.Radio.Interfaces(ctx)
	if err != nil {
		return StationNone, fmt.Errorf("localui: listing the radios: %w", err)
	}
	var apIf, sta *RadioIface
	for i := range ifs {
		switch ifs[i].Name {
		case ap:
			apIf = &ifs[i]
		case StationIface:
			sta = &ifs[i]
		}
	}
	if apIf == nil {
		return StationNone, fmt.Errorf("localui: %s is not a radio nl80211 lists", ap)
	}
	combs, err := l.Radio.Combinations(ctx, apIf.Phy)
	if err != nil {
		return StationNone, fmt.Errorf("localui: reading %s's interface combinations: %w", ap, err)
	}
	ch := StationChannels(combs)
	if ch == 0 {
		return StationNone, nil
	}
	if sta != nil {
		if sta.Phy != apIf.Phy || sta.Type != IfaceStation {
			return StationNone, fmt.Errorf("localui: %s exists but is not a station on %s's radio", StationIface, ap)
		}
		l.station, l.channels = true, ch
		return StationPresent, nil
	}
	mac, err := StationMAC(apIf.MAC)
	if err != nil {
		return StationNone, err
	}
	if err := l.Radio.NewStation(ctx, apIf.Phy, StationIface, mac); err != nil {
		return StationNone, fmt.Errorf("localui: creating %s: %w", StationIface, err)
	}
	l.station, l.channels = true, ch
	return StationMade, nil
}

// Station says whether the last EnsureStation left StationIface beside
// the access point.
func (l *APLoader) Station() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.station
}

// StationChannels is how many channels the radio's best combination for
// an access point beside the station allows, 0 with no station. With one,
// the station's channel moves the access point (StationFreq).
func (l *APLoader) StationChannels() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.channels
}

// StationFreq is the station's frequency in MHz, 0 when it is on no
// channel or there is no station.
func (l *APLoader) StationFreq(ctx context.Context) (uint32, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.station || l.Radio == nil {
		return 0, nil
	}
	ifs, err := l.Radio.Interfaces(ctx)
	if err != nil {
		return 0, err
	}
	for _, i := range ifs {
		if i.Name == StationIface {
			return i.Freq, nil
		}
	}
	return 0, errors.New("localui: the station is gone")
}

// Channel24 is the 2.4 GHz channel (1-13) at freq MHz, 0 for any other
// frequency: the access point serves only those (APConfig.Channel).
func Channel24(freq uint32) int {
	if freq < 2412 || freq > 2472 || (freq-2412)%5 != 0 {
		return 0
	}
	return int((freq-2412)/5) + 1
}
