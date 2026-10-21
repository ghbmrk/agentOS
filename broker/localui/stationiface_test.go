package localui

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// REQ: ONB-3, DEV-2, STO-2, HW-4

// fakeRadio is the nl80211 seam: ifs is what Interfaces lists, combs the
// combinations of each phy, and made the stations NewStation created,
// which then appear in ifs.
type fakeRadio struct {
	ifs                    []RadioIface
	combs                  map[uint32][]IfaceCombination
	ifsErr, combErr, nsErr error
	made                   []RadioIface
}

func (r *fakeRadio) Interfaces(context.Context) ([]RadioIface, error) {
	if r.ifsErr != nil {
		return nil, r.ifsErr
	}
	return append([]RadioIface(nil), r.ifs...), nil
}

func (r *fakeRadio) Combinations(_ context.Context, phy uint32) ([]IfaceCombination, error) {
	if r.combErr != nil {
		return nil, r.combErr
	}
	return r.combs[phy], nil
}

func (r *fakeRadio) NewStation(_ context.Context, phy uint32, name string, mac net.HardwareAddr) error {
	if r.nsErr != nil {
		return r.nsErr
	}
	i := RadioIface{Name: name, Phy: phy, Type: IfaceStation, MAC: mac}
	r.made = append(r.made, i)
	r.ifs = append(r.ifs, i)
	return nil
}

var apMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

// apSta is a combination that allows an access point and a station
// together, on ch channels: the usual mac80211 "#{ managed } <= 1,
// #{ AP } <= 1, total <= 2".
func apSta(ch uint32) IfaceCombination {
	return IfaceCombination{
		Limits:   []IfaceLimit{{Max: 1, Types: []IfaceType{IfaceStation}}, {Max: 1, Types: []IfaceType{IfaceAP}}},
		Total:    2,
		Channels: ch,
	}
}

func radioWith(combs ...IfaceCombination) *fakeRadio {
	return &fakeRadio{
		ifs:   []RadioIface{{Name: "wlan0", Phy: 0, Type: IfaceAP, MAC: apMAC}},
		combs: map[uint32][]IfaceCombination{0: combs},
	}
}

// ONB-3, #936: a radio that allows an access point and a station creates
// the station once, managed, on the access point's radio with its own
// address; a second ensure finds it and creates nothing. It never touches
// the host (no BringDown, no exemption change).
func TestEnsureStationCreatesTheStationOnce(t *testing.T) {
	h := newNetHost()
	l, _ := newLoader(h)
	r := radioWith(apSta(1))
	l.Radio = r
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	n := len(h.log)
	s, err := l.EnsureStation(context.Background(), "wlan0")
	if err != nil || s != StationMade {
		t.Fatalf("EnsureStation = %v, %v; want created", s, err)
	}
	want, _ := StationMAC(apMAC)
	if len(r.made) != 1 || r.made[0].Name != StationIface || r.made[0].Phy != 0 || r.made[0].MAC.String() != want.String() {
		t.Fatalf("created %+v", r.made)
	}
	if !l.Station() || l.StationChannels() != 1 {
		t.Fatalf("Station %v, channels %d", l.Station(), l.StationChannels())
	}
	s, err = l.EnsureStation(context.Background(), "wlan0")
	if err != nil || s != StationPresent || len(r.made) != 1 {
		t.Fatalf("second EnsureStation = %v, %v, created %d", s, err, len(r.made))
	}
	if len(h.log) != n {
		t.Fatalf("EnsureStation touched the host: %q", h.log[n:])
	}
}

// #936: anything short of a combination that fits one access point and
// one station creates nothing, and leaves no station claimed.
func TestEnsureStationCreatesNothingTheRadioDoesNotAllow(t *testing.T) {
	for name, combs := range map[string][]IfaceCombination{
		"none":             nil,
		"AP only":          {{Limits: []IfaceLimit{{Max: 2, Types: []IfaceType{IfaceAP}}}, Total: 2, Channels: 1}},
		"one of either":    {{Limits: []IfaceLimit{{Max: 1, Types: []IfaceType{IfaceAP, IfaceStation}}}, Total: 2, Channels: 1}},
		"total one":        {func() IfaceCombination { c := apSta(1); c.Total = 1; return c }()},
		"no channel":       {apSta(0)},
		"limit max zero":   {{Limits: []IfaceLimit{{Max: 0, Types: []IfaceType{IfaceStation}}, {Max: 1, Types: []IfaceType{IfaceAP}}}, Total: 2, Channels: 1}},
		"station only":     {{Limits: []IfaceLimit{{Max: 2, Types: []IfaceType{IfaceStation}}}, Total: 2, Channels: 1}},
		"other types":      {{Limits: []IfaceLimit{{Max: 2, Types: []IfaceType{7, 8}}}, Total: 2, Channels: 2}},
		"no limits at all": {{Total: 2, Channels: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			l, _ := newLoader(newNetHost())
			r := radioWith(combs...)
			l.Radio = r
			s, err := l.EnsureStation(context.Background(), "wlan0")
			if err != nil || s != StationNone || len(r.made) != 0 || l.Station() || l.StationChannels() != 0 {
				t.Fatalf("EnsureStation = %v, %v; created %d, Station %v", s, err, len(r.made), l.Station())
			}
		})
	}
}

// A single limit that allows two of AP-or-station fits both.
func TestStationChannelsSharedLimit(t *testing.T) {
	c := IfaceCombination{Limits: []IfaceLimit{{Max: 2, Types: []IfaceType{IfaceStation, IfaceAP}}}, Total: 2, Channels: 1}
	if got := StationChannels([]IfaceCombination{c}); got != 1 {
		t.Fatalf("StationChannels = %d, want 1", got)
	}
	if got := StationChannels([]IfaceCombination{apSta(1), apSta(2)}); got != 2 {
		t.Fatalf("StationChannels = %d, want the best, 2", got)
	}
}

// Fail closed: an answer that cannot be read creates nothing, says so,
// and clears what an earlier ensure found.
func TestEnsureStationFailsClosed(t *testing.T) {
	boom := errors.New("synthetic nl80211 fault")
	for name, set := range map[string]func(*fakeRadio){
		"interfaces":   func(r *fakeRadio) { r.ifsErr = boom },
		"combinations": func(r *fakeRadio) { r.combErr = boom },
		"new station":  func(r *fakeRadio) { r.nsErr = boom },
		"ap not listed": func(r *fakeRadio) {
			r.ifs = []RadioIface{{Name: "wlan1", Phy: 0, Type: IfaceAP, MAC: apMAC}}
		},
		"ap without address": func(r *fakeRadio) { r.ifs[0].MAC = nil },
		"name taken by an AP": func(r *fakeRadio) {
			r.ifs = append(r.ifs, RadioIface{Name: StationIface, Phy: 0, Type: IfaceAP})
		},
		"name taken on another radio": func(r *fakeRadio) {
			r.ifs = append(r.ifs, RadioIface{Name: StationIface, Phy: 1, Type: IfaceStation})
		},
	} {
		t.Run(name, func(t *testing.T) {
			l, _ := newLoader(newNetHost())
			r := radioWith(apSta(2))
			l.Radio = r
			if s, err := l.EnsureStation(context.Background(), "wlan0"); err != nil || s != StationMade {
				t.Fatalf("setup: %v, %v", s, err)
			}
			r.ifs, r.made = r.ifs[:1], nil
			set(r)
			s, err := l.EnsureStation(context.Background(), "wlan0")
			if err == nil || s != StationNone || len(r.made) != 0 || l.Station() || l.StationChannels() != 0 {
				t.Fatalf("EnsureStation = %v, %v; created %d, Station %v", s, err, len(r.made), l.Station())
			}
		})
	}
}

func TestEnsureStationWithoutARadioDoesNothing(t *testing.T) {
	l, _ := newLoader(newNetHost())
	if s, err := l.EnsureStation(context.Background(), "wlan0"); err != nil || s != StationNone || l.Station() {
		t.Fatalf("EnsureStation = %v, %v", s, err)
	}
	if f, err := l.StationFreq(context.Background()); f != 0 || err != nil {
		t.Fatalf("StationFreq = %d, %v", f, err)
	}
}

// #936: the station is never the access point's: Start refuses it and
// touches nothing for it, so a restart never brings it down.
func TestStartRefusesTheStation(t *testing.T) {
	h := newNetHost()
	l, _ := newLoader(h)
	err := l.Start(context.Background(), "wlan0", StationIface)
	if err == nil || !strings.Contains(err.Error(), StationIface) {
		t.Fatalf("Start = %v", err)
	}
	for _, s := range h.log {
		if strings.Contains(s, StationIface) {
			t.Fatalf("Start touched the station: %q", h.log)
		}
	}
	if err := l.Up(context.Background(), apCfg(StationIface)); err == nil {
		t.Fatal("the access point came up on the station")
	}
}

func TestStationFreq(t *testing.T) {
	l, _ := newLoader(newNetHost())
	r := radioWith(apSta(1))
	l.Radio = r
	if _, err := l.EnsureStation(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	r.ifs[1].Freq = 2437
	if f, err := l.StationFreq(context.Background()); f != 2437 || err != nil {
		t.Fatalf("StationFreq = %d, %v", f, err)
	}
	r.ifs = r.ifs[:1]
	if _, err := l.StationFreq(context.Background()); err == nil {
		t.Fatal("a gone station read as on a channel")
	}
}

func TestStationMAC(t *testing.T) {
	for in, want := range map[string]string{
		"00:11:22:33:44:55": "02:11:22:33:44:55",
		"02:11:22:33:44:55": "02:11:22:33:44:54",
		"03:11:22:33:44:54": "03:11:22:33:44:55",
	} {
		hw, _ := net.ParseMAC(in)
		got, err := StationMAC(hw)
		if err != nil || got.String() != want {
			t.Errorf("StationMAC(%s) = %v, %v; want %s", in, got, err, want)
		}
		if hw.String() != in {
			t.Errorf("StationMAC changed its input to %s", hw)
		}
	}
	if _, err := StationMAC(net.HardwareAddr{1, 2, 3}); err == nil {
		t.Error("a short address made a station address")
	}
}

func TestChannel24(t *testing.T) {
	for f, want := range map[uint32]int{2412: 1, 2437: 6, 2472: 13, 2484: 0, 2407: 0, 2413: 0, 5180: 0, 0: 0} {
		if got := Channel24(f); got != want {
			t.Errorf("Channel24(%d) = %d, want %d", f, got, want)
		}
	}
}
