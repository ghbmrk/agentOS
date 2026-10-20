package main

// REQ: ONB-3, ONB-1, ONB-4, DEV-2, CH-9, STO-2, HW-1, HW-4, HW-10

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localui"
)

// boxRadio is the box's radio as nl80211 shows it: wlan0 on phy0, and
// wlsta0 once made. channels is what its one AP-and-station combination
// allows (0: none). At each NewStation it records how far the loader had
// got: the host calls Start made, and the access point's starts.
type boxRadio struct {
	mu       sync.Mutex
	b        *box
	channels uint32
	err      error // fails Combinations
	ifs      []localui.RadioIface
	made     int
	madeAt   struct{ hostCalls, started int }
}

func newBoxRadio(b *box, channels uint32) *boxRadio {
	r := &boxRadio{b: b, channels: channels,
		ifs: []localui.RadioIface{{Name: "wlan0", Type: localui.IfaceAP, MAC: net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x44, 0x55}}}}
	b.radio = r
	return r
}

func (r *boxRadio) Interfaces(context.Context) ([]localui.RadioIface, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]localui.RadioIface(nil), r.ifs...), nil
}

func (r *boxRadio) Combinations(context.Context, uint32) ([]localui.IfaceCombination, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if r.channels == 0 {
		return []localui.IfaceCombination{{Limits: []localui.IfaceLimit{{Max: 1, Types: []localui.IfaceType{localui.IfaceAP}}}, Total: 1, Channels: 1}}, nil
	}
	return []localui.IfaceCombination{{
		Limits:   []localui.IfaceLimit{{Max: 1, Types: []localui.IfaceType{localui.IfaceStation}}, {Max: 1, Types: []localui.IfaceType{localui.IfaceAP}}},
		Total:    2,
		Channels: r.channels,
	}}, nil
}

func (r *boxRadio) NewStation(_ context.Context, phy uint32, name string, mac net.HardwareAddr) error {
	r.b.host.mu.Lock()
	hc := len(r.b.host.calls)
	r.b.host.mu.Unlock()
	st := r.b.startedCount()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.made++
	r.madeAt.hostCalls, r.madeAt.started = hc, st
	r.ifs = append(r.ifs, localui.RadioIface{Name: name, Phy: phy, Type: localui.IfaceStation, MAC: mac})
	return nil
}

// present adds wlsta0 as a running box already has it, at freq.
func (r *boxRadio) present(freq uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ifs = append(r.ifs, localui.RadioIface{Name: localui.StationIface, Type: localui.IfaceStation, Freq: freq})
}

// tune puts the station on freq, as NetworkManager's join would.
func (r *boxRadio) tune(freq uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.ifs {
		if r.ifs[i].Name == localui.StationIface {
			r.ifs[i].Freq = freq
		}
	}
}

func (r *boxRadio) madeCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.made }

// touched reports any host call that names the station.
func (b *box) touchedStation() []string {
	b.host.mu.Lock()
	defer b.host.mu.Unlock()
	var out []string
	for _, c := range b.host.calls {
		if strings.Contains(c, localui.StationIface) {
			out = append(out, c)
		}
	}
	return out
}

// ONB-3, #936: on a radio that allows an access point and a station, the
// loader creates wlsta0 once, after Start brought the radios down and
// before the access point first comes up, and still serves the setup
// network on wlan0.
func TestTheStationIsMadeAfterStartBeforeUp(t *testing.T) {
	b := newBox(t, "wlan0")
	r := newBoxRadio(b, 2)
	cancel, done := b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == 1 })
	time.Sleep(5 * b.cfg.Poll)
	cancel()
	<-done
	if r.madeCount() != 1 {
		t.Fatalf("made %d stations, want 1", r.madeCount())
	}
	if r.madeAt.hostCalls == 0 || r.madeAt.started != 0 {
		t.Fatalf("made at %+v: want after Start's bring-down, before the first Up", r.madeAt)
	}
	if c := b.startedAt(0); c.Iface != "wlan0" || c.SSID != b.net.SSID {
		t.Fatalf("served %q on %s", c.SSID, c.Iface)
	}
	if got := b.touchedStation(); len(got) != 0 {
		t.Fatalf("the loader touched the station: %q", got)
	}
}

// #936: a restart finds wlsta0 (the kernel lists it with a phy80211, like
// any radio) and leaves it: no second station, no bring-down of it, and
// the access point still serves on wlan0.
func TestARestartLeavesTheStation(t *testing.T) {
	b := newBox(t, "wlan0", localui.StationIface)
	r := newBoxRadio(b, 2)
	r.present(2412)
	cancel, done := b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r.madeCount() != 0 {
		t.Fatalf("made %d stations beside the one there", r.madeCount())
	}
	if got := b.touchedStation(); len(got) != 0 {
		t.Fatalf("the loader touched the station: %q", got)
	}
	if c := b.startedAt(0); c.Iface != "wlan0" {
		t.Fatalf("served on %s", c.Iface)
	}
}

// wireless never lists the station, so no Start names it.
func TestWirelessLeavesOutTheStation(t *testing.T) {
	d := sysNet(t, []string{"wlan0", localui.StationIface, "wlan1"}, []string{"eth0"})
	got, err := wireless(d)
	if err != nil || strings.Join(got, ",") != "wlan0,wlan1" {
		t.Fatalf("wireless = %q, %v", got, err)
	}
}

// #936: a radio that does not allow both, or whose answer cannot be read,
// gets no station; the access point still comes up as before (ONB-4),
// and a box that cannot join over Wi-Fi joins over Ethernet (ONB-1).
func TestNoStationTheRadioDoesNotAllow(t *testing.T) {
	for name, set := range map[string]func(*boxRadio){
		"not allowed": func(r *boxRadio) { r.channels = 0 },
		"unreadable":  func(r *boxRadio) { r.err = errors.New("synthetic nl80211 fault") },
	} {
		t.Run(name, func(t *testing.T) {
			b := newBox(t, "wlan0")
			r := newBoxRadio(b, 1)
			set(r)
			cancel, done := b.runAsync(t)
			waitFor(t, func() bool { return b.startedCount() == 1 })
			time.Sleep(5 * b.cfg.Poll)
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if r.madeCount() != 0 || b.startedCount() != 1 {
				t.Fatalf("made %d stations, %d starts", r.madeCount(), b.startedCount())
			}
		})
	}
}

// CH-9, #936: on a radio that allows one channel between them, the
// station's 2.4 GHz channel moves the access point: Down, then Up on that
// channel, with the same network, once.
func TestSingleChannelFollowsTheStation(t *testing.T) {
	b := newBox(t, "wlan0")
	r := newBoxRadio(b, 1)
	cancel, done := b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == 1 })
	stops := func() int { b.ap.mu.Lock(); defer b.ap.mu.Unlock(); return b.ap.stops }
	before := stops()
	r.tune(2462) // channel 11
	waitFor(t, func() bool { return b.startedCount() == 2 })
	time.Sleep(5 * b.cfg.Poll)
	cancel()
	<-done
	if stops() <= before {
		t.Fatal("the access point moved without coming down")
	}
	first, second := b.startedAt(0), b.startedAt(1)
	if first.Channel != 6 || second.Channel != 11 || second.SSID != first.SSID || second.Password != first.Password {
		t.Fatalf("starts: channel %d then %d", first.Channel, second.Channel)
	}
	if b.startedCount() != 2 {
		t.Fatalf("%d starts: the access point kept moving", b.startedCount())
	}
}

// #936: a station on the access point's own channel, on 5 GHz (which the
// 2.4 GHz access point cannot follow) or not associated leaves the access
// point alone; so does any station on a radio that allows two channels.
func TestTheAccessPointStaysPut(t *testing.T) {
	for name, c := range map[string]struct {
		channels, freq uint32
	}{
		"same channel":   {1, 2437},
		"5 GHz":          {1, 5180},
		"not associated": {1, 0},
		"two channels":   {2, 2462},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBox(t, "wlan0")
			r := newBoxRadio(b, c.channels)
			r.present(c.freq)
			cancel, done := b.runAsync(t)
			waitFor(t, func() bool { return b.startedCount() == 1 })
			time.Sleep(10 * b.cfg.Poll)
			cancel()
			<-done
			if b.startedCount() != 1 {
				t.Fatalf("%d starts, want the access point left on its channel", b.startedCount())
			}
		})
	}
}

// ARC-1, HW-10: the station's log lines name no network and no key, not
// the setup network's nor the card's.
func TestTheStationLogsNoNetwork(t *testing.T) {
	var buf safeBuf
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	b := newBox(t, "wlan0")
	r := newBoxRadio(b, 1)
	cancel, done := b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == 1 })
	r.tune(2412)
	waitFor(t, func() bool { return b.startedCount() == 2 })
	b.reportCardNet(t)
	os.WriteFile(filepath.Join(b.cfg.Latch), []byte(`{"card_confirmed":true}`), 0o600)
	waitFor(t, func() bool { return b.startedCount() == 3 })
	cancel()
	<-done
	out := buf.String()
	if !strings.Contains(out, localui.StationIface) || !strings.Contains(out, "channel 1") {
		t.Fatalf("log says nothing of the station: %q", out)
	}
	for _, secret := range []string{b.net.SSID, b.net.Password, cardNet.SSID, cardNet.Password} {
		if strings.Contains(out, secret) {
			t.Fatalf("log holds a network name or key: %q", out)
		}
	}
}

type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
