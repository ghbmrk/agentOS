package localui

import (
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// REQ: CH-12, ONB-3

// P2-2w c4 r1 (#1223): with no Wi-Fi device beside the access point, a
// saved home Wi-Fi can never come online, so the never-online note names
// Ethernet only, before pairing too, and the number step offers no rejoin
// form. Setup still continues. Since #1429 the page refuses a Wi-Fi join
// with no station device, so the Wi-Fi here was saved while one was
// present (a USB adapter since unplugged).
func TestNeverOnlineNoStationEthernetOnly(t *testing.T) {
	r := newRig(t)
	asked, station := 0, true
	r.srv.cfg.Station = func() bool { asked++; return station }
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
	station = false
	if n := joinNote.FindStringSubmatch(r.get("/setup")); n != nil {
		t.Fatalf("a note before never online: %q", n[1])
	}
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "offline", NeverOnline: true}
	r.hooks.mu.Unlock()
	page := r.get("/setup")
	n := joinNote.FindStringSubmatch(page)
	if n == nil || !strings.Contains(page, "Text your box") {
		t.Fatalf("number step without the note: %s", page)
	}
	note := html.UnescapeString(n[1])
	ch12(t, note)
	if !strings.Contains(note, "Setup can continue") || !strings.Contains(note, "Ethernet") {
		t.Fatalf("note lacks continue or Ethernet: %q", note)
	}
	for _, w := range []string{"password", "join again", "Wi-Fi name"} {
		if strings.Contains(note, w) {
			t.Fatalf("note suggests rejoining (%q) with no station device: %q", w, note)
		}
	}
	if strings.Contains(page, `action="/setup/network"`) {
		t.Fatalf("a rejoin form with no station device: %s", page)
	}
	if asked == 0 {
		t.Fatal("the page never asked for a station device")
	}

	// Pairing still works, and the note stays Ethernet only.
	m := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no pairing code")
	}
	if _, ok := r.srv.OfferText(ownerNum, "PAIR "+m[1]); !ok {
		t.Fatal("pairing refused while never online")
	}
	page = r.get("/setup")
	if n = joinNote.FindStringSubmatch(page); n == nil || strings.Contains(n[1], "password") {
		t.Fatalf("after pairing: %v", n)
	}
}

// A station device present keeps the rejoin advice and form (the c4
// behaviour TestNeverOnlineNote covers with no Station set).
func TestNeverOnlineWithStationKeepsRejoin(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Station = func() bool { return true }
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "offline", NeverOnline: true}
	r.hooks.mu.Unlock()
	page := r.get("/setup")
	n := joinNote.FindStringSubmatch(page)
	if n == nil || !strings.Contains(html.UnescapeString(n[1]), "Wi-Fi name and password") {
		t.Fatalf("no rejoin advice with a station device: %v", n)
	}
	if !strings.Contains(page, `action="/setup/network"`) {
		t.Fatalf("no rejoin form with a station device: %s", page)
	}
}

// StationDevice counts a wireless interface other than the access point's
// in a sysfs net class directory; anything unreadable counts as none, so
// the page never suggests a rejoin it cannot back.
func TestStationDevice(t *testing.T) {
	mk := func(t *testing.T, ifaces map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, kind := range ifaces {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "wireless":
				if err := os.Mkdir(filepath.Join(p, "wireless"), 0o755); err != nil {
					t.Fatal(err)
				}
			case "phy80211":
				if err := os.Symlink(dir, filepath.Join(p, "phy80211")); err != nil {
					t.Fatal(err)
				}
			}
		}
		return dir
	}
	for _, c := range []struct {
		name   string
		ifaces map[string]string
		want   bool
	}{
		{"ap only", map[string]string{"lo": "", "eth0": "", "wlan0": "wireless"}, false},
		{"ap and station vif", map[string]string{"eth0": "", "wlan0": "wireless", "wlan1": "phy80211"}, true},
		{"second adapter", map[string]string{"wlan0": "phy80211", "wlx001122": "wireless"}, true},
		{"wired only", map[string]string{"lo": "", "eth0": "", "enp1s0": ""}, false},
	} {
		if got := StationDevice(mk(t, c.ifaces), "wlan0"); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if StationDevice(filepath.Join(t.TempDir(), "missing"), "wlan0") {
		t.Error("an unreadable directory counted a station device")
	}
}
