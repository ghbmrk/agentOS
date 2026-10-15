package localui

import (
	"context"
	"encoding/json"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-3, ONB-4, CH-12

// P2-2w c4: never_online and the offline phase cross from agentosd's
// progress to the page's.
func TestAgentosdProgressCarriesNeverOnline(t *testing.T) {
	for _, c := range []struct {
		in   localapi.SetupProgress
		want Progress
	}{
		{localapi.SetupProgress{Phase: "offline", NeverOnline: true}, Progress{Phase: "offline", NeverOnline: true}},
		{localapi.SetupProgress{Phase: "offline"}, Progress{Phase: "offline"}},
		{localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}, Progress{Phase: "ready", Updated: true, Online: true}},
	} {
		a := AgentosdSetup{Owner: InProcess{localapi.OpSetupProgress: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return c.in, nil
		}}}
		if got := a.Progress(); got != c.want {
			t.Errorf("%+v gave %+v", c.in, got)
		}
	}
}

// joinNote finds the never-online note on a setup page.
var joinNote = regexp.MustCompile(`<p class="err" id="uplink">([^<]*)</p>`)

func ch12(t *testing.T, s string) {
	t.Helper()
	if n, gsm := modem.Segments(s); !gsm || n > 3 {
		t.Fatalf("note breaks CH-12 (%d segments, gsm7 %v): %q", n, gsm, s)
	}
	for _, w := range []string{"netjoin", "agentosd", "helper", "socket", "NetworkManager", "saved state", "uplink"} {
		if strings.Contains(s, w) {
			t.Fatalf("note names %q: %q", w, s)
		}
	}
}

// A saved home Wi-Fi that never came online: before pairing, every step
// says so with a rejoin form and Ethernet; after pairing, Ethernet only.
// Setup continues in both.
func TestNeverOnlineNote(t *testing.T) {
	r := newRig(t)
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
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
	before := html.UnescapeString(n[1])
	ch12(t, before)
	for _, w := range []string{"Setup can continue", "Wi-Fi name and password", "Ethernet"} {
		if !strings.Contains(before, w) {
			t.Fatalf("note lacks %q: %q", w, before)
		}
	}
	if !strings.Contains(page, `action="/setup/network"`) || !strings.Contains(page, `<option value="Neighbor">Neighbor</option>`) {
		t.Fatalf("no rejoin form on the number step: %s", page)
	}
	r.post("/setup/network", url.Values{"ssid": {"Neighbor"}, "password": {"home-pass"}})
	if r.hooks.joined != "Neighbor" {
		t.Fatalf("rejoin went to %q", r.hooks.joined)
	}
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "offline", NeverOnline: true}
	r.hooks.mu.Unlock()

	// Pairing still works, and the note then names Ethernet only.
	m := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(r.get("/setup"))
	if m == nil {
		t.Fatal("no pairing code")
	}
	if _, ok := r.srv.OfferText(ownerNum, "PAIR "+m[1]); !ok {
		t.Fatal("pairing refused while never online")
	}
	page = r.get("/setup")
	n = joinNote.FindStringSubmatch(page)
	if n == nil || !strings.Contains(page, "Add approval codes") {
		t.Fatalf("codes step without the note: %s", page)
	}
	after := html.UnescapeString(n[1])
	ch12(t, after)
	if !strings.Contains(after, "Setup can continue") || !strings.Contains(after, "Ethernet") || strings.Contains(after, "password") {
		t.Fatalf("after pairing: %q", after)
	}
	if strings.Contains(page, `action="/setup/network"`) {
		t.Fatal("a network form after pairing")
	}
	if before == after {
		t.Fatal("one note for both")
	}
}

// noScan is setup with no networks in range to list (until c4b).
type noScan struct{ *fakeHooks }

func (noScan) Networks() []string { return nil }

// With no list, the network step takes a typed name.
func TestNetworkStepTakesATypedName(t *testing.T) {
	r := newRig(t)
	r.via = noScan{r.hooks}
	r.srv = r.open(&MemStore{})
	page := r.get("/setup")
	if !strings.Contains(page, `<input type="text" name="ssid"`) || strings.Contains(page, "<select") {
		t.Fatalf("no typed name: %s", page)
	}
	r.post("/setup/network", url.Values{"ssid": {"My Home 5G"}, "password": {"home-pass"}})
	if r.hooks.joined != "My Home 5G" {
		t.Fatalf("joined %q", r.hooks.joined)
	}
	if !strings.Contains(r.get("/setup"), "Text your box") {
		t.Fatal("setup did not move on")
	}
}
