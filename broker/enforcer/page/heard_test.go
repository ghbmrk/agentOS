package page

// REQ: NET-3, NET-4

import (
	"encoding/base64"
	"html"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// TestHeardNamesPinned: the names come from the enforcer, never the core
// (D-266, #4488). A link that pairs a Devices-network device and leaves
// its MDNS empty gets the names the relay heard it prove its own on its
// VLAN, listed on the card before the passkey and signed with it; a link
// that pins a name the enforcer never heard there is refused with the
// device and the name; a device the link adds, or gives another Wi-Fi
// identity, has been heard on no VLAN of its own yet, so it keeps the
// unpinned line; a name the policy in force already pins needs no
// hearing; a held name for a person's device is not checked; and a
// heard name another device pins is refused with policy's words.
func TestHeardNamesPinned(t *testing.T) {
	g := newRig(t)
	tvNames := [][]string{{"Living Room", "_airplay", "_tcp", "local"}, {"tv", "local"}}
	g.heard["vlan104"] = tvNames
	g.heard["vlan105"] = [][]string{{"printer", "local"}} // heard, but not yet in force
	g.heard["vlan110"] = [][]string{{"tv-moved", "local"}}
	laptop := func(d *policy.Document) {
		d.Devices = append(d.Devices, policy.Device{ID: "laptop", Network: policy.NetHousehold, Everyday: true, MDNS: [][]string{{"macbook", "local"}}})
	}
	paired := edit(2, func(d *policy.Document) {
		laptop(d)
		d.Pairs = []policy.Pair{{A: "laptop", B: "tv"}}
	})
	unpinnedLine := "laptop won't find tv by name: tv announces no names across this pair."

	// (2) A name the core adds that tv never announced is refused, naming
	// it; nothing is offered to sign.
	spoof := clone(paired)
	dev(&spoof, "tv").MDNS = [][]string{{"tv", "local"}, {"macbook-pro", "local"}}
	w := g.do(http.MethodGet, linkFor(spoof, "pair"), nil)
	if body := w.Body.String(); w.Code != http.StatusBadRequest ||
		!strings.Contains(body, `the enforcer never heard tv announce the name "macbook-pro.local" on its own address, so it cannot be pinned for tv: decline this link`) ||
		reChal.MatchString(body) {
		t.Errorf("an unheard name: %d %s", w.Code, body)
	}

	// The device a link adds has been heard on no VLAN in force, so it
	// keeps the unpinned line though its identity's VLAN has names.
	added := edit(2, func(d *policy.Document) {
		laptop(d)
		d.Devices = append(d.Devices, policy.Device{ID: "printer", Network: policy.NetDevices, WiFi: "vlan105", Everyday: true})
		d.Pairs = []policy.Pair{{A: "laptop", B: "printer"}}
	})
	if screen, _, _ := g.open(added, "printer"); !strings.Contains(html.UnescapeString(screen), "laptop won't find printer by name: printer announces no names across this pair.") ||
		strings.Contains(screen, "printer.local") {
		t.Errorf("an added device was filled:\n%s", screen)
	}
	// So does one this link moves to another VLAN.
	moved := clone(paired)
	dev(&moved, "tv").WiFi = "vlan110"
	if screen, _, _ := g.open(moved, "move"); !strings.Contains(html.UnescapeString(screen), unpinnedLine) || strings.Contains(screen, "tv-moved") || strings.Contains(screen, "tv.local") {
		t.Errorf("a moved device was filled:\n%s", screen)
	}
	// And an unpaired device is not filled.
	if screen, _, _ := g.open(edit(2, func(d *policy.Document) { dev(d, "tv").Allow = append(dev(d, "tv").Allow, "b.example") }), "allow"); strings.Contains(screen, "tv.local") {
		t.Errorf("an unpaired device was filled:\n%s", screen)
	}

	// (1) The pair with MDNS omitted: the card lists each heard name, and
	// the owner signs them.
	screen, id, ch := g.open(paired, "pair")
	plain := html.UnescapeString(screen)
	for _, want := range []string{
		"Let tv announce the name tv.local to the networks and devices it is paired with; no other device may use it.",
		`Let tv announce the name "Living Room._airplay._tcp.local" to the networks and devices it is paired with; no other device may use it.`,
		"Hold the name macbook.local for laptop: no paired device may announce it.",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("the card lacks %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, unpinnedLine) {
		t.Errorf("a filled device still says it announces nothing:\n%s", plain)
	}
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if _, err := g.e.Tick(g.now.UnixMilli() + policy.Wait); err != nil {
		t.Fatal(err)
	}
	cur := g.e.Current()
	if got := cur.Device("tv").MDNS; !slices.EqualFunc(got, tvNames, slices.Equal) {
		t.Fatalf("signed tv pins %q, want %q", got, tvNames)
	}

	// A pin already in force needs no hearing: the relay may have
	// restarted, and the next link keeps it.
	g.heard = map[string][][]string{}
	kept := clone(cur)
	dev(&kept, "tv").Allow = append(dev(&kept, "tv").Allow, "b.example")
	if screen, _, _ := g.open(kept, "allow"); strings.Contains(screen, "announce the name") {
		t.Errorf("a kept pin shows as new:\n%s", screen)
	}

	// A heard name another device pins: the fill clashes and the screen
	// says so in policy's words.
	g.heard["vlan102"] = [][]string{{"tv", "local"}}
	clash := clone(cur)
	clash.Pairs = append(clash.Pairs, policy.Pair{A: "laptop", B: "cam"})
	b, err := policy.Encode(clash)
	if err != nil {
		t.Fatal(err)
	}
	w = g.do(http.MethodGet, "/p?d="+base64.RawURLEncoding.EncodeToString(b), nil)
	if body := w.Body.String(); w.Code != http.StatusBadRequest || !strings.Contains(body, `one name is pinned twice: "tv.local" is`) || reChal.MatchString(body) {
		t.Errorf("a clashing heard name: %d %s", w.Code, body)
	}
}

// TestHeardNamesNeedAHearer: with no relay wired (Config.Heard nil), the
// page pins nothing and refuses every name a link adds to a
// Devices-network device (D-266).
func TestHeardNamesNeedAHearer(t *testing.T) {
	g := newRig(t)
	cfg := g.s.cfg
	cfg.Heard = nil
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.s = s
	next := edit(2, func(d *policy.Document) { dev(d, "tv").MDNS = [][]string{{"tv", "local"}} })
	if w := g.do(http.MethodGet, linkFor(next, "pin"), nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "the enforcer never heard tv") {
		t.Errorf("a pin with no hearer: %d %s", w.Code, w.Body)
	}
}
