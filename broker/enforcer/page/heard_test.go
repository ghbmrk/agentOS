package page

// REQ: NET-3, NET-4

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

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

	// A heard name another device pins or holds is left out of the fill,
	// so it can block no link (Security on #4531): cam proves tv's name
	// and the laptop's held one beside its own, and only its own is
	// offered.
	g.heard["vlan102"] = [][]string{{"cam", "local"}, {"macbook", "local"}, {"tv", "local"}}
	camPaired := clone(cur)
	camPaired.Pairs = append(camPaired.Pairs, policy.Pair{A: "laptop", B: "cam"})
	screen, id, ch = g.open(camPaired, "pair cam")
	plain = html.UnescapeString(screen)
	if !strings.Contains(plain, "Let cam announce the name cam.local") || strings.Contains(plain, "Let cam announce the name tv.local") || strings.Contains(plain, "Let cam announce the name macbook.local") {
		t.Errorf("cam's fill:\n%s", plain)
	}

	// Only the link that opens a pair's path fills: once cam's pair is
	// signed with nothing heard, a later unrelated link draws as it is,
	// whatever cam has announced since.
	g.heard["vlan102"] = nil
	screen, id, ch = g.open(camPaired, "pair cam")
	if strings.Contains(screen, "announce the name") {
		t.Fatalf("nothing heard, yet a name:\n%s", screen)
	}
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	g.now = g.now.Add(time.Duration(policy.Wait) * time.Millisecond)
	if _, err := g.e.Tick(g.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	cur = g.e.Current()
	if !slices.Contains(cur.Pairs, policy.Pair{A: "cam", B: "laptop"}) {
		t.Fatalf("cam's pair not in force: %+v", cur.Pairs)
	}
	g.heard["vlan102"] = [][]string{{"cam", "local"}, {"tv", "local"}}
	unrelated := clone(cur)
	dev(&unrelated, "cam").Allow = append(dev(&unrelated, "cam").Allow, "b.example")
	if screen, _, _ := g.open(unrelated, "allow"); strings.Contains(screen, "announce the name") {
		t.Errorf("an unrelated link was filled:\n%s", screen)
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

// TestHeardFillsWhenPathOpens: a pair signed while it had no path (tv
// isolated) is filled by the link that gives it its path, as a new pair
// is, and not by a link that keeps the path as it was.
func TestHeardFillsWhenPathOpens(t *testing.T) {
	g := newRig(t)
	g.heard["vlan104"] = [][]string{{"tv", "local"}}
	cur := edit(2, func(d *policy.Document) {
		d.Devices = append(d.Devices, policy.Device{ID: "laptop", Network: policy.NetHousehold, Everyday: true})
		d.Pairs = []policy.Pair{{A: "laptop", B: "tv"}}
		dev(d, "tv").Isolated = true
	})
	opened := clone(cur)
	dev(&opened, "tv").Isolated = false
	got, _, err := g.s.heard(cur, opened)
	if err != nil || len(got.Device("tv").MDNS) != 1 {
		t.Errorf("the path's return filled %q (%v)", got.Device("tv").MDNS, err)
	}
	// The other end's isolation lifted opens tv's path too.
	camOff := edit(2, func(d *policy.Document) {
		d.Pairs = []policy.Pair{{A: "cam", B: "tv"}}
		dev(d, "cam").Isolated = true
	})
	camOn := clone(camOff)
	dev(&camOn, "cam").Isolated = false
	if got, _, err := g.s.heard(camOff, camOn); err != nil || len(got.Device("tv").MDNS) != 1 {
		t.Errorf("the other end's return filled %q (%v)", got.Device("tv").MDNS, err)
	}
	kept := clone(opened)
	dev(&kept, "tv").Allow = append(dev(&kept, "tv").Allow, "b.example")
	if got, _, err := g.s.heard(opened, kept); err != nil || len(got.Device("tv").MDNS) != 0 {
		t.Errorf("a kept path filled %q (%v)", got.Device("tv").MDNS, err)
	}
}

// pairedTV is home(v) with a Household laptop paired with tv and the
// laptop holding macbook.local.
func pairedTV(v uint64) policy.Document {
	return edit(v, func(d *policy.Document) {
		d.Devices = append(d.Devices, policy.Device{ID: "laptop", Network: policy.NetHousehold, Everyday: true, MDNS: [][]string{{"macbook", "local"}}})
		d.Pairs = []policy.Pair{{A: "laptop", B: "tv"}}
	})
}

// sign has the owner approve the change screen id and ch drew, and lets
// it apply.
func (g *rig) sign(id, ch string) policy.Document {
	g.t.Helper()
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		g.t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	g.now = g.now.Add(time.Duration(policy.Wait) * time.Millisecond)
	if _, err := g.e.Tick(g.now.UnixMilli()); err != nil {
		g.t.Fatal(err)
	}
	return g.e.Current()
}

// TestHeardHolds: a person's network's names are held from what the
// enforcer heard there (#4411). The link that pairs a Household device
// offers every name heard on the Household network that no device pins
// or holds as a hold for it, on the card before the passkey; once
// signed, a device that later proves one of them is not offered it, and
// no document can pin it on a device (ErrNameHeld).
func TestHeardHolds(t *testing.T) {
	g := newRig(t)
	// tv.local stands for a name the relay's claims would keep from both
	// networks at once: the device that announces it gets it.
	g.heard["household"] = [][]string{{"macbook", "local"}, {"spouse-phone", "local"}, {"tv", "local"}}
	g.heard["vlan104"] = [][]string{{"tv", "local"}}
	screen, id, ch := g.open(pairedTV(2), "pair")
	plain := html.UnescapeString(screen)
	if !strings.Contains(plain, "Hold the name spouse-phone.local for laptop: no paired device may announce it.") ||
		strings.Contains(plain, "Hold the name tv.local") || strings.Count(plain, "Hold the name macbook.local") != 1 {
		t.Errorf("the pairing card's holds:\n%s", plain)
	}
	cur := g.sign(id, ch)
	if got, want := cur.Device("laptop").MDNS, [][]string{{"macbook", "local"}, {"spouse-phone", "local"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("laptop holds %q, want %q", got, want)
	}
	if got := cur.Device("tv").MDNS; !slices.EqualFunc(got, [][]string{{"tv", "local"}}, slices.Equal) {
		t.Fatalf("tv pins %q", got)
	}

	// cam, paired later, proves the held name on its own VLAN: it is not
	// offered, and a link that pins it anyway is refused naming both.
	g.heard["vlan102"] = [][]string{{"cam", "local"}, {"spouse-phone", "local"}}
	withCam := clone(cur)
	withCam.Pairs = append(withCam.Pairs, policy.Pair{A: "cam", B: "laptop"})
	if screen, _, _ := g.open(withCam, "pair cam"); strings.Contains(screen, "Let cam announce the name spouse-phone.local") ||
		!strings.Contains(screen, "Let cam announce the name cam.local") {
		t.Errorf("cam's fill:\n%s", screen)
	}
	dev(&withCam, "cam").MDNS = [][]string{{"spouse-phone", "local"}}
	if _, err := policy.Encode(withCam); !errors.Is(err, policy.ErrNameHeld) {
		t.Errorf("pinning a held name: %v", err)
	}

	// A link that keeps the pair's path fills no holds.
	g.heard["household"] = append(g.heard["household"], []string{"new-phone", "local"})
	kept := clone(cur)
	dev(&kept, "tv").Allow = append(dev(&kept, "tv").Allow, "b.example")
	if screen, _, _ := g.open(kept, "allow"); strings.Contains(screen, "Hold the name") {
		t.Errorf("a kept path filled holds:\n%s", screen)
	}
}

// TestHeardFillBounded: one card adds at most maxFill heard names to a
// device, hosts first, and says how many it left out (#4565, Security on
// #4531): a device flooding its VLAN cannot bury the card's other lines.
func TestHeardFillBounded(t *testing.T) {
	g := newRig(t)
	var flood, hosts [][]string
	for i := range 3 * maxFill {
		flood = append(flood, []string{fmt.Sprintf("Svc%03d", i), "_ipp", "_tcp", "local"})
	}
	for i := range 10 {
		h := []string{fmt.Sprintf("h%02d", i), "local"}
		hosts = append(hosts, h)
		flood = append(flood, h)
	}
	g.heard["vlan104"] = flood
	var person [][]string
	for i := range maxFill + 5 {
		person = append(person, []string{fmt.Sprintf("p%02d", i), "local"})
	}
	g.heard["household"] = person
	screen, id, ch := g.open(pairedTV(2), "pair")
	plain := html.UnescapeString(screen)
	if n := strings.Count(plain, "Let tv announce the name"); n != maxFill {
		t.Errorf("%d tv names on the card, want %d", n, maxFill)
	}
	if n := strings.Count(plain, "Hold the name p"); n != maxFill {
		t.Errorf("%d holds on the card, want %d", n, maxFill)
	}
	for _, want := range []string{
		fmt.Sprintf("%d more names tv announces are left out of this change; the home page offers them once it applies.", 3*maxFill+10-maxFill),
		"5 more names heard on the household network are left out of this change; the home page offers to hold them for laptop once it applies.",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("the card lacks %q:\n%s", want, plain)
		}
	}
	cur := g.sign(id, ch)
	tv := cur.Device("tv").MDNS
	if len(tv) != maxFill {
		t.Fatalf("tv pins %d names, want %d", len(tv), maxFill)
	}
	for _, h := range hosts {
		if !listed(tv, h) {
			t.Errorf("host %q left out before an instance", h)
		}
	}
	// The home page offers the next ones, at most maxFill again.
	offs := g.s.offers(cur)
	if len(offs) != 2 || offs[0].ID != "laptop" || len(offs[0].Names) != 5 || offs[1].ID != "tv" || len(offs[1].Names) != maxFill || offs[1].More != 3*maxFill+10-2*maxFill {
		t.Errorf("offers after the flood: %+v", offs)
	}
}

// TestHeardOffer: names a paired device starts announcing after its pair
// was signed are offered on the home page as their own change, one tap
// on the confirm screen, drawn by the enforcer from what it heard (#4566,
// UX on #4531): no unpairing. So are names newly heard on a person's
// network, as holds. No offer is made for an unpaired or isolated
// device, nor for a name another device pins or holds.
func TestHeardOffer(t *testing.T) {
	g := newRig(t)
	g.heard["vlan104"] = [][]string{{"tv", "local"}}
	_, id, ch := g.open(pairedTV(2), "pair")
	cur := g.sign(id, ch)

	g.heard["vlan104"] = [][]string{{"Living Room", "_airplay", "_tcp", "local"}, {"macbook", "local"}, {"tv", "local"}}
	g.heard["vlan102"] = [][]string{{"cam", "local"}} // unpaired
	g.heard["household"] = [][]string{{"spouse-phone", "local"}}
	w := g.do(http.MethodGet, "/", nil)
	home := html.UnescapeString(w.Body.String())
	for _, want := range []string{
		`tv now announces "Living Room._airplay._tcp.local": let it?`,
		`href="/heard?d=tv"`,
		"The household network now announces spouse-phone.local: hold them for laptop, so no paired device may announce them?",
		`href="/heard?d=laptop"`,
	} {
		if !strings.Contains(home, want) {
			t.Errorf("the home page lacks %q:\n%s", want, home)
		}
	}
	if strings.Contains(home, "cam now announces") || strings.Contains(home, "macbook.local: let") {
		t.Errorf("an unpaired device or a held name is offered:\n%s", home)
	}
	if w := g.do(http.MethodGet, "/heard?d=cam", nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), errNoOffer.Error()) {
		t.Errorf("no offer for cam: %d %s", w.Code, w.Body)
	}
	for _, bad := range []string{"/heard", "/heard?d=tv&d=tv", "/heard?d=tv&x=1"} {
		if w := g.do(http.MethodGet, bad, nil); w.Code != http.StatusBadRequest || reChal.MatchString(w.Body.String()) {
			t.Errorf("%s: %d %s", bad, w.Code, w.Body)
		}
	}

	// One tap lets tv announce its new name.
	w = g.do(http.MethodGet, "/heard?d=tv", nil)
	body := w.Body.String()
	m, c := reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if w.Code != http.StatusOK || m == nil || c == nil {
		t.Fatalf("the offer's screen: %d %s", w.Code, body)
	}
	plain := html.UnescapeString(body)
	if !strings.Contains(plain, `Let tv announce the name "Living Room._airplay._tcp.local" to the networks and devices it is paired with; no other device may use it.`) ||
		strings.Contains(plain, "macbook") || strings.Contains(plain, "Hold the name") {
		t.Errorf("the offer's card:\n%s", plain)
	}
	cur = g.sign(m[1], c[1])
	if got, want := cur.Device("tv").MDNS, [][]string{{"Living Room", "_airplay", "_tcp", "local"}, {"tv", "local"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("tv pins %q, want %q", got, want)
	}
	// And one holds the household's.
	w = g.do(http.MethodGet, "/heard?d=laptop", nil)
	body = w.Body.String()
	m, c = reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if w.Code != http.StatusOK || m == nil || !strings.Contains(body, "Hold the name spouse-phone.local for laptop") {
		t.Fatalf("the hold offer's screen: %d %s", w.Code, body)
	}
	cur = g.sign(m[1], c[1])
	if !listed(cur.Device("laptop").MDNS, []string{"spouse-phone", "local"}) {
		t.Fatalf("laptop holds %q", cur.Device("laptop").MDNS)
	}
	if offs := g.s.offers(cur); len(offs) != 0 {
		t.Errorf("still offered after signing: %+v", offs)
	}
	// A person's network is offered once, however many of its devices
	// are paired.
	g.heard["household"] = append(g.heard["household"], []string{"new-phone", "local"})
	two := clone(cur)
	two.Devices = append(two.Devices, policy.Device{ID: "desk", Network: policy.NetHousehold, Everyday: true})
	two.Pairs = append(two.Pairs, policy.Pair{A: "desk", B: "tv"})
	if offs := g.s.offers(two); len(offs) != 1 || !slices.EqualFunc(offs[0].Names, [][]string{{"new-phone", "local"}}, slices.Equal) {
		t.Errorf("two paired household devices: %+v", offs)
	}
	// An isolated device's pair has no path: nothing is offered for it.
	g.heard["vlan104"] = append(g.heard["vlan104"], []string{"tv-2", "local"})
	iso := clone(cur)
	dev(&iso, "tv").Isolated = true
	if offs := g.s.offers(iso); len(offs) != 0 {
		t.Errorf("offered for an isolated device: %+v", offs)
	}
}
