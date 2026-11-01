package page

// REQ: NET-3, NET-4

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// TestMDNSNamesOnTheScreen: the pairing screen names each mDNS name a
// device pins or unpins (#4144): what a Devices-network device may
// announce across its pairs, or a name held for a Household device. Names
// compare exactly, so a change of case shows, and one that is not
// printable ASCII is shown quoted with escapes.
func TestMDNSNamesOnTheScreen(t *testing.T) {
	base := edit(1, func(d *policy.Document) {
		d.Devices = append(d.Devices, policy.Device{ID: "laptop", Network: policy.NetHousehold, Everyday: true})
		d.Pairs = []policy.Pair{{A: "laptop", B: "tv"}}
		dev(d, "tv").MDNS = [][]string{{"tv", "local"}}
	})
	next := clone(base)
	dev(&next, "tv").MDNS = [][]string{{"TV", "local"}, {"Living Room", "_airplay", "_tcp", "local"}}
	dev(&next, "laptop").MDNS = [][]string{{"Café", "_smb", "_tcp", "local"}}
	next.Devices = append(next.Devices, policy.Device{ID: "printer", Network: policy.NetDevices, WiFi: "vlan105", Everyday: true, MDNS: [][]string{{"printer", "local"}}})
	if _, err := policy.Encode(next); err != nil {
		t.Fatal(err)
	}
	got := Describe(base, next, zone)
	for _, want := range []string{
		"Let tv announce the name TV.local to the networks and devices it is paired with; no other device may use it.",
		`Let tv announce the name "Living Room._airplay._tcp.local" to the networks and devices it is paired with; no other device may use it.`,
		"Stop tv announcing the name tv.local to what it is paired with.",
		`Hold the name "Caf\u00e9._smb._tcp.local" for laptop: no paired device may announce it.`,
		"Let printer announce the name printer.local to the networks and devices it is paired with; no other device may use it.",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("the screen lacks %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
	back := Describe(next, base, zone)
	if !slices.Contains(back, `Stop holding the name "Caf\u00e9._smb._tcp.local" for laptop.`) {
		t.Errorf("unholding not shown:\n%s", strings.Join(back, "\n"))
	}
}

// TestMDNSConflictOnTheScreen: a change that pins a name another device
// already pins, or one held for a Household device, is refused on the
// confirm screen with the name and both devices, and offers nothing to
// sign; renamed, it opens (#4144, UX lens on #4145).
func TestMDNSConflictOnTheScreen(t *testing.T) {
	g := newRig(t)
	ok := edit(2, func(d *policy.Document) {
		dev(d, "tv").MDNS = [][]string{{"Den", "_airplay", "_tcp", "local"}}
		dev(d, "cam").MDNS = [][]string{{"Dex", "_airplay", "_tcp", "local"}}
	})
	b, err := policy.Encode(ok)
	if err != nil {
		t.Fatal(err)
	}
	// The core can text any bytes: here the camera's name is the TV's.
	clash := strings.Replace(string(b), `"Dex"`, `"DEN"`, 1)
	w := g.do(http.MethodGet, "/p?d="+base64.RawURLEncoding.EncodeToString([]byte(clash)), nil)
	body := w.Body.String()
	if w.Code != http.StatusBadRequest || !strings.Contains(body, `two devices announce one name: "Den._airplay._tcp.local" is cam's and tv's; rename one before signing`) {
		t.Errorf("the clash: %d %s", w.Code, body)
	}
	if reChal.MatchString(body) {
		t.Error("the clash offered a challenge")
	}
	if screen, _, _ := g.open(ok, "names"); !strings.Contains(screen, "announce the name") {
		t.Errorf("renamed, the screen lacks the names:\n%s", screen)
	}
}
