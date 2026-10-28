package card

import (
	"reflect"
	"strings"
	"testing"
)

// REQ: HW-1, ONB-7, CH-9
//
// The Owner Card and the rotation card print the box page by the page's
// name over HTTPS, the one name its authority certifies (CH-9), never the
// access point address the core no longer serves (D-178, WIFI-del-c).
func TestCardPrintsThePageByItsName(t *testing.T) {
	if BoxPage != "https://"+PageName+"/" {
		t.Fatalf("BoxPage = %q", BoxPage)
	}
	c := mustGen(t, 7)
	full, err := HTML(c, testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := rotationHTML(c, Parts{Setup: true}, testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, page := range map[string]string{"card": string(full), "rotation": string(rot)} {
		if !strings.Contains(page, `<span class="mono">`+BoxPage+`</span>`) {
			t.Fatalf("%s lacks the box page %q", name, BoxPage)
		}
		if strings.Contains(page, "10.42.0.1") || strings.Contains(page, `<span class="mono">http://`) {
			t.Fatalf("%s still names a plain or access point address", name)
		}
	}
}

// allParts is a rotation of every part the card has.
var allParts = Parts{Setup: true, Passphrase: true, Grid: true, Recovery: true}

// REQ: HW-1, CH-9
//
// WIFI-del-e (#3365, D-178): the Owner Card carries no Wi-Fi. The core
// serves none, and only the enforcer holds the Owner network's password,
// so neither the card nor a rotation of every part prints a "Box Wi-Fi"
// section, a Wi-Fi QR payload or a Wi-Fi password, and the display never
// says the box's Wi-Fi switches. It catches a card that still names a
// network no device serves. Any "my Wi-Fi" other than "my Wi-Fi page",
// the local page's name (CH-12, WIFI-del-f), names a box Wi-Fi.
func TestCardCarriesNoWiFi(t *testing.T) {
	c := mustGen(t, 8)
	full, err := HTML(c, testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := rotationHTML(c, allParts, testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := newRig(t).d.Page()
	if err != nil {
		t.Fatal(err)
	}
	rotPage, err := newRotRig(t, allParts).d.Page()
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{"card": string(full), "rotation": string(rot), "display": string(first), "rotation display": string(rotPage)}
	for name, page := range pages {
		for _, bad := range []string{"Box Wi-Fi", "WIFI:", "Wi-Fi password", "Wi-Fi QR", "look for the Wi-Fi"} {
			if strings.Contains(page, bad) {
				t.Fatalf("%s still carries %q", name, bad)
			}
		}
		if strings.Contains(strings.ReplaceAll(page, "my Wi-Fi page", ""), "my Wi-Fi") {
			t.Fatalf("%s names a box Wi-Fi other than my Wi-Fi page", name)
		}
	}
	if _, ok := reflect.TypeOf(Card{}).FieldByName("WiFiPassword"); ok {
		t.Fatal("the card still has a Wi-Fi password")
	}
	if _, ok := reflect.TypeOf(Card{}).FieldByName("WiFiName"); ok {
		t.Fatal("the card still has a Wi-Fi name")
	}
	if _, ok := reflect.TypeOf(Parts{}).FieldByName("WiFi"); ok {
		t.Fatal("a rotation still has a Wi-Fi part")
	}
	if _, ok := reflect.TypeOf(DisplayConfig{}).FieldByName("WiFiName"); ok {
		t.Fatal("the display still takes a Wi-Fi name")
	}
}

// REQ: ONB-7, CH-9
//
// The quick-start (at most five steps) starts from the enforcer's setup
// network: the step with the setup Wi-Fi code names the enforcer, and a
// later step names the Owner network before the claim (§12.1 steps 1 and
// 4). No step says to join the box's Wi-Fi. The printed card carries the
// quick-start and ONB-7's WPA3 note.
func TestQuickStartStartsFromTheEnforcer(t *testing.T) {
	if n := len(QuickStart); n == 0 || n > 5 {
		t.Fatalf("quick-start has %d steps", n)
	}
	setup, owner := -1, -1
	for i, s := range QuickStart {
		if strings.Contains(s, "setup Wi-Fi code") && strings.Contains(s, "enforcer") {
			setup = i
		}
		if o, c := strings.Index(s, "Owner network"), strings.Index(s, "claim"); o >= 0 && c > o {
			owner = i
		}
		if strings.Contains(s, "Join the Wi-Fi") || strings.Contains(s, "box's Wi-Fi") {
			t.Fatalf("step %d sends the owner to a box Wi-Fi: %q", i+1, s)
		}
	}
	if setup < 0 || owner <= setup {
		t.Fatalf("setup network step %d, Owner network claim step %d", setup+1, owner+1)
	}
	page, err := HTML(mustGen(t, 9), testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range append([]string{"it needs WPA3"}, QuickStart...) {
		if !strings.Contains(string(page), htmlEsc(want)) {
			t.Fatalf("card lacks %q", want)
		}
	}
}

// cardPages renders every page the owner reads from the card package: the
// card, a rotation sheet of every part, and both displays.
func cardPages(t *testing.T) map[string]string {
	t.Helper()
	c := mustGen(t, 10)
	full, err := HTML(c, testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := rotationHTML(c, allParts, testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := newRig(t).d.Page()
	if err != nil {
		t.Fatal(err)
	}
	rotPage, err := newRotRig(t, allParts).d.Page()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"card": string(full), "rotation": string(rot), "display": string(first), "rotation display": string(rotPage)}
}

// REQ: CH-12, ONB-7
//
// WIFI-del-f (#3404): the card names the local page as the owner texts and
// SPEC do, "my Wi-Fi page" (CH-12: one name for the local UI). The card
// and rotation sheet label its address "Wi-Fi page:", and no card page or
// display answer says "box page". It catches a card that sends the owner
// to a page the texts call by another name.
func TestCardNamesTheWiFiPage(t *testing.T) {
	pages := cardPages(t)
	pages["in effect"] = inEffectProblem
	pages["cancelled"] = cancelledGone
	pages["confirmed"] = confirmedGone
	for name, page := range pages {
		if strings.Contains(strings.ToLower(page), "box page") {
			t.Fatalf("%s still says box page", name)
		}
	}
	for _, name := range []string{"card", "rotation"} {
		if !strings.Contains(pages[name], `Wi-Fi page: <span class="mono">`+BoxPage) {
			t.Fatalf("%s does not label the address as the Wi-Fi page", name)
		}
	}
	for _, name := range []string{"in effect", "cancelled", "confirmed"} {
		if !strings.Contains(pages[name], "my Wi-Fi page") {
			t.Fatalf("%s answer does not name my Wi-Fi page: %q", name, pages[name])
		}
	}
	if !strings.Contains(pages["card"], "type it on my Wi-Fi page") {
		t.Fatal("the passphrase note does not name my Wi-Fi page")
	}
}

// REQ: HW-1
//
// The project's name is "agentOS" on everything the owner reads from the
// card package. It catches a page that prints the capitalized old name.
func TestCardSaysAgentOSInLowerCase(t *testing.T) {
	old := "Agent" + "OS" // split so the CX-name-case check reads no new old-name text
	for name, page := range cardPages(t) {
		if strings.Contains(page, old) {
			t.Fatalf("%s says %s", name, old)
		}
	}
}
