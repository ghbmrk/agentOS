package main

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/claim"
)

// REQ: HW-10, CH-9
//
// The sticker's claim link is the page's name over HTTPS with the code
// (D-178, WIFI-del-c): the core has no access point address, and the plain
// listener's redirect to HTTPS keeps only the path, so a plain link would
// open /claim without the code.
func TestStickerClaimLinkIsThePageName(t *testing.T) {
	code := "CCCC-CCCC-CCCC-CCCC"
	if got, want := claimURL(code), "https://"+card.PageName+"/claim?code="+code; got != want {
		t.Fatalf("claim link = %q, want %q", got, want)
	}
	out := t.TempDir()
	if err := writeSticker(out, code, claim.SetupNet{SSID: "agentos-setup-test", Password: "PWPW-PWPW-PWPW-PWPW"}); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(out, "sticker.html"))
	if err != nil {
		t.Fatal(err)
	}
	txt, err := os.ReadFile(filepath.Join(out, "sticker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	qr, err := card.QRSVG(claimURL(code))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), string(qr)) || !strings.Contains(string(html), "open "+card.BoxPage+"claim and type") {
		t.Fatal("sticker.html lacks the claim QR or the typed link on the page name")
	}
	if !strings.Contains(string(txt), "Claim page: "+claimURL(code)+"\n") {
		t.Fatalf("sticker.txt lacks the claim link: %q", txt)
	}
	for name, b := range map[string][]byte{"sticker.html": html, "sticker.txt": txt} {
		if strings.Contains(string(b), "10.42.0.1") {
			t.Fatalf("%s still names the access point address", name)
		}
	}
}

// REQ: HW-10
//
// The core serves no network (D-178, WIFI-del-a2, a3), so prep seals only
// the claim state: nothing at claim.SetupNetPath, and an image without the
// access point loader's directory (WIFI-del-b) is accepted.
func TestPrepSealsNoSetupNetwork(t *testing.T) {
	needTools(t)
	img, sums := writeImage(t, standardDisk(t, rootTree))
	out := filepath.Join(t.TempDir(), "box1")
	if err := runPrep(img, sums, out); err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(out, "box.raw")
	off, err := rootOffset(box)
	if err != nil {
		t.Fatal(err)
	}
	ents := entries(t, box, off)
	if _, ok := ents[claim.StatePath]; !ok {
		t.Fatalf("no claim state in %v", ents)
	}
	for p := range ents {
		if p == claim.SetupNetPath || p == path.Dir(claim.SetupNetPath) {
			t.Fatalf("the core image holds %s", p)
		}
	}

	// An image that already has /var/lib/agentos but no ap directory.
	tree := map[string]string{"var/lib/agentos/": ""}
	for k, v := range rootTree {
		tree[k] = v
	}
	img, sums = writeImage(t, standardDisk(t, tree))
	if err := runPrep(img, sums, filepath.Join(t.TempDir(), "box2")); err != nil {
		t.Fatalf("prep refused an image without the ap directory: %v", err)
	}
}

// REQ: HW-10
//
// The seller hands the setup network to the enforcer's preload (D-178) in
// enforcer-setup-net.json: 0600, parseable, the network the sticker
// prints, a password apart from the code, and never overwritten.
func TestEnforcerSetupNetworkIsHandedOff(t *testing.T) {
	needTools(t)
	img, sums := writeImage(t, standardDisk(t, rootTree))
	out := filepath.Join(t.TempDir(), "box1")
	if err := runPrep(img, sums, out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(out, enforcerNetFile)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %v, want 0600", p, fi.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	net, err := claim.ParseSetupNet(b)
	if err != nil {
		t.Fatal(err)
	}
	txt, err := os.ReadFile(filepath.Join(out, "sticker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(out, "sticker.html"))
	if err != nil {
		t.Fatal(err)
	}
	m := codeLineRe.FindStringSubmatch(string(txt))
	if m == nil {
		t.Fatalf("no code in sticker.txt: %q", txt)
	}
	code := m[1]
	if net.Password == code || claim.Normalize(net.Password)[:claim.PrefixSymbols] == claim.Normalize(code)[:claim.PrefixSymbols] {
		t.Fatal("the setup password is the claim code")
	}
	for _, want := range []string{"Wi-Fi network: " + net.SSID + "\n", "Wi-Fi password: " + net.Password + "\n"} {
		if !strings.Contains(string(txt), want) {
			t.Fatalf("sticker.txt lacks %q: %q", want, txt)
		}
	}
	wq, err := card.QRSVG(card.WiFiQR(net.SSID, net.Password))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{string(wq), ">" + net.SSID + "<", ">" + net.Password + "<"} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("sticker.html lacks %.60q", want)
		}
	}

	// writeNew refuses an existing hand-off file; the old one is kept.
	if err := writeEnforcerNet(out, claim.SetupNet{SSID: "agentos-setup-other", Password: "PWPW-PWPW-PWPW-PWPW"}); err == nil {
		t.Fatal("the hand-off file was overwritten")
	}
	if again, err := os.ReadFile(p); err != nil || string(again) != string(b) {
		t.Fatalf("the hand-off file changed: %v", err)
	}
}

// REQ: HW-10, CH-9
//
// Step 1 is the enforcer's setup Wi-Fi with its QR; step 2 claims once the
// phone is back on the Owner network, before the claim QR (§12.1 steps 1
// and 4). The setup network opens only the enforcer's page.
func TestStickerStepOneIsTheEnforcers(t *testing.T) {
	out := t.TempDir()
	net := claim.SetupNet{SSID: "agentos-setup-test", Password: "PWPW-PWPW-PWPW-PWPW"}
	code := "CCCC-CCCC-CCCC-CCCC"
	if err := writeSticker(out, code, net); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "sticker.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	wq, err := card.QRSVG(card.WiFiQR(net.SSID, net.Password))
	if err != nil {
		t.Fatal(err)
	}
	cq, err := card.QRSVG(claimURL(code))
	if err != nil {
		t.Fatal(err)
	}
	s1, s2 := strings.Index(html, `<div class="step">1.`), strings.Index(html, `<div class="step">2.`)
	iw, ic := strings.Index(html, string(wq)), strings.Index(html, string(cq))
	if s1 < 0 || s2 < 0 || iw < 0 || ic < 0 || !(s1 < iw && iw < s2 && s2 < ic) {
		t.Fatalf("step order: step1 %d, wifi QR %d, step2 %d, claim QR %d", s1, iw, s2, ic)
	}
	if !strings.Contains(strings.ToLower(html[s1:s2]), "enforcer") {
		t.Fatalf("step 1 does not name the enforcer: %q", html[s1:iw])
	}
	if !strings.Contains(html[s2:ic], "Owner network") {
		t.Fatalf("step 2 does not name the Owner network before the claim QR: %q", html[s2:ic])
	}

	t2, err := os.ReadFile(filepath.Join(out, "sticker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	txt := string(t2)
	// Step 2 is everything after the setup password: it names the Owner
	// network before the claim code.
	in, ip := strings.Index(txt, "Wi-Fi network: "+net.SSID), strings.Index(txt, "Wi-Fi password: "+net.Password)
	ie := strings.Index(strings.ToLower(txt), "enforcer")
	io, ic2 := -1, -1
	if ip >= 0 {
		io, ic2 = strings.Index(txt[ip:], "Owner network"), strings.Index(txt[ip:], "agentOS claim code: "+code)
	}
	if ie < 0 || in < 0 || ip < 0 || io < 0 || ic2 < 0 || !(ie < in && in < ip && io < ic2) {
		t.Fatalf("sticker.txt order wrong: %q", txt)
	}
}
