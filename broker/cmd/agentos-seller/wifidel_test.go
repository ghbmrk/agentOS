package main

import (
	"os"
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
