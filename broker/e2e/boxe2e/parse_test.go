package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/owner"
)

// The driver reads the Owner Card the way an owner does: the saved sheet
// for the values, the display page for which word and group to type. A
// real display accepts what it reads, and provisions.
func TestCardSheetAndPromptConfirmARealDisplay(t *testing.T) {
	provisioned := 0
	d, err := card.NewDisplay(card.DisplayConfig{Provision: func(*card.Card) error { provisioned++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	h := d.Handler(func(*http.Request) bool { return true }, "/setup")
	get := func(target string) []byte {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 200 {
			t.Fatalf("GET %s: %d", target, w.Code)
		}
		return w.Body.Bytes()
	}
	pass, rec, err := sheetSecrets(get("/setup/card?save=1"))
	if err != nil {
		t.Fatal(err)
	}
	word, group, err := promptAsks(get("/setup/card"))
	if err != nil {
		t.Fatal(err)
	}
	w, g, err := answers(pass, rec, word, group)
	if err != nil {
		t.Fatal(err)
	}
	// A wrong answer is refused, so the parser is not trivially right.
	post := func(w, g string) int {
		req := httptest.NewRequest("POST", "/setup/card", strings.NewReader(url.Values{"word": {w}, "group": {g}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := post(w, "ZZZZ"); code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong group: %d", code)
	}
	if code := post(w, g); code != http.StatusSeeOther || provisioned != 1 {
		t.Fatalf("confirm: %d, provisioned %d", code, provisioned)
	}
}

func TestSheetSecretsParsesByHeading(t *testing.T) {
	// The Setup code's mono big span comes first on the sheet; the
	// parser must take the values under their own headings.
	sheet := []byte(`<h2>Setup code</h2><p><span class="mono big">SETUP-CANARY</span></p>
<h2>Vault passphrase</h2><div><p class="mono big">alpha bravo&#39;s charlie</p></div>
<h1>Recovery key</h1><p class="note">x</p><p class="mono big">AAAA-BBBB-CCCC</p>`)
	pass, rec, err := sheetSecrets(sheet)
	if err != nil || pass != "alpha bravo's charlie" || rec != "AAAA-BBBB-CCCC" {
		t.Fatalf("%q %q %v", pass, rec, err)
	}
	if _, _, err := sheetSecrets([]byte(`<h2>Vault passphrase</h2>`)); err == nil {
		t.Fatal("a sheet with no values parsed")
	}
	w, g, err := answers(pass, rec, 2, 3)
	if err != nil || w != "bravo's" || g != "CCCC" {
		t.Fatalf("%q %q %v", w, g, err)
	}
	if _, _, err := answers(pass, rec, 4, 1); err == nil {
		t.Fatal("a word past the passphrase was answered")
	}
}

func TestPromptAsks(t *testing.T) {
	w, g, err := promptAsks([]byte(`<p>Type word 3 of your vault passphrase and group 7 of your recovery key.</p>`))
	if err != nil || w != 3 || g != 7 {
		t.Fatalf("%d %d %v", w, g, err)
	}
	if _, _, err := promptAsks([]byte(`<p>Type group 7 of your new recovery key.</p>`)); err == nil {
		t.Fatal("a rotation prompt parsed as first boot")
	}
}

func TestSMSLinkAndOTPSeed(t *testing.T) {
	page := []byte(`<a class="button" href="sms:&#43;15550000100?&amp;body=PAIR%20ABCD2345">Text</a>`)
	num, code, ok := smsLink(page)
	if !ok || num != "+15550000100" || code != "ABCD2345" {
		t.Fatalf("%q %q %v", num, code, ok)
	}
	seed := []byte("synthetic-seed-canary")
	enc := strings.TrimRight(base32Std(seed), "=")
	got, err := otpSeed([]byte(`<a class="button" href="otpauth://totp/AgentOS:AgentOS?secret=` + enc + `&amp;issuer=AgentOS">`))
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("%q %v", got, err)
	}
	if owner.TOTP(got, time.Unix(0, 0)) != owner.TOTP(seed, time.Unix(0, 0)) {
		t.Fatal("seed round trip")
	}
	if _, err := otpSeed([]byte(`<p>no link</p>`)); err == nil {
		t.Fatal("no link parsed")
	}
	if _, _, ok := smsLink([]byte(`<h2>1. Home network</h2>`)); ok {
		t.Fatal("no link parsed")
	}
}

// Details on the console carry headings only, never a value from a page.
func TestHeadingIsSanitized(t *testing.T) {
	for page, want := range map[string]string{
		`<h1>Set up AgentOS</h1><h2>1. Home network</h2><p class="mono">SECRET</p>`: `"1. Home network"`,
		`<h1>Claim <b>AgentOS</b></h1>`:                                             `"Claim AgentOS"`,
		`<h1>Bad <script>&lt;x&gt;</script></h1>`:                                   `"Bad x"`,
		`plain`: `"(no heading)"`,
	} {
		if got := heading([]byte(page)); got != want {
			t.Errorf("%s: %s, want %s", page, got, want)
		}
	}
}

func TestLineState(t *testing.T) {
	for page, want := range map[string]string{
		`<h2>2. Text your box</h2><p>Pairing is not available yet: I cannot send texts right now. Reload this page to try again.</p>`: "cannot-text",
		`<h2>2. Text your box</h2><p>I do not know my own number yet, so you cannot text me first.</p>`:                               "number-unknown",
		`<h2>2. Text your box</h2><p><a class="button" href="sms:+15550000100?&amp;body=PAIR%20123456">Text my box</a></p>`:           "link",
		`<h2>1. Home network</h2>`: "other",
	} {
		if got := lineState([]byte(page)); got != want {
			t.Errorf("lineState(%q) = %q, want %q", page, got, want)
		}
	}
}

// The step-7 parsers match localui's own template, so a wording change
// there fails here rather than in the image run.
func TestDeviceOfferAndLinkMatchThePage(t *testing.T) {
	src, err := os.ReadFile("../../localui/pages.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, frag := range []string{
		aiOpen,
		`<form method="post" action="/setup/ai-device"><input type="hidden" name="provider" value="{{.ID}}">`,
		`<p>Open <a href="{{index $d 0}}">{{index $d 0}}</a> and enter <span class="mono">{{index $d 1}}</span>.</p>`,
	} {
		if !bytes.Contains(src, []byte(frag)) {
			t.Errorf("localui's step 7 no longer has %q", frag)
		}
	}
	page := []byte(`<form method="post" action="/setup/ai-device"><input type="hidden" name="provider" value="codex"><button>`)
	if !deviceOffer(page, "codex") || deviceOffer(page, "cod") || deviceOffer([]byte(`<h2>7. Connect AI</h2>`), "codex") {
		t.Fatal("deviceOffer")
	}
	link, code, ok := deviceLink([]byte(`<p>Open <a href="https://auth.openai.com/codex/device?a=1&amp;b=2">x</a> and enter <span class="mono">ABCD-EF23</span>.</p>`))
	if !ok || link != "https://auth.openai.com/codex/device?a=1&b=2" || code != "ABCD-EF23" {
		t.Fatalf("%q %q %v", link, code, ok)
	}
	if _, _, ok := deviceLink(page); ok {
		t.Fatal("link parsed from the offer")
	}
}
