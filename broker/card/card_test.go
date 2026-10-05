package card

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: ONB-7, ONB-1, CH-4, CRED-8, CH-7

// detRand is a deterministic source for tests only.
func detRand(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

func mustGen(t *testing.T, seed int64) *Card {
	t.Helper()
	c, err := Generate(detRand(seed))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWordlistIsEFFLarge(t *testing.T) {
	// SHA-256 of eff_large_wordlist.txt as EFF publishes it.
	sum := sha256.Sum256(effLarge)
	if got := hex.EncodeToString(sum[:]); got != "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e" {
		t.Fatalf("wordlist hash %s", got)
	}
	if len(words) != 7776 || words[0] != "abacus" || words[7775] != "zoom" {
		t.Fatalf("wordlist parse: %d words", len(words))
	}
}

// §3.1 and CRED-8: each card secret has at least the entropy the spec
// names, and two cards share nothing.
func TestGenerateStrengthAndUniqueness(t *testing.T) {
	a, b := mustGen(t, 1), mustGen(t, 2)
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	ws := strings.Fields(a.VaultPassphrase)
	if len(ws) != PassphraseWords || float64(len(ws))*math.Log2(7776) < 80 {
		t.Fatalf("passphrase %d words", len(ws))
	}
	for _, w := range ws {
		if !inList(w) {
			t.Fatalf("word %q not from the list", w)
		}
	}
	bits := func(s string) float64 { return float64(len(strings.ReplaceAll(s, "-", ""))) * 5 }
	if bits(a.WiFiPassword) < 80 || bits(a.SetupSecret) < 128 || bits(a.RecoveryKey)*32/40 < 160 || len(a.GridSeed) < 32 {
		t.Fatalf("weak secret: %+v", a)
	}
	if len(a.WiFiPassword) < 8 || len(a.WiFiPassword) > 63 {
		t.Fatalf("Wi-Fi password length %d outside WPA's 8-63", len(a.WiFiPassword))
	}
	for _, p := range [][2]string{{a.WiFiPassword, b.WiFiPassword}, {a.SetupSecret, b.SetupSecret},
		{a.VaultPassphrase, b.VaultPassphrase}, {a.RecoveryKey, b.RecoveryKey}, {a.WiFiName, b.WiFiName}} {
		if p[0] == p[1] {
			t.Fatalf("two cards share %q", p[0])
		}
	}
	if bytes.Equal(a.GridSeed, b.GridSeed) {
		t.Fatal("two cards share a grid seed")
	}
}

// The setup code is derived from the setup secret, and from nothing else:
// in particular the vault passphrase cannot be learned from it (CRED-8).
func TestSetupCodeIsDerivedFromTheSecretOnly(t *testing.T) {
	a := mustGen(t, 3)
	b := *a
	b.VaultPassphrase = "other words entirely here for this test"
	if SetupCodeFor(a.SetupSecret) != a.SetupCode || SetupCodeFor(b.SetupSecret) != a.SetupCode {
		t.Fatal("setup code not a function of the setup secret")
	}
	if !regexp.MustCompile(`^[A-Z2-9]{4}-[A-Z2-9]{4}$`).MatchString(a.SetupCode) {
		t.Fatalf("setup code shape %q", a.SetupCode)
	}
	if !CheckSetupCode(a.SetupSecret, strings.ToLower(strings.ReplaceAll(a.SetupCode, "-", " "))) {
		t.Fatal("typed setup code with case and separator changes refused")
	}
	if CheckSetupCode(a.SetupSecret, "AAAA-AAAA") {
		t.Fatal("wrong setup code accepted")
	}
}

// The recovery key prints in broker/recovery's format (P2-8): 40 symbols,
// eight groups of four plus a GF(32) check symbol. The vectors were made
// with recovery.RecoveryKey.Text and recovery.GridCheck, so the card and
// the vault agree.
func TestRecoveryKeyAndGridCheckMatchRecovery(t *testing.T) {
	var b [recoveryKeyBytes]byte
	for i := range b {
		b[i] = byte(i*37 + 11)
	}
	if got := RecoveryKeyText(b); got != "BN2FV-L8W9W-2VWSR-6N429-RYTNQ-R5ATA-G3P23-BKQLP" {
		t.Fatalf("recovery key text %s", got)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	if got := GridCheck(seed); got != "THJA" {
		t.Fatalf("grid check %s", got)
	}
	c := mustGen(t, 5)
	if !regexp.MustCompile(`^([A-Z2-9]{5}-){7}[A-Z2-9]{5}$`).MatchString(c.RecoveryKey) {
		t.Fatalf("recovery key shape %q", c.RecoveryKey)
	}
	// One mistyped symbol fails its group's check, wherever it is: a key
	// symbol of the first or last group, or a check symbol.
	key := c.RecoveryKey
	for _, i := range []int{0, 37, 4, 22} {
		bad := []byte(key)
		if bad[i] == 'A' {
			bad[i] = 'B'
		} else {
			bad[i] = 'A'
		}
		c.RecoveryKey = string(bad)
		if c.Validate() == nil {
			t.Fatalf("mistyped recovery key accepted (symbol %d)", i)
		}
	}
	page, err := HTML(mustGen(t, 6))
	if err != nil || !strings.Contains(string(page), "Grid check code: <span class=\"mono\">"+GridCheck(mustGen(t, 6).GridSeed)) {
		t.Fatalf("grid check not printed under the grid: %v", err)
	}
}

func TestWiFiQRPayloadEscapes(t *testing.T) {
	got := WiFiQR(`My;Box`, `pa:ss\word,"x"`)
	want := `WIFI:T:WPA;S:My\;Box;P:pa\:ss\\word\,\"x\";;`
	if got != want {
		t.Fatalf("got %s", got)
	}
}

// ONB-7: the card is the manual. A quick-start of at most five steps, and a
// "nothing happened" side with the Wi-Fi name, how long to wait, and boot
// keys for major PC brands. ONB-1: the printable page needs nothing but
// itself (no external fetch).
func TestRenderedCardIsTheManual(t *testing.T) {
	c := mustGen(t, 4)
	out, err := HTML(c)
	if err != nil {
		t.Fatal(err)
	}
	page := string(out)
	if n := len(QuickStart); n == 0 || n > 5 {
		t.Fatalf("quick-start has %d steps", n)
	}
	for _, s := range QuickStart {
		if !strings.Contains(page, htmlEsc(s)) {
			t.Fatalf("quick-start step missing: %q", s)
		}
	}
	for _, want := range []string{"Nothing happened?", c.WiFiName, htmlEsc(c.WiFiPassword), c.SetupCode, c.SetupSecret,
		c.VaultPassphrase, c.RecoveryKey, "Dell", "HP", "Lenovo", "ASUS", "Acer",
		"minutes", "apart from the drive", "<svg", "Box page: <span class=\"mono\">" + BoxPage, "Wi-Fi joined but no page?",
		"apart from the box and from this card", "Reset secret", "tap Copy",
		"The box cannot print this again, so keep this sheet.", "The box cannot print this again; keep the card."} {
		if !strings.Contains(page, want) {
			t.Fatalf("card lacks %q", want)
		}
	}
	// The paper grid: every cell, as owner.GridCell computes it.
	for _, l := range owner.GridLabels() {
		if !strings.Contains(page, owner.GridCell(c.GridSeed, l)) {
			t.Fatalf("grid cell %s missing", l)
		}
	}
	// Three sheets: card, grid, recovery key; the recovery key is printed
	// only on its own sheet.
	sheets := strings.Split(page, `class="sheet`)
	if len(sheets) != 4 {
		t.Fatalf("%d sheets", len(sheets)-1)
	}
	// The setup secret, only for re-running setup after a reset, rides
	// with it, off the card.
	for i, s := range sheets[1:] {
		if strings.Contains(s, c.RecoveryKey) != (i == 2) || strings.Contains(s, c.SetupSecret) != (i == 2) {
			t.Fatalf("recovery key or setup secret placement wrong on sheet %d", i+1)
		}
	}
	assertSelfContained(t, page)
}

var external = regexp.MustCompile(`(?i)(src|href|action)\s*=\s*["']?\s*(https?:)?//|url\(\s*["']?(https?:)?//|@import`)

func assertSelfContained(t *testing.T, page string) {
	t.Helper()
	if m := external.FindString(page); m != "" {
		t.Fatalf("page references something outside itself: %q", m)
	}
	if strings.Contains(page, "<script") {
		t.Fatal("card has a script")
	}
}

func TestQRSVGMatchesTheCode(t *testing.T) {
	svg, err := QRSVG("WIFI:T:WPA;S:x;P:y;;")
	if err != nil {
		t.Fatal(err)
	}
	s := string(svg)
	if !strings.HasPrefix(s, "<svg") || !strings.Contains(s, `shape-rendering="crispEdges"`) {
		t.Fatalf("svg: %.80s", s)
	}
	if _, err := QRSVG(strings.Repeat("x", 4000)); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func inList(w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

func htmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return r.Replace(s)
}
