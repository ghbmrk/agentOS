package card

// REQ: HW-1, REC-4, ONB-7

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// rig is a display with a recording provisioner and journal; gen keeps
// the generated card so a test knows the answers and the values to look
// for (the display never hands them out).
type rig struct {
	d    *Display
	gen  *Card // a copy taken at generation, never erased
	mu   sync.Mutex
	got  []*Card
	fail error
	log  []string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	x := &rig{}
	d, err := NewDisplay(DisplayConfig{
		Generate: func(r io.Reader) (*Card, error) {
			c, err := Generate(r)
			if err == nil {
				cp := *c
				cp.GridSeed = bytes.Clone(c.GridSeed)
				x.gen = &cp
			}
			return c, err
		},
		Provision: func(c *Card) error {
			x.mu.Lock()
			defer x.mu.Unlock()
			if x.fail != nil {
				return x.fail
			}
			cp := *c
			cp.GridSeed = bytes.Clone(c.GridSeed)
			x.got = append(x.got, &cp)
			return nil
		},
		Journal: func(e string) { x.log = append(x.log, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	x.d = d
	return x
}

// answers are the word and group the display asks for, from the saved card.
func (x *rig) answers() (string, string) {
	w, g := x.d.Asks()
	return strings.Fields(x.gen.VaultPassphrase)[w-1], strings.Split(x.gen.RecoveryKey, "-")[g-1]
}

// secrets are the card's printed and stored secret values.
func secrets(c *Card) map[string]string {
	return map[string]string{"wifi": c.WiFiPassword, "setup secret": c.SetupSecret, "setup code": c.SetupCode,
		"passphrase": c.VaultPassphrase, "recovery key": c.RecoveryKey, "grid seed": fmt.Sprintf("%x", c.GridSeed),
		"grid check": GridCheck(c.GridSeed)}
}

// Acceptance 1 and 2 at the card level: the display stays until a correct
// confirm, provisioning happens only then, and the display copy is erased.
func TestDisplayConfirmThenErase(t *testing.T) {
	x := newRig(t)
	page, err := x.d.Page()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte(x.gen.RecoveryKey)) || !bytes.Contains(page, []byte(x.gen.VaultPassphrase)) {
		t.Fatal("page does not show the card")
	}
	w, g := x.d.Asks()
	if w < 1 || w > PassphraseWords || g < 1 || g > recoveryGroups {
		t.Fatalf("asks word %d group %d", w, g)
	}
	if want := fmt.Sprintf("Type word %d of your vault passphrase and group %d of your recovery key.", w, g); x.d.Prompt() != want {
		t.Fatalf("prompt %q", x.d.Prompt())
	}

	word, grp := x.answers()
	other := "zzzzz"
	for _, bad := range [][2]string{{"", ""}, {word, ""}, {"", grp}, {other, grp}, {word, "AAAAA"}, {grp, word}} {
		if err := x.d.Confirm(bad[0], bad[1]); !errors.Is(err, ErrNotConfirmed) {
			t.Fatalf("confirm %q: %v", bad, err)
		}
	}
	if len(x.got) != 0 || x.d.Confirmed() {
		t.Fatal("provisioned before a correct confirm")
	}
	if _, err := x.d.Page(); err != nil {
		t.Fatalf("display gone after wrong answers: %v", err)
	}

	// Case, spaces and dashes are forgiven, as on paper.
	if err := x.d.Confirm("  "+strings.ToUpper(word)+" ", strings.ToLower(grp[:2])+" "+grp[2:]); err != nil {
		t.Fatal(err)
	}
	if !x.d.Confirmed() || len(x.got) != 1 {
		t.Fatalf("confirmed %v, provisioned %d times", x.d.Confirmed(), len(x.got))
	}
	for name, v := range secrets(x.gen) {
		got := secrets(x.got[0])[name]
		if got != v {
			t.Fatalf("provisioned %s differs from the card shown", name)
		}
	}
	if _, err := x.d.Page(); !errors.Is(err, ErrDisplayGone) {
		t.Fatalf("page after confirm: %v", err)
	}
	if err := x.d.Confirm(word, grp); !errors.Is(err, ErrDisplayGone) {
		t.Fatalf("confirm after erase: %v", err)
	}
	if len(x.got) != 1 {
		t.Fatal("provisioned twice")
	}
	// Nothing the display still holds reaches a formatter.
	for _, s := range []string{fmt.Sprintf("%v %+v %#v %s", x.d, x.d, x.d, x.d)} {
		for name, v := range secrets(x.gen) {
			if strings.Contains(s, v) {
				t.Fatalf("display formats its %s", name)
			}
		}
	}
	if len(x.log) == 0 {
		t.Fatal("no journal events")
	}
	for _, e := range x.log {
		for name, v := range secrets(x.gen) {
			if strings.Contains(e, v) {
				t.Fatalf("journal event carries the %s", name)
			}
		}
	}
}

// The card held in memory is wiped on erase: its byte values are zeroed
// and the display drops its strings.
func TestDisplayEraseWipesMemory(t *testing.T) {
	x := newRig(t)
	seed, sheet := x.d.c.GridSeed, x.d.sheet
	word, grp := x.answers()
	if err := x.d.Confirm(word, grp); err != nil {
		t.Fatal(err)
	}
	if x.d.c != nil || x.d.sheet != nil {
		t.Fatal("display still references the card")
	}
	if !bytes.Equal(seed, make([]byte, len(seed))) {
		t.Fatal("grid seed not zeroed")
	}
	if !bytes.Equal(sheet, make([]byte, len(sheet))) {
		t.Fatal("rendered sheet not zeroed")
	}
}

// A failed provision keeps the display (acceptance 2: the box does not
// finish setup without the card in the owner's hands and in the vault).
func TestDisplayProvisionFailureKeepsDisplay(t *testing.T) {
	x := newRig(t)
	x.fail = errors.New("vault busy")
	word, grp := x.answers()
	if err := x.d.Confirm(word, grp); err == nil || errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("confirm with a failing provision: %v", err)
	}
	if x.d.Confirmed() {
		t.Fatal("confirmed although provisioning failed")
	}
	if _, err := x.d.Page(); err != nil {
		t.Fatalf("display gone after a failed provision: %v", err)
	}
	x.fail = nil
	if err := x.d.Confirm(word, grp); err != nil || !x.d.Confirmed() {
		t.Fatalf("retry: %v", err)
	}
}

// Acceptance 3 at the card level, and REC-4: each display (a first boot
// or a full rotation) makes its own card from the box's randomness; no
// value repeats.
func TestDisplayFreshCards(t *testing.T) {
	a, b := newRig(t), newRig(t)
	sa, sb := secrets(a.gen), secrets(b.gen)
	for name := range sa {
		if sa[name] == sb[name] {
			t.Fatalf("two displays share the %s", name)
		}
	}
	if a.gen.WiFiName == b.gen.WiFiName {
		t.Fatal("two displays share the Wi-Fi name")
	}
}

func TestNewDisplayNeedsProvision(t *testing.T) {
	if _, err := NewDisplay(DisplayConfig{}); err == nil {
		t.Fatal("display without a provisioner")
	}
	// A generator returning an invalid card is refused, not shown.
	_, err := NewDisplay(DisplayConfig{Provision: func(*Card) error { return nil },
		Generate: func(io.Reader) (*Card, error) { return &Card{}, nil }})
	if err == nil {
		t.Fatal("invalid card shown")
	}
}

func paired(r *http.Request) bool { return r.Header.Get("X-Test-Paired") == "yes" }

func do(t *testing.T, h http.Handler, method, target string, form url.Values, isPaired bool, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	r.Host = "10.42.0.1"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if isPaired {
		r.Header.Set("X-Test-Paired", "yes")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The page goes only to the paired phone, is never cached, offers print
// before save, warns against photos, and asks for the confirm (ONB-7: the
// card is the manual, so the page carries no other instructions).
func TestDisplayHandler(t *testing.T) {
	x := newRig(t)
	h := x.d.Handler(paired, "/setup")

	if w := do(t, h, "GET", "/card", nil, false, nil); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), x.gen.RecoveryKey) {
		t.Fatalf("unpaired GET: %d", w.Code)
	}
	w := do(t, h, "GET", "/card", nil, true, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control %q", cc)
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing referrer or frame headers")
	}
	body := w.Body.String()
	pr, sv := strings.Index(body, "window.print()"), strings.Index(body, "?save=1")
	if pr < 0 || sv < 0 || pr > sv {
		t.Fatal("print not offered before save")
	}
	for _, want := range []string{"screenshot", x.d.Prompt(), `name="word"`, `name="group"`, "@media print", x.gen.RecoveryKey} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q", want)
		}
	}
	if strings.Index(body, "<body>") > strings.Index(body, `class="noprint"`) {
		t.Fatal("controls not inside the body")
	}

	w = do(t, h, "GET", "/card?save=1", nil, true, nil)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") ||
		!strings.Contains(w.Body.String(), x.gen.VaultPassphrase) || strings.Contains(w.Body.String(), "noprint") {
		t.Fatalf("save: %d %q", w.Code, w.Header().Get("Content-Disposition"))
	}

	word, grp := x.answers()
	right := url.Values{"word": {word}, "group": {grp}}
	if w := do(t, h, "POST", "/card", right, false, nil); w.Code != http.StatusForbidden || x.d.Confirmed() {
		t.Fatalf("unpaired POST: %d", w.Code)
	}
	if w := do(t, h, "POST", "/card", right, true, map[string]string{"Origin": "http://evil.example"}); w.Code != http.StatusForbidden || x.d.Confirmed() {
		t.Fatalf("cross-origin POST: %d", w.Code)
	}
	w = do(t, h, "POST", "/card", url.Values{"word": {"xqzxqzx"}, "group": {grp}}, true, nil)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "did not match") || x.d.Confirmed() {
		t.Fatalf("wrong POST: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "xqzxqzx") {
		t.Fatal("page echoes the typed answer")
	}
	w = do(t, h, "POST", "/card", right, true, map[string]string{"Origin": "http://10.42.0.1"})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" || !x.d.Confirmed() {
		t.Fatalf("right POST: %d %q", w.Code, w.Header().Get("Location"))
	}
	for _, target := range []string{"/card", "/card?save=1"} {
		w = do(t, h, "GET", target, nil, true, nil)
		if w.Code != http.StatusGone || strings.Contains(w.Body.String(), x.gen.RecoveryKey) {
			t.Fatalf("GET %s after confirm: %d", target, w.Code)
		}
		if !strings.Contains(w.Body.String(), "no copy") {
			t.Fatalf("gone page: %q", w.Body.String())
		}
	}
	if w := do(t, h, "PUT", "/card", nil, true, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: %d", w.Code)
	}
}

// Card values never reach a formatter (a stray log line).
func TestCardFormatsRedacted(t *testing.T) {
	x := newRig(t)
	c := *x.gen
	s := fmt.Sprintf("%v %+v %#v %s", c, &c, &c, &c)
	for name, v := range secrets(x.gen) {
		if strings.Contains(s, v) {
			t.Fatalf("card formats its %s", name)
		}
	}
}

// #1185: at the confirm the box's Wi-Fi switches to the card's, so the
// first card's page tells the phone to rejoin with the card's Wi-Fi QR
// code before it confirms. A rotation's page does not: the switch is the
// first card's only.
func TestTheCardPageSaysToRejoinWithTheCardsWiFi(t *testing.T) {
	const rejoin = "join that Wi-Fi with your card's Wi-Fi QR code"
	x := newRig(t)
	body := do(t, x.d.Handler(paired, "/setup"), "GET", "/card", nil, true, nil).Body.String()
	at, confirm := strings.Index(body, rejoin), strings.Index(body, `type="submit">Confirm`)
	if at < 0 || confirm < 0 || at > confirm {
		t.Fatalf("the rejoin text is missing or after the confirm (%d, %d)", at, confirm)
	}
	y := newRotRig(t, Parts{WiFi: true})
	if body := do(t, y.d.Handler(paired, "/home"), "GET", "/rotate/card", nil, true, nil).Body.String(); strings.Contains(body, rejoin) {
		t.Fatal("a rotation's page tells the phone to rejoin")
	}
}

// #1526 U-1: a Wi-Fi rotation's page says to rejoin and reload this page,
// which re-requests the done page; Home does not offer that page again.
func TestTheWiFiRotationPageSaysToReload(t *testing.T) {
	y := newRotRig(t, Parts{WiFi: true})
	body := do(t, y.d.Handler(paired, "/rotate/done"), "GET", "/rotate/card", nil, true, nil).Body.String()
	const want = "Your phone drops off it: rejoin with this card's Wi-Fi QR code, or its name and password, then reload this page."
	if !strings.Contains(body, want) || strings.Contains(body, "open my box page again") {
		t.Fatalf("rotation rejoin text: %s", body)
	}
}
