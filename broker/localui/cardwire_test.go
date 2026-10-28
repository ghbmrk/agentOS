package localui

// REQ: HW-1, ONB-7

import (
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/owner"
)

// cardRig is a setup page with the first-boot Owner Card step (CTRL-card-wire).
type cardRig struct {
	*rig
	step  *firstboot.CardStep
	shown *card.Card // the test's copy of the generated card
	made  int        // provisions
}

func newCardRig(t *testing.T) *cardRig {
	t.Helper()
	cr := &cardRig{rig: newRig(t)}
	var err error
	cr.step, err = firstboot.NewCardStep(&change.MemStore{}, card.DisplayConfig{Authority: testAuthority(),
		Generate: func(rd io.Reader) (*card.Card, error) {
			c, err := card.Generate(rd)
			if err == nil {
				cp := *c
				cr.shown = &cp
			}
			return c, err
		},
		Provision: func(*card.Card) error { cr.made++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	cr.owned = cr.step
	cr.srv = cr.open(&MemStore{})
	return cr
}

// toCard pairs this phone and enrolls approval codes.
func (cr *cardRig) toCard() {
	cr.t.Helper()
	m := secretRe.FindStringSubmatch(cr.toCodes())
	seed, err := b32.DecodeString(m[1])
	if err != nil {
		cr.t.Fatal(err)
	}
	cr.post("/setup/codes", url.Values{"code": {owner.TOTP(seed, cr.clock())}})
}

func (cr *cardRig) answers() (string, string) {
	w, g := cr.step.Display().Asks()
	return strings.Fields(cr.shown.VaultPassphrase)[w-1], strings.Split(cr.shown.RecoveryKey, "-")[g-1]
}

// cardText reports whether body holds any of the card's secrets.
func (cr *cardRig) cardText(body string) bool {
	c := cr.shown
	for _, v := range []string{c.VaultPassphrase, c.RecoveryKey, c.SetupSecret, c.SetupCode} {
		if strings.Contains(body, v) {
			return true
		}
	}
	return false
}

// Brief test 1 (cond 1): the card is served by the setup page's own server,
// behind its Host check: another host name is redirected (GET) or refused
// (POST), never shown the card. The paired phone sees it.
func TestTheCardRoutesSitBehindTheHostCheck(t *testing.T) {
	cr := newCardRig(t)
	cr.toCard()
	for _, method := range []string{"GET", "POST"} {
		for _, path := range []string{"/setup/card", "/setup/card?save=1"} {
			var form url.Values
			if method == "POST" {
				w, g := cr.answers()
				form = url.Values{"word": {w}, "group": {g}}
			}
			rec := cr.do(method, path, form, func(r *http.Request) {
				r.Host = "box.attacker.example"
				r.Header.Set("Origin", "http://box.attacker.example")
			})
			if rec.Code != http.StatusMisdirectedRequest || cr.cardText(rec.Body.String()) {
				t.Fatalf("%s %s from another host: %d %q", method, path, rec.Code, rec.Body.String())
			}
		}
	}
	if cr.made != 0 || cr.step.Hold() == nil {
		t.Fatal("a foreign host's post confirmed the card")
	}
	page := cr.get("/setup/card")
	if !strings.Contains(page, cr.shown.VaultPassphrase) {
		t.Fatal("the paired phone was not shown its card")
	}
}

// Cond 1: only the phone that paired sees the card; another phone on the
// Wi-Fi, or this one before pairing, is refused with no card text.
func TestTheCardIsShownOnlyToThePairedPhone(t *testing.T) {
	cr := newCardRig(t)
	cr.get("/setup") // a setup cookie, but not paired yet
	if rec := cr.do("GET", "/setup/card", nil); rec.Code == http.StatusOK || cr.cardText(rec.Body.String()) {
		t.Fatalf("before pairing: %d", rec.Code)
	}
	cr.toCard()
	cr.asOther(func() {
		cr.get("/setup")
		for _, method := range []string{"GET", "POST"} {
			var form url.Values
			if method == "POST" {
				w, g := cr.answers()
				form = url.Values{"word": {w}, "group": {g}}
			}
			if rec := cr.do(method, "/setup/card", form); rec.Code != http.StatusForbidden || cr.cardText(rec.Body.String()) {
				t.Fatalf("other phone %s: %d", method, rec.Code)
			}
		}
	})
	if cr.made != 0 {
		t.Fatal("another phone confirmed the card")
	}
}

// HW-1, ONB-7, §8.1 step 5: the card step follows approval codes; setup
// does not move on to the recovery sheet or finish until the card is
// confirmed, and the confirm returns the phone to setup.
func TestSetupWaitsForTheCard(t *testing.T) {
	cr := newCardRig(t)
	cr.toCard()
	if page := cr.get("/setup"); !strings.Contains(page, "Owner Card") || !strings.Contains(page, `href="/setup/card"`) {
		t.Fatalf("no card step after codes: %s", page)
	}
	cr.post("/setup/recovery", url.Values{"stored": {"1"}})
	if !strings.Contains(cr.setupErr(), "Owner Card") {
		t.Fatal("recovery step passed before the card")
	}
	w, g := cr.answers()
	rec := cr.do("POST", "/setup/card", url.Values{"word": {w}, "group": {g}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("confirm: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if cr.step.Hold() != nil || cr.made != 1 {
		t.Fatalf("hold %v, provisions %d", cr.step.Hold(), cr.made)
	}
	if page := cr.get("/setup"); !strings.Contains(page, "Recovery sheet") {
		t.Fatalf("after the confirm: %s", page)
	}
	if rec := cr.do("GET", "/setup/card", nil); rec.Code == http.StatusOK || cr.cardText(rec.Body.String()) {
		t.Fatalf("card shown after the confirm: %d", rec.Code)
	}
}

// heldCard is a card step that is never confirmed and shows nothing, as
// after a lost latch: finish must still wait for it.
type heldCard struct{}

func (heldCard) Display() *card.Display { return nil }
func (heldCard) Hold() error            { return firstboot.ErrCardPending }

// The finish path calls Hold first: setup with every other step done does
// not finish while the card is held.
func TestFinishWaitsForTheCard(t *testing.T) {
	r := newRig(t)
	r.owned = heldCard{}
	st := &MemStore{s: SetupState{Owner: ownerNum, Device: "x", Codes: true, Recovery: true, Host: true}}
	r.srv = r.open(st)
	r.hooks.connected = true
	r.srv.setup.maybeFinish()
	if r.hooks.finishes != 0 || r.srv.setup.done() {
		t.Fatal("setup finished with the card held")
	}
	if !errors.Is(r.srv.cfg.Card.Hold(), firstboot.ErrCardPending) {
		t.Fatal("hold")
	}
}

// REQ: HW-1
//
// No authority, no card (F19): the card step with no page authority holds
// setup at the card step, and the page says why in the fixed line instead
// of a card; the card route shows nothing, and setup's recovery step still
// refuses.
func TestTheCardStepWithoutAuthoritySaysWhy(t *testing.T) {
	cr := &cardRig{rig: newRig(t)}
	var err error
	cr.step, err = firstboot.NewCardStep(&change.MemStore{}, card.DisplayConfig{Provision: func(*card.Card) error { cr.made++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	cr.owned = cr.step
	cr.srv = cr.open(&MemStore{})
	cr.toCard()
	if p := html.UnescapeString(cr.get("/setup")); !strings.Contains(p, firstboot.ErrNoAuthority.Error()) || !strings.Contains(p, "Owner Card") {
		t.Fatalf("the card step does not say why:\n%s", p)
	}
	if w := cr.do("GET", "/setup/card", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("the card route without a card: %d", w.Code)
	}
	cr.post("/setup/recovery", url.Values{"stored": {"1"}})
	if cr.made != 0 || cr.step.Hold() == nil {
		t.Fatal("setup passed the card step without a card")
	}
}
