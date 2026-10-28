package localui

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: REC-4, HW-1

// rotRig is a set-up box with a card rotation waiting on its page: a
// rotation display whose provisioner records the commit, as agentosd's
// rotation does.
type rotRig struct {
	*rig
	mu   sync.Mutex
	d    *card.Display
	gen  *card.Card
	made []string // committed recovery keys
}

func (x *rotRig) Display() *card.Display { x.mu.Lock(); defer x.mu.Unlock(); return x.d }

func newRotPageRig(t *testing.T, signIn bool) *rotRig {
	t.Helper()
	x := &rotRig{rig: newRig(t)}
	d, err := card.NewDisplay(card.DisplayConfig{Authority: testAuthority(),
		Rotate: &card.Parts{Recovery: true},
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if err == nil {
				cp := *c
				x.gen = &cp
			}
			return c, err
		},
		Provision: func(c *card.Card) error {
			x.mu.Lock()
			defer x.mu.Unlock()
			x.made = append(x.made, c.RecoveryKey)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	x.d = d
	x.rot = x
	x.srv = x.open(&MemStore{})
	x.runSetup()
	x.startChannel(modem.NewCarrier().Line(boxNum))
	if signIn {
		x.signIn()
	}
	return x
}

func (x *rotRig) group(right bool) url.Values {
	_, g := x.d.Asks()
	v := strings.Split(x.gen.RecoveryKey, "-")[g-1]
	if !right {
		v = strings.Repeat("A", len(v))
		if v == strings.Split(x.gen.RecoveryKey, "-")[g-1] {
			v = strings.Repeat("B", len(v))
		}
	}
	return url.Values{"group": {v}}
}

func (x *rotRig) madeN() int { x.mu.Lock(); defer x.mu.Unlock(); return len(x.made) }

// The rotation's new key is shown only to a signed-in phone on the box's
// own host; a post from elsewhere commits nothing.
func TestTheRotationPageNeedsSignInAndTheBoxsOwnOrigin(t *testing.T) {
	x := newRotPageRig(t, false)
	for _, m := range []string{"GET", "POST"} {
		w := x.do(m, "/rotate/card", x.group(true))
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") ||
			strings.Contains(w.Body.String(), x.gen.RecoveryKey) {
			t.Fatalf("%s without sign-in: %d %s", m, w.Code, w.Header().Get("Location"))
		}
	}
	x.signIn()
	w := x.do("POST", "/rotate/card", x.group(true), func(r *http.Request) {
		r.Header.Set("Origin", "http://attacker.example")
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin post: %d", w.Code)
	}
	w = x.do("GET", "/rotate/card", nil, func(r *http.Request) { r.Host = "box.attacker.example" })
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), x.gen.RecoveryKey) {
		t.Fatalf("another host name: %d", w.Code)
	}
	if x.madeN() != 0 {
		t.Fatal("a refused request committed the rotation")
	}
	if !strings.Contains(x.get("/rotate/card"), x.gen.RecoveryKey) {
		t.Fatal("the signed-in phone is not shown the new key")
	}
}

// A wrong confirm keeps the page; the right one commits once and erases
// it, and the phone goes home.
func TestTheRotationPageConfirmsThenErases(t *testing.T) {
	x := newRotPageRig(t, true)
	page := x.get("/rotate/card")
	if !strings.Contains(page, x.gen.RecoveryKey) || !strings.Contains(page, "Cancel: keep my current card") {
		t.Fatal("rotation page without the new key or the cancel")
	}
	if w := x.post("/rotate/card", x.group(false)); w.Code != http.StatusUnprocessableEntity || x.madeN() != 0 {
		t.Fatalf("wrong confirm: %d, %d commits", w.Code, x.madeN())
	}
	if !strings.Contains(x.get("/rotate/card"), x.gen.RecoveryKey) {
		t.Fatal("a wrong confirm erased the page")
	}
	w := x.post("/rotate/card", x.group(true))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/home" {
		t.Fatalf("confirm: %d %s", w.Code, w.Header().Get("Location"))
	}
	if x.madeN() != 1 || x.made[0] != x.gen.RecoveryKey {
		t.Fatal("the confirm did not commit the shown key once")
	}
	w = x.do("GET", "/rotate/card", nil)
	if strings.Contains(w.Body.String(), x.gen.RecoveryKey) || strings.Contains(w.Body.String(), card.Normalize(x.gen.RecoveryKey)) {
		t.Fatal("key text after the confirm")
	}
	if _, err := x.d.Page(); err == nil {
		t.Fatal("display copy kept after the confirm")
	}
	if w := x.post("/rotate/card", x.group(true)); x.madeN() != 1 || bytes.Contains(w.Body.Bytes(), []byte(x.gen.RecoveryKey)) {
		t.Fatal("a second confirm committed again")
	}
}

// Cancel erases the page with nothing committed; with no rotation
// waiting the page sends the phone home.
func TestTheRotationPageCancelsAndIdles(t *testing.T) {
	x := newRotPageRig(t, true)
	w := x.post("/rotate/card", url.Values{"cancel": {"1"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/home" || x.madeN() != 0 {
		t.Fatalf("cancel: %d %s, %d commits", w.Code, w.Header().Get("Location"), x.madeN())
	}
	if _, err := x.d.Page(); err == nil {
		t.Fatal("display copy kept after cancel")
	}
	x.mu.Lock()
	x.d = nil
	x.mu.Unlock()
	if w := x.do("GET", "/rotate/card", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/home" {
		t.Fatalf("no rotation waiting: %d %s", w.Code, w.Header().Get("Location"))
	}
}
