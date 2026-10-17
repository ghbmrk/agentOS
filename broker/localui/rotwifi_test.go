package localui

// REQ: REC-4, CH-7, CRED-1

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
)

const (
	wifiSwitched = "My Wi-Fi now uses your new card"
	wifiKept     = "My Wi-Fi still uses your old card"
	wifiWarning  = "my Wi-Fi switches to the new password on this card"
	// #1526 U-2, U-3: the drop is expected now, and the way back names
	// the Home entry that rotates.
	wifiDropNow = "Your phone may drop off now"
	wifiRetry   = "again from Replace Owner Card parts on Home"
)

// nets counts the Wi-Fi hand-offs agentosd took; the network itself
// comes from the vault process, never the page (#1522).
func (x *wireRig) nets() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.handOffs
}

// #1191: a committed rotation of the Wi-Fi password hands the new card's
// network to agentosd, which writes it for the access point, and the
// done page says so; the confirm page warned before the switch.
func TestRotationOfTheWiFiPasswordSwitchesTheAccessPoint(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	if p := x.get("/rotate/card"); !strings.Contains(p, wifiWarning) {
		t.Fatal("the confirm page does not warn of the switch")
	}
	if x.nets() != 0 {
		t.Fatal("handed off before the confirm")
	}
	if w := x.post("/rotate/card", x.group()); w.Header().Get("Location") != "/rotate/done" {
		t.Fatalf("confirm: %d %s", w.Code, w.Header().Get("Location"))
	}
	if n := x.nets(); n != 1 {
		t.Fatalf("handed off %d networks", n)
	}
	done := x.get("/rotate/done")
	if !strings.Contains(done, wifiSwitched) || !strings.Contains(done, wifiDropNow) || strings.Contains(done, wifiKept) {
		t.Fatalf("done page: %s", done)
	}
	if strings.Contains(done, x.gen.WiFiPassword) {
		t.Fatal("the done page shows the password")
	}
}

// #1191: when agentosd cannot write the network, the rotation stands (the
// vault process committed it) and the done page says the old password
// still runs the Wi-Fi.
func TestRotationOfTheWiFiPasswordThatCannotSwitchSaysSo(t *testing.T) {
	x := newWireRig(t)
	x.wifiErr = errors.New("synthetic write failure")
	x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	if w := x.post("/rotate/card", x.group()); w.Header().Get("Location") != "/rotate/done" {
		t.Fatalf("confirm: %d %s", w.Code, w.Header().Get("Location"))
	}
	done := x.get("/rotate/done")
	if !strings.Contains(done, wifiKept) || !strings.Contains(done, wifiRetry) || strings.Contains(done, wifiSwitched) {
		t.Fatalf("done page: %s", done)
	}
}

// #1191: a card that may be in effect (409, or no answer from the vault
// process) is the card the owner keeps, so its Wi-Fi password goes on the
// air too: the old password, perhaps on a lost card, must not stay.
func TestRotationHandsOffAWiFiPasswordThatMayBeInEffect(t *testing.T) {
	for name, commitErr := range map[string]error{
		"in effect": &VaultError{Status: http.StatusConflict, Msg: "in effect"},
		"no answer": errors.New("synthetic: no answer"),
	} {
		t.Run(name, func(t *testing.T) {
			x := newWireRig(t)
			x.v.commitErr = commitErr
			x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
			w := x.post("/rotate/card", x.group())
			if n := x.nets(); n != 1 {
				t.Fatalf("handed off %d networks", n)
			}
			// #1614 U-2: the owner learns the Wi-Fi switched and how to
			// rejoin, as after a commit that stood.
			if b := w.Body.String(); w.Code != http.StatusGone || strings.Contains(b, wifiKeptInEffect) || !strings.Contains(b, wifiSwitched) {
				t.Fatalf("in-effect page: %d %s", w.Code, b)
			}
		})
	}
}

// #1523: when a card that may be in effect (409, or no answer) cannot
// switch the Wi-Fi, the owner's page says so after the in-effect text
// (REC-4), and shows no password. The note asks for the Wi-Fi part on the
// next card: after no answer nothing may be owed, so a card started
// without it would leave the old password on the air (#1614 U-1).
func TestAnInEffectRotationThatCannotSwitchTheWiFiSaysSo(t *testing.T) {
	for name, commitErr := range map[string]error{
		"in effect": &VaultError{Status: http.StatusConflict, Msg: "in effect"},
		"no answer": errors.New("synthetic: no answer"),
	} {
		t.Run(name, func(t *testing.T) {
			x := newWireRig(t)
			x.v.commitErr = commitErr
			x.wifiErr = errors.New("synthetic write failure")
			x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
			w := x.post("/rotate/card", x.group())
			b := w.Body.String()
			if w.Code != http.StatusGone || !strings.Contains(b, "already in effect") || !strings.Contains(b, wifiKeptInEffect) {
				t.Fatalf("in-effect page: %d %s", w.Code, b)
			}
			if !strings.Contains(wifiKeptInEffect, "include the Wi-Fi password") {
				t.Fatalf("the note does not ask for the Wi-Fi part: %q", wifiKeptInEffect)
			}
			if strings.Contains(b, x.gen.WiFiPassword) {
				t.Fatal("the page shows the password")
			}
			// A later look at the card page says the same.
			if g := x.do("GET", "/rotate/card", nil); g.Code == http.StatusGone && !strings.Contains(g.Body.String(), wifiKeptInEffect) {
				t.Fatalf("later: %d %s", g.Code, g.Body)
			}
		})
	}
}

// #1524: the hand-off runs after the commit stood, so a phone that hung
// up on its post (a cancelled request) still gets its Wi-Fi switched.
func TestTheWiFiHandOffOutlivesTheConfirmingRequest(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	// agentosd's socket drops a call whose context is done, as a real
	// connection does.
	x.srv.SetOwner(liveOwner{x.srv.getOwner()})
	ctx, cancel := context.WithCancel(context.Background())
	x.v.onCommit = cancel
	x.do("POST", "/rotate/card", x.group(), func(r *http.Request) { *r = *r.WithContext(ctx) })
	if n := x.nets(); n != 1 {
		t.Fatalf("handed off %d networks", n)
	}
}

// #1191: nothing is handed off when the vault process refused the card
// before writing any of it (410, 400), nor for a rotation without the
// Wi-Fi part (whose confirm page has no warning).
func TestRotationHandsOffNoRefusedWiFiPassword(t *testing.T) {
	for name, commitErr := range map[string]error{
		"gone":    &VaultError{Status: http.StatusGone, Msg: "cancelled"},
		"refused": &VaultError{Status: http.StatusBadRequest, Msg: "bad"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newWireRig(t)
			x.v.commitErr = commitErr
			x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
			x.post("/rotate/card", x.group())
			if n := x.nets(); n != 0 {
				t.Fatalf("handed off %d networks", n)
			}
		})
	}
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	if p := x.get("/rotate/card"); strings.Contains(p, wifiWarning) {
		t.Fatal("warned of a switch that does not happen")
	}
	x.post("/rotate/card", x.group())
	if n := x.nets(); n != 0 {
		t.Fatalf("handed off %d networks", n)
	}
	if done := x.get("/rotate/done"); strings.Contains(done, wifiSwitched) || strings.Contains(done, wifiKept) {
		t.Fatalf("done page: %s", done)
	}
}

// #1191: a commit outside a session's confirm has no session to hand off
// with, so nothing is handed off.
func TestRotationWithNoConfirmerHandsOffNothing(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	_, g := x.r.Display().Asks()
	if err := x.r.Display().ConfirmAnswers(card.Answers{Group: strings.Split(x.gen.RecoveryKey, "-")[g-1]}); err != nil {
		t.Fatal(err)
	}
	if n := x.nets(); n != 0 {
		t.Fatalf("handed off %d networks", n)
	}
}

// #1526 L-2 (mutant M14): a post's hand-off is cleared when the post
// ends, so a later commit outside any post (here ConfirmAnswers after a
// mismatched post) hands off nothing.
func TestAPostsWiFiHandOffEndsWithThePost(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"wifi", "recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	if w := x.post("/rotate/card", url.Values{"group": {"ZZZZ"}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched post: %d", w.Code)
	}
	_, g := x.r.Display().Asks()
	if err := x.r.Display().ConfirmAnswers(card.Answers{Group: strings.Split(x.gen.RecoveryKey, "-")[g-1]}); err != nil {
		t.Fatal(err)
	}
	if n := x.nets(); n != 0 {
		t.Fatalf("handed off %d networks after the post ended", n)
	}
}

// liveOwner refuses a call whose context is already done, as agentosd's
// socket client does.
type liveOwner struct{ Owner }

func (o liveOwner) Call(ctx context.Context, op string, args, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return o.Owner.Call(ctx, op, args, out)
}
