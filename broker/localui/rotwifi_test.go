package localui

// REQ: REC-4, CH-7, CRED-1

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/card"
)

const (
	wifiSwitched = "My Wi-Fi now uses your new card"
	wifiKept     = "My Wi-Fi still uses your old card"
	wifiWarning  = "my Wi-Fi switches to the new password on this card"
)

func (x *wireRig) nets() []apnet.Network {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]apnet.Network(nil), x.wifiNets...)
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
	if len(x.nets()) != 0 {
		t.Fatal("handed off before the confirm")
	}
	if w := x.post("/rotate/card", x.group()); w.Header().Get("Location") != "/rotate/done" {
		t.Fatalf("confirm: %d %s", w.Code, w.Header().Get("Location"))
	}
	nets := x.nets()
	if len(nets) != 1 || nets[0] != (apnet.Network{SSID: "AgentOS-TEST", Password: x.gen.WiFiPassword}) {
		t.Fatalf("handed off %d networks, or another one", len(nets))
	}
	done := x.get("/rotate/done")
	if !strings.Contains(done, wifiSwitched) || strings.Contains(done, wifiKept) {
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
	if !strings.Contains(done, wifiKept) || strings.Contains(done, wifiSwitched) {
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
			x.post("/rotate/card", x.group())
			nets := x.nets()
			if len(nets) != 1 || nets[0] != (apnet.Network{SSID: "AgentOS-TEST", Password: x.gen.WiFiPassword}) {
				t.Fatalf("handed off %d networks, or another one", len(nets))
			}
		})
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
			if n := len(x.nets()); n != 0 {
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
	if n := len(x.nets()); n != 0 {
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
	if n := len(x.nets()); n != 0 {
		t.Fatalf("handed off %d networks", n)
	}
}
