package localsrv

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: REC-4, CH-7, ARC-1

// A synthetic card network, the shape card.Generate makes.
const (
	rotSSID     = "AgentOS-AB2C"
	rotPassword = "ABCD-EFGH-JKLM-NP23"
)

// #1191: a committed Wi-Fi rotation reaches agentos-ap only through
// agentosd, and only from a live session and in a shape a card prints;
// anything else is refused before the hook runs.
func TestARotatedWiFiNetworkNeedsASessionAndACardShape(t *testing.T) {
	r := newRig(t)
	if _, err := r.call(localapi.OpRotateAPNet, localapi.RotateAPNet{SSID: rotSSID, Password: rotPassword}); code(err) != localapi.ErrUnauthorized || len(r.rotated) != 0 {
		t.Fatalf("no token: %v %d", err, len(r.rotated))
	}
	tok := r.signIn()
	for _, bad := range []localapi.RotateAPNet{
		{Token: tok, SSID: rotSSID},
		{Token: tok, SSID: "home", Password: rotPassword},
		{Token: tok, SSID: rotSSID, Password: "password1"},
		{Token: tok, SSID: rotSSID, Password: rotPassword + "\nwpa_key_mgmt=WPA-PSK"},
	} {
		if _, err := r.call(localapi.OpRotateAPNet, bad); code(err) != localapi.ErrBadArgs {
			t.Errorf("%q/%q: %v", bad.SSID, bad.Password, err)
		}
	}
	if _, err := r.raw(localapi.OpRotateAPNet, `{"token":"`+tok+`","ssid":"`+rotSSID+`","password":"`+rotPassword+`","wpa2":true}`); code(err) != localapi.ErrBadArgs {
		t.Fatalf("unknown field: %v", err)
	}
	if len(r.rotated) != 0 {
		t.Fatalf("hook ran on a refusal: %d", len(r.rotated))
	}
	if _, err := r.call(localapi.OpRotateAPNet, localapi.RotateAPNet{Token: tok, SSID: rotSSID, Password: rotPassword}); err != nil {
		t.Fatal(err)
	}
	if len(r.rotated) != 1 || r.rotated[0] != (apnet.Network{SSID: rotSSID, Password: rotPassword}) {
		t.Fatalf("rotated %d", len(r.rotated))
	}
}

// A hook that fails, or none, is a fixed failure, never its own text.
func TestARotatedWiFiNetworkThatCannotBeWrittenFails(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.srv.cfg.RotateAPNet = func(apnet.Network) error { return errors.New("apnet: /var/lib/agentos/ap-net.json: read-only") }
	if _, err := r.call(localapi.OpRotateAPNet, localapi.RotateAPNet{Token: tok, SSID: rotSSID, Password: rotPassword}); code(err) != localapi.ErrFailed {
		t.Fatalf("hook error: %v", err)
	}
	r.srv.cfg.RotateAPNet = nil
	if _, err := r.call(localapi.OpRotateAPNet, localapi.RotateAPNet{Token: tok, SSID: rotSSID, Password: rotPassword}); code(err) != localapi.ErrFailed {
		t.Fatalf("no hook: %v", err)
	}
}

// ARC-1: the op's arguments never print the token or the password.
func TestARotatedWiFiNetworkDoesNotPrint(t *testing.T) {
	in := localapi.RotateAPNet{Token: "0123456789abcdef0123456789abcdef", SSID: rotSSID, Password: rotPassword}
	for _, s := range []string{fmt.Sprintf("%v %+v %s", in, in, in), fmt.Sprintf("%#v", in)} {
		if strings.Contains(s, rotPassword) || strings.Contains(s, in.Token) {
			t.Fatalf("printed: %s", s)
		}
	}
}
