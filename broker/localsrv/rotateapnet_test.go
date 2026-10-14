package localsrv

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: REC-4, CH-7, ARC-1

// #1191, #1522: the page asks for a rotated Wi-Fi network only with a live
// session, and sends nothing else: the network comes from the vault
// process through the hook, never from the page.
func TestARotatedWiFiNetworkNeedsASessionAndNothingElse(t *testing.T) {
	r := newRig(t)
	if _, err := r.call(localapi.OpRotateAPNet, localapi.Auth{}); code(err) != localapi.ErrUnauthorized || r.rotated != 0 {
		t.Fatalf("no token: %v %d", err, r.rotated)
	}
	tok := r.signIn()
	// The old shape, a page-supplied network, is refused outright.
	if _, err := r.raw(localapi.OpRotateAPNet, `{"token":"`+tok+`","ssid":"AgentOS-AB2C","password":"ABCD-EFGH-JKLM-NP23"}`); code(err) != localapi.ErrBadArgs {
		t.Fatalf("page-supplied network: %v", err)
	}
	if r.rotated != 0 {
		t.Fatalf("hook ran on a refusal: %d", r.rotated)
	}
	if _, err := r.call(localapi.OpRotateAPNet, localapi.Auth{Token: tok}); err != nil {
		t.Fatal(err)
	}
	if r.rotated != 1 {
		t.Fatalf("rotated %d", r.rotated)
	}
}

// A hook that fails, or none, is a fixed failure, never its own text.
func TestARotatedWiFiNetworkThatCannotBeWrittenFails(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.srv.cfg.RotateAPNet = func() error { return errors.New("apnet: /var/lib/agentos/ap-net.json: read-only") }
	if _, err := r.call(localapi.OpRotateAPNet, localapi.Auth{Token: tok}); code(err) != localapi.ErrFailed {
		t.Fatalf("hook error: %v", err)
	}
	r.srv.cfg.RotateAPNet = nil
	if _, err := r.call(localapi.OpRotateAPNet, localapi.Auth{Token: tok}); code(err) != localapi.ErrFailed {
		t.Fatalf("no hook: %v", err)
	}
}
