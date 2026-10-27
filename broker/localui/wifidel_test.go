package localui

import (
	"net/url"
	"strings"
	"testing"
)

// REQ: CH-9, ONB-5, HW-10

// D-178 (WIFI-del-a, #3234): the core joins no Wi-Fi and runs no setup
// network. After the claim the claimant goes straight to setup, which
// starts at the number step; neither the claim's Wi-Fi step nor the home
// network step is served.
func TestSetupHasNoWiFiStep(t *testing.T) {
	r := newClaimRig(t)
	w := r.post("/claim", url.Values{"code": {claimCode}})
	if w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatalf("claim: %d %q", w.Code, w.Header().Get("Location"))
	}
	page := r.get("/setup")
	if !strings.Contains(page, "<h2>1. Text your box</h2>") {
		t.Fatalf("setup does not start at the number step: %s", page)
	}
	for _, s := range []string{"Wi-Fi", "Home network", "Ethernet", "/setup/network", "/claim/wifi"} {
		if strings.Contains(page, s) {
			t.Errorf("setup page names %q", s)
		}
	}
	for _, p := range []string{"/claim/wifi", "/setup/network"} {
		if w := r.do("GET", p, nil); w.Code != 404 {
			t.Errorf("GET %s: %d", p, w.Code)
		}
		if w := r.post(p, url.Values{"ssid": {"Home"}, "password": {"home-pass"}, "last": {"WXYZ"}}); w.Code != 404 {
			t.Errorf("POST %s: %d", p, w.Code)
		}
	}
}
