package localui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// REQ: CH-9, ONB-5, HW-10, REC-4

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

// D-178 (WIFI-del-a2, #3234): the core runs no access point (CH-9), so a
// card rotation offers no Wi-Fi password part, and a post that asks for
// one is refused before it reaches the vault process. It catches a page
// that still rotates a password no access point serves.
func TestRotationOffersNoWiFiPart(t *testing.T) {
	x := newWireRig(t)
	if p := x.get("/rotate/"); strings.Contains(p, `value="wifi"`) || strings.Contains(p, "Wi-Fi") {
		t.Fatalf("the rotation form offers Wi-Fi: %s", p)
	}
	for _, parts := range [][]string{{"wifi"}, {"wifi", "grid"}} {
		if w := x.post("/rotate/", url.Values{"parts": parts, "code": {"123456"}}); w.Code != http.StatusBadRequest || x.r.Display() != nil {
			t.Fatalf("parts %v: %d", parts, w.Code)
		}
	}
	if b, _, _ := x.v.n(); b != 0 {
		t.Fatalf("a Wi-Fi rotation reached the vault %d times", b)
	}
}

// D-178 (WIFI-del-a2, #3234): the core runs no captive portal (ONB-5). A
// phone's captive-portal check, or any other foreign host name, gets a
// refusal and never a redirect to the box, whatever the method.
func TestCoreAnswersNoCaptiveCheck(t *testing.T) {
	r := newRig(t)
	for _, u := range []string{"http://captive.apple.com/hotspot-detect.html", "http://connectivitycheck.gstatic.com/generate_204",
		"http://www.msftconnecttest.com/connecttest.txt", "http://detectportal.firefox.com/success.txt"} {
		for _, m := range []string{"GET", "HEAD", "POST"} {
			req := httptest.NewRequest(m, u, nil)
			req.RemoteAddr = phoneIP
			w := httptest.NewRecorder()
			r.srv.ServeHTTP(w, reaching(req))
			if w.Code != http.StatusMisdirectedRequest || w.Header().Get("Location") != "" {
				t.Errorf("%s %s: %d %q", m, u, w.Code, w.Header().Get("Location"))
			}
		}
	}
}
