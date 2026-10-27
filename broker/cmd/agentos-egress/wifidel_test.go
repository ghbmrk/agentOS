package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: CH-9, REC-4
//
// WIFI-del-e (#3365, D-178): the Owner Card has no Wi-Fi, so the vault
// process hands out no Wi-Fi network. The verify socket's rotated-network
// permit and committed-network read are gone: both paths are refused like
// any unknown route, and the refusal no longer lists them. The rotation's
// begin answers no Wi-Fi name. It catches a vault route that would still
// hand out a Wi-Fi password.
func TestTheVaultHandsOutNoWiFi(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	for _, req := range [][2]string{{"POST", "/rotate/wifi"}, {"GET", "/committed-wifi"}} {
		w := httptest.NewRecorder()
		verifyHandler(x.c).ServeHTTP(w, httptest.NewRequest(req[0], req[1], nil))
		if w.Code != http.StatusMethodNotAllowed || strings.Contains(w.Body.String(), "wifi") {
			t.Fatalf("%s %s: %d %s", req[0], req[1], w.Code, w.Body)
		}
	}
	code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup"}})
	if code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	if _, ok := out["wifi_name"]; ok {
		t.Fatalf("begin answers a Wi-Fi name: %v", out)
	}
}
