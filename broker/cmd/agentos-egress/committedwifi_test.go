package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/recovery"
)

// REQ: REC-4, CRED-8, ARC-1, CH-7

// #1696: while the vault is open, the verify socket answers the Owner
// Card's committed Wi-Fi network, so agentosd can put it back in
// ap-net.json after a missed hand-off. It follows a commit, takes
// nothing (the one-shot permit stays), and is refused while locked.
func TestTheCommittedWiFiRouteAnswersTheVaultsNetwork(t *testing.T) {
	x := newCardRig(t)
	v := x.verifier(t)
	if _, err := v.CommittedWiFi(); !errors.Is(err, modelroute.ErrVaultLocked) {
		t.Fatalf("locked: %v", err)
	}
	x.open(t)
	w, err := v.CommittedWiFi()
	if err != nil || w.SSID != x.card.WiFiName || w.Password != x.card.WiFiPassword {
		t.Fatalf("card's own: %v", err)
	}

	if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"wifi"}}); code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	if w, err := v.CommittedWiFi(); err != nil || w.Password != x.card.WiFiPassword {
		t.Fatalf("begun, not committed: %v", err)
	}
	next := synthetic(t, "wifi-next-")
	if code, out := x.commit(t, rotateCommit{WiFiPassword: next}); code != http.StatusOK {
		t.Fatalf("commit: %d %v", code, out)
	}
	for i := 0; i < 2; i++ {
		if w, err := v.CommittedWiFi(); err != nil || w.SSID != x.card.WiFiName || w.Password != next {
			t.Fatalf("committed, read %d: %v", i, err)
		}
	}
	if w, err := v.TakeRotatedWiFi(); err != nil || w.Password != next {
		t.Fatalf("the permit was spent by a read: %v", err)
	}

	x.c.lock()
	if _, err := v.CommittedWiFi(); !errors.Is(err, modelroute.ErrVaultLocked) {
		t.Fatalf("after a lock: %v", err)
	}
	x.clk.add(30 * time.Second)
	x.open(t)
	if w, err := v.CommittedWiFi(); err != nil || w.Password != next {
		t.Fatalf("after unlock: %v", err)
	}
}

// #1696: a vault with no Owner Card has no committed network, and a
// rotation that stopped part way still owes its Wi-Fi part: the stored
// network may not be the one in effect, so none is answered.
func TestTheCommittedWiFiRouteAnswersNothingUncertain(t *testing.T) {
	r := newFastRig(t, true)
	r.c.afterFunc = func(time.Duration, func()) func() bool { return func() bool { return true } }
	tk := r.unlock(t)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	verifyHandler(r.c).ServeHTTP(w, httptest.NewRequest("GET", "/committed-wifi", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no card: %d", w.Code)
	}

	x := newCardRig(t)
	x.open(t)
	v := x.verifier(t)
	if code, out := x.begin(t, map[string]any{"recovery": x.rk.Text(), "parts": []string{"wifi", "recovery"}}); code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	x.c.mu.Lock()
	x.c.host = failReencrypt{nil, errors.New("tpm: synthetic failure")}
	x.c.mu.Unlock()
	nk, _ := recovery.NewRecoveryKey(nil)
	if code, out := x.commit(t, rotateCommit{WiFiPassword: synthetic(t, "wifi-next-"), RecoveryKey: nk.Text()}); code != http.StatusConflict {
		t.Fatalf("part way: %d %v", code, out)
	}
	if _, err := v.CommittedWiFi(); !errors.Is(err, modelroute.ErrWiFiOwed) {
		t.Fatalf("Wi-Fi owed: %v", err)
	}
}

// ARC-1: the route answers only a GET; the client's value never prints.
func TestTheCommittedWiFiRouteIsNarrow(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		w := httptest.NewRecorder()
		verifyHandler(x.c).ServeHTTP(w, httptest.NewRequest(m, "/committed-wifi", nil))
		if w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Body.String(), "/committed-wifi") {
			t.Fatalf("%s: %d %s", m, w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	verifyHandler(x.c).ServeHTTP(w, httptest.NewRequest("GET", "/committed-wifi", nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cacheable: %q", w.Header().Get("Cache-Control"))
	}
	cw := modelroute.RotatedWiFi{SSID: x.card.WiFiName, Password: x.card.WiFiPassword}
	for _, s := range []string{fmt.Sprintf("%v %+v %s", cw, cw, cw), fmt.Sprintf("%#v", cw)} {
		if strings.Contains(s, cw.Password) {
			t.Fatalf("printed: %s", s)
		}
	}
}
