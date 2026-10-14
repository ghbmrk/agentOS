package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/recovery"
)

// REQ: REC-4, CH-3, CH-7, ARC-1

// verifier serves the rig's vault process and answers agentosd's client
// of its verify socket.
func (x *cardRig) verifier(t *testing.T) *modelroute.Verifier {
	t.Helper()
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, x.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range srvs {
			s.Close()
		}
	})
	return modelroute.NewVerifier(filepath.Join(run, VerifySocket))
}

// #1522: a committed Wi-Fi rotation leaves its network with the vault
// process for agentosd to take once over the verify socket; the page
// never supplies it. A second take, or one with no Wi-Fi commit, gets
// nothing.
func TestACommittedWiFiRotationIsHeldForAgentosdOnce(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	v := x.verifier(t)
	if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
		t.Fatalf("before any rotation: %v", err)
	}
	if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"wifi", "grid"}}); code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
		t.Fatalf("begun, not committed: %v", err)
	}
	next := nextWiFiGrid(t)
	if code, out := x.commit(t, next); code != http.StatusOK {
		t.Fatalf("commit: %d %v", code, out)
	}
	w, err := v.TakeRotatedWiFi()
	if err != nil || w.SSID != x.card.WiFiName || w.Password != next.WiFiPassword {
		t.Fatalf("take: %v", err)
	}
	if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
		t.Fatalf("second take: %v", err)
	}

	// A rotation without the Wi-Fi part holds nothing.
	x.clk.add(30 * time.Second)
	if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"grid"}}); code != http.StatusOK {
		t.Fatalf("begin grid: %d %v", code, out)
	}
	if code, out := x.commit(t, rotateCommit{GridSeed: nextWiFiGrid(t).GridSeed}); code != http.StatusOK {
		t.Fatalf("commit grid: %d %v", code, out)
	}
	if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
		t.Fatalf("grid only: %v", err)
	}
}

// #1522: the held network lapses, and a new begin or a lock drops it, so
// it never outlives the commit's hand-off.
func TestAHeldWiFiNetworkLapsesAndIsDropped(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	v := x.verifier(t)
	commit := func() {
		t.Helper()
		x.clk.add(30 * time.Second)
		if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"wifi"}}); code != http.StatusOK {
			t.Fatalf("begin: %d %v", code, out)
		}
		if code, out := x.commit(t, rotateCommit{WiFiPassword: synthetic(t, "wifi-next-")}); code != http.StatusOK {
			t.Fatalf("commit: %d %v", code, out)
		}
	}
	commit()
	x.clk.add(wifiHold + time.Second)
	if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
		t.Fatalf("lapsed: %v", err)
	}

	commit()
	x.clk.add(30 * time.Second)
	if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"wifi"}}); code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
		t.Fatalf("after a new begin: %v", err)
	}

	commit()
	x.c.lock()
	x.clk.add(30 * time.Second)
	x.open(t)
	if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
		t.Fatalf("after a lock: %v", err)
	}
}

// #1523: a commit that stopped after a slot was rewritten (409) shows the
// new card as in effect, so its Wi-Fi network is held as a clean
// commit's is.
func TestAPartWayWiFiRotationIsHeldToo(t *testing.T) {
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
	next := rotateCommit{WiFiPassword: synthetic(t, "wifi-next-"), RecoveryKey: nk.Text()}
	if code, out := x.commit(t, next); code != http.StatusConflict {
		t.Fatalf("part way: %d %v", code, out)
	}
	if w, err := v.TakeRotatedWiFi(); err != nil || w.Password != next.WiFiPassword || w.SSID != x.card.WiFiName {
		t.Fatalf("take: %v", err)
	}
}

// ARC-1: the route answers only a POST, and only the network; the held
// value never prints from the client's type.
func TestTheRotatedWiFiRouteIsNarrow(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	w := httptest.NewRecorder()
	verifyHandler(x.c).ServeHTTP(w, httptest.NewRequest("GET", "/rotate/wifi", nil))
	if w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Body.String(), "/rotate/wifi") {
		t.Fatalf("GET: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	verifyHandler(x.c).ServeHTTP(w, httptest.NewRequest("POST", "/rotate/wifi", nil))
	if w.Code != http.StatusGone {
		t.Fatalf("nothing held: %d", w.Code)
	}
	rw := modelroute.RotatedWiFi{SSID: x.card.WiFiName, Password: synthetic(t, "wifi-next-")}
	for _, s := range []string{fmt.Sprintf("%v %+v %s", rw, rw, rw), fmt.Sprintf("%#v", rw)} {
		if strings.Contains(s, rw.Password) {
			t.Fatalf("printed: %s", s)
		}
	}
}

// Sec R1 / P-1 on #1614: only a commit that put the new card in effect
// holds its Wi-Fi network. A commit for another rotation, a card that
// does not fit, a lapsed rotation, a vault no longer open, and a commit
// that failed before any slot was written all leave nothing to take.
func TestACommitThatDidNotTakeEffectHoldsNoWiFi(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	v := x.verifier(t)
	begin := func() {
		t.Helper()
		x.clk.add(30 * time.Second)
		if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"wifi"}}); code != http.StatusOK {
			t.Fatalf("begin: %d %v", code, out)
		}
	}
	none := func(what string, code, want int) {
		t.Helper()
		if code != want {
			t.Fatalf("%s: %d, want %d", what, code, want)
		}
		if _, err := v.TakeRotatedWiFi(); !errors.Is(err, modelroute.ErrNoRotatedWiFi) {
			t.Fatalf("%s left a permit: %v", what, err)
		}
	}

	begin()
	code, _ := x.commit(t, rotateCommit{ID: newRotationID(), WiFiPassword: synthetic(t, "wifi-next-")})
	none("another rotation's ID", code, http.StatusGone)

	code, _ = x.commit(t, rotateCommit{WiFiPassword: synthetic(t, "wifi-next-"), GridSeed: nextWiFiGrid(t).GridSeed})
	none("a card that does not fit", code, http.StatusBadRequest)

	x.clk.add(recovery.PendingTTL + time.Second)
	code, _ = x.commit(t, rotateCommit{WiFiPassword: synthetic(t, "wifi-next-")})
	none("a lapsed rotation", code, http.StatusGone)

	begin()
	x.c.lock()
	x.clk.add(30 * time.Second)
	x.open(t)
	code, _ = x.commit(t, rotateCommit{WiFiPassword: synthetic(t, "wifi-next-")})
	none("a vault locked since the begin", code, http.StatusGone)

	// Long enough for the card's shape, too short for the vault's own
	// entry: the commit fails at the store, before anything was written,
	// and the rotation is spent.
	begin()
	code, _ = x.commit(t, rotateCommit{WiFiPassword: "short-wifi"})
	none("a commit that wrote nothing", code, http.StatusGone)
	code, _ = x.commit(t, rotateCommit{WiFiPassword: synthetic(t, "wifi-next-")})
	none("the spent rotation", code, http.StatusGone)
	if got := x.stored(t, x.rk); got.WiFiPassword != x.card.WiFiPassword {
		t.Fatal("a failed commit changed the card")
	}
}
