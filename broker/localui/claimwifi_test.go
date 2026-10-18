package localui

// REQ: HW-10, CH-7, ARC-1, CRED-1

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// wifiSSID is a synthetic setup network name.
const wifiSSID = "AgentOS-setup-CANARYXX"

// fakeSetupNet stands in for agentosd's setup Wi-Fi ops (#1692): it holds
// the network and refuses as agentosd does. fail, when set, refuses every
// call with it; rotateFail refuses only the rotation, after a good read.
type fakeSetupNet struct {
	mu         sync.Mutex
	none       bool
	rotated    bool
	pw         string
	fail       sockets.Code
	rotateFail sockets.Code
	writes     int
}

func (f *fakeSetupNet) ops() InProcess {
	return InProcess{
		localapi.OpSetupWiFiName: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			switch {
			case f.fail != "":
				return nil, f.fail
			case f.none:
				return nil, sockets.Code(localapi.ErrNoSetupWiFi)
			}
			return localapi.SetupWiFiName{SSID: wifiSSID, Rotated: f.rotated}, nil
		},
		localapi.OpSetupWiFi: func(_ context.Context, _ sockets.Peer, b json.RawMessage) (any, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			var a localapi.SetupWiFi
			if err := json.Unmarshal(b, &a); err != nil || apnet.ValidPassword(a.Password) != nil {
				return nil, sockets.Code(localapi.ErrBadArgs)
			}
			switch {
			case f.fail != "":
				return nil, f.fail
			case f.rotateFail != "":
				return nil, f.rotateFail
			case f.none:
				return nil, sockets.Code(localapi.ErrNoSetupWiFi)
			case f.rotated:
				return nil, sockets.Code(localapi.ErrWiFiRotated)
			}
			f.pw, f.rotated = a.Password, true
			f.writes++
			return nil, nil
		},
	}
}

func (f *fakeSetupNet) set(fn func(*fakeSetupNet)) { f.mu.Lock(); fn(f); f.mu.Unlock() }

// withWiFi starts the claim rig's UI again with the setup Wi-Fi step
// served through agentosd's page ops in ops.
func (cr *claimRig) withWiFi(ops InProcess) {
	cr.t.Helper()
	cl, err := claim.Open(claim.Config{Store: cr.st, BootID: func() (string, error) { return cr.boot, nil },
		Rand: rand.New(rand.NewSource(4))})
	if err != nil {
		cr.t.Fatal(err)
	}
	s, err := New(Config{AP: testAP(), Hooks: cr.hooks, SetupSecret: cr.card.SetupSecret, Store: &MemStore{},
		Claim: boxClaim{cl}, SetupWiFi: AgentosdSetup{Owner: ops}, Now: cr.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		cr.t.Fatal(err)
	}
	cr.srv = s
}

// shownPassword is the password the Wi-Fi step's page shows.
func shownPassword(t *testing.T, body string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, `New password: <span class="mono">`)
	pw, _, ok2 := strings.Cut(rest, "<")
	if !ok || !ok2 {
		t.Fatalf("no password on the page: %s", body)
	}
	return pw
}

// saved is the commit form with the password's last four characters typed
// back, as an owner who saved it does.
func saved(pw string) url.Values { return url.Values{"last": {strings.ToLower(pw[len(pw)-4:])}} }

// HW-10 (#1692): right after the claim, the claiming phone is shown a new
// setup Wi-Fi password with its QR, and setup waits until the phone
// commits it; only then is the sticker's password replaced, once, with the
// password the page showed. Nobody else sees the step.
func TestTheClaimRotatesTheSetupWiFi(t *testing.T) {
	r := newClaimRig(t)
	f := &fakeSetupNet{}
	r.withWiFi(f.ops())

	// Before the claim the step is closed like the rest of setup.
	if w := r.do("GET", "/claim/wifi", nil); w.Code != 303 || w.Header().Get("Location") != "/claim" {
		t.Fatalf("Wi-Fi step before the claim: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := r.post("/claim", url.Values{"code": {claimCode}}); w.Code != 303 || w.Header().Get("Location") != "/claim/wifi" {
		t.Fatalf("claim: %d %q", w.Code, w.Header().Get("Location"))
	}
	// Setup sends the claimant to the Wi-Fi step and takes no setup post.
	for _, p := range []string{"/setup", "/setup/card"} {
		if w := r.do("GET", p, nil); w.Code != 303 || w.Header().Get("Location") != "/claim/wifi" {
			t.Fatalf("GET %s before the Wi-Fi step: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}}); w.Code != 403 {
		t.Fatalf("setup post before the Wi-Fi step: %d", w.Code)
	}
	body := r.get("/claim/wifi")
	pw := shownPassword(t, body)
	if apnet.ValidPassword(pw) != nil {
		t.Fatalf("shown password %q is not 16 card symbols", pw)
	}
	if !strings.Contains(body, wifiSSID) || !strings.Contains(body, "<svg") || !strings.Contains(body, "screenshot") ||
		!strings.Contains(body, "http://10.42.0.1/setup") || !strings.Contains(body, "Forget This Network") ||
		!strings.Contains(body, "reinstall me") {
		t.Fatalf("Wi-Fi step page: %s", body)
	}
	// A reload shows the same password, and nothing is written yet.
	if again := shownPassword(t, r.get("/claim/wifi")); again != pw || f.writes != 0 {
		t.Fatalf("reload showed %q (was %q), %d writes", again, pw, f.writes)
	}

	// Another phone on the Wi-Fi never sees the password or commits it.
	claimant := r.jar
	r.otherPhone()
	if w := r.do("GET", "/claim/wifi", nil); w.Code != 303 || strings.Contains(w.Body.String(), pw) {
		t.Fatalf("other phone's Wi-Fi step: %d", w.Code)
	}
	if w := r.post("/claim/wifi", saved(pw)); w.Code != 303 || f.writes != 0 {
		t.Fatalf("other phone's commit: %d, %d writes", w.Code, f.writes)
	}
	r.jar, r.ip = claimant, phoneIP

	// A tap without the saved password's last four characters switches
	// nothing and shows the same password again.
	for _, last := range []string{"", "ZZZZ", pw[:4]} {
		w := r.post("/claim/wifi", url.Values{"last": {last}})
		if w.Code != 400 || f.writes != 0 || shownPassword(t, w.Body.String()) != pw {
			t.Fatalf("commit with %q typed: %d, %d writes", last, w.Code, f.writes)
		}
	}

	// The claimant commits: the password shown is the one written.
	w := r.post("/claim/wifi", saved(pw))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "restarting with the new password") ||
		!strings.Contains(w.Body.String(), "Forget This Network") {
		t.Fatalf("commit: %d %s", w.Code, w.Body.String())
	}
	if f.pw != pw || f.writes != 1 || strings.Contains(w.Body.String(), pw) {
		t.Fatalf("wrote %q (shown %q), %d writes", f.pw, pw, f.writes)
	}
	// Setup goes on; the step is over, also after the page restarts.
	if w := r.do("GET", "/setup", nil); w.Code != 200 {
		t.Fatalf("setup after the Wi-Fi step: %d", w.Code)
	}
	if w := r.do("GET", "/claim/wifi", nil); w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatalf("Wi-Fi step after it: %d %q", w.Code, w.Header().Get("Location"))
	}
	r.withWiFi(f.ops())
	if w := r.do("GET", "/setup", nil); w.Code != 200 {
		t.Fatalf("setup after a restart: %d", w.Code)
	}
	if w := r.post("/claim/wifi", saved(pw)); w.Code != 303 || f.writes != 1 {
		t.Fatalf("commit after the step: %d, %d writes", w.Code, f.writes)
	}
}

// A box with no setup network (none preloaded, burned, or -setup-net set
// empty, all answered "no setup wifi" by agentosd) has no Wi-Fi step. One
// agentosd cannot answer for, or serves no setup Wi-Fi op for, keeps setup
// closed (fails closed), and a failed commit leaves setup closed and can
// be tried again with the same password.
func TestTheWiFiStepFailsClosed(t *testing.T) {
	r := newClaimRig(t)
	r.withWiFi((&fakeSetupNet{none: true}).ops())
	r.post("/claim", url.Values{"code": {claimCode}})
	if w := r.do("GET", "/setup", nil); w.Code != 200 {
		t.Fatalf("no network: setup: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := r.do("GET", "/claim/wifi", nil); w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatalf("no network: Wi-Fi step: %d", w.Code)
	}

	for name, f := range map[string]*fakeSetupNet{"agentosd fails": {fail: sockets.ErrFailed}, "no op": nil} {
		r := newClaimRig(t)
		ops := InProcess{}
		if f != nil {
			ops = f.ops()
		}
		r.withWiFi(ops)
		r.post("/claim", url.Values{"code": {claimCode}})
		if w := r.do("GET", "/setup", nil); w.Code != 503 {
			t.Fatalf("%s: setup: %d", name, w.Code)
		}
		if w := r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}}); w.Code != 503 {
			t.Fatalf("%s: setup post: %d", name, w.Code)
		}
		if w := r.do("GET", "/claim/wifi", nil); w.Code != 503 {
			t.Fatalf("%s: Wi-Fi step: %d", name, w.Code)
		}
	}

	// Only the rotation fails, after a good read: the commit answers 503,
	// setup stays closed, and a retry writes the password shown.
	r = newClaimRig(t)
	f := &fakeSetupNet{}
	r.withWiFi(f.ops())
	r.post("/claim", url.Values{"code": {claimCode}})
	pw := shownPassword(t, r.get("/claim/wifi"))
	f.set(func(f *fakeSetupNet) { f.rotateFail = sockets.ErrFailed })
	if w := r.post("/claim/wifi", saved(pw)); w.Code != 503 || shownPassword(t, w.Body.String()) != pw {
		t.Fatalf("commit while the rotation fails: %d", w.Code)
	}
	for _, p := range []string{"/setup", "/setup/card"} {
		if w := r.do("GET", p, nil); w.Code != 303 || w.Header().Get("Location") != "/claim/wifi" {
			t.Fatalf("GET %s after a failed commit: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}}); w.Code != 403 {
		t.Fatalf("setup post after a failed commit: %d", w.Code)
	}
	if w := r.do("GET", "/claim/wifi", nil); w.Code != 200 || shownPassword(t, w.Body.String()) != pw {
		t.Fatalf("Wi-Fi step after a failed commit: %d", w.Code)
	}
	f.set(func(f *fakeSetupNet) { f.rotateFail = "" })
	if w := r.post("/claim/wifi", saved(pw)); w.Code != 200 || f.pw != pw || f.writes != 1 {
		t.Fatalf("retried commit: %d wrote %q, shown %q", w.Code, f.pw, pw)
	}

	// The rotation answers that it already landed (a lost answer) or that
	// the network is gone (burned): the step is over and setup goes on.
	for name, code := range map[string]sockets.Code{"rotated": localapi.ErrWiFiRotated, "burned": localapi.ErrNoSetupWiFi} {
		r := newClaimRig(t)
		f := &fakeSetupNet{}
		r.withWiFi(f.ops())
		r.post("/claim", url.Values{"code": {claimCode}})
		pw := shownPassword(t, r.get("/claim/wifi"))
		f.set(func(f *fakeSetupNet) { f.rotateFail = code })
		if w := r.post("/claim/wifi", saved(pw)); w.Code != 303 || w.Header().Get("Location") != "/setup" {
			t.Fatalf("%s: commit: %d %q", name, w.Code, w.Header().Get("Location"))
		}
		if w := r.do("GET", "/setup", nil); w.Code != 200 {
			t.Fatalf("%s: setup: %d", name, w.Code)
		}
	}

	// A POST with no password shown commits nothing.
	r = newClaimRig(t)
	f = &fakeSetupNet{}
	r.withWiFi(f.ops())
	r.post("/claim", url.Values{"code": {claimCode}})
	if w := r.post("/claim/wifi", url.Values{"last": {"ABCD"}}); w.Code != 303 || w.Header().Get("Location") != "/claim/wifi" || f.writes != 0 {
		t.Fatalf("unshown commit: %d, %d writes", w.Code, f.writes)
	}
}
