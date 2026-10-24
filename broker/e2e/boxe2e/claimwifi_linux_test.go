package main

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/localui"
)

// REQ: HW-10

// wifiBoxCode is a synthetic claim code; wifiBoxToken the claimant token
// the fake claim hands back for it.
const (
	wifiBoxCode  = "CANA-RYCL-AXMC-KDE2"
	wifiBoxToken = "claimant-canary"
)

// wifiBoxClaim is a sealed claim that takes wifiBoxCode once.
type wifiBoxClaim struct {
	mu      sync.Mutex
	claimed bool
}

func (c *wifiBoxClaim) Status() claim.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return claim.Status{Claimed: c.claimed, TriesLeft: claim.MaxWrong}
}

func (c *wifiBoxClaim) Claim(code string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.claimed:
		return "", claim.ErrAlreadyClaimed
	case code != wifiBoxCode:
		return "", claim.ErrWrongCode
	}
	c.claimed = true
	return wifiBoxToken, nil
}

func (c *wifiBoxClaim) Claimant(tok string) bool { return tok == wifiBoxToken }

// fakeSetupWiFi is agentosd's setup network as the claim step sees it:
// none, or a network rotated at most once. rotateErr refuses the rotation.
type fakeSetupWiFi struct {
	mu        sync.Mutex
	none      bool
	rotated   string // the password it was rotated to
	writes    int
	rotateErr error
}

func (f *fakeSetupWiFi) SetupWiFi() (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.none {
		return "", false, localui.ErrNoSetupWiFi
	}
	return "agentOS-setup-CANARYXX", f.rotated != "", nil
}

func (f *fakeSetupWiFi) RotateSetupWiFi(pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rotateErr != nil {
		return f.rotateErr
	}
	f.rotated = pw
	f.writes++
	return nil
}

// phoneRT serves the phone's requests from h as if they came from the
// phone's address on the box's Wi-Fi.
type phoneRT struct{ h http.Handler }

func (t phoneRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.RemoteAddr = "10.42.0.23:51000"
	r.RequestURI = r.URL.RequestURI()
	return handlerRT{t.h}.RoundTrip(r)
}

// wifiDriver is a driver whose phone talks to a real setup page with a
// fake claim and setup network, keeping its cookies.
func wifiDriver(t *testing.T, f *fakeSetupWiFi, c *wifiBoxClaim) *driver {
	t.Helper()
	ui, err := localui.New(localui.Config{
		AP: localui.APConfig{Iface: "wlan0", Uplink: "eth0", Addr: netip.MustParsePrefix("10.42.0.1/24"),
			SSID: "AgentOS-7K3M", Password: "ABCD-EFGH-JKLM-NPQR"},
		Port:      80,
		Claim:     c,
		SetupWiFi: f,
	})
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	return &driver{phone: &http.Client{
		Transport:     phoneRT{ui},
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// claimed claims the box from d's phone as claim() does, and returns
// where the page sent it.
func claimed(t *testing.T, d *driver) string {
	t.Helper()
	st, loc, err := d.post("/claim", url.Values{"code": {wifiBoxCode}})
	if err != nil || st != http.StatusSeeOther {
		t.Fatalf("POST /claim %d %q %v", st, loc, err)
	}
	return loc
}

// The claim's Wi-Fi step (#2393): claimWiFi rotates the setup network when
// the page has one, skips only on the page's own 303 to /setup, and fails
// on any other answer. An always-skip mutant fails the rotation case; a
// skip on any 303 fails the not-the-claimant case.
func TestClaimWiFiRotatesOrSkipsAsThePageSays(t *testing.T) {
	// The box has a setup network: the shown password is saved, its last
	// four typed back, and setup no longer waits on the step.
	f := &fakeSetupWiFi{}
	d := wifiDriver(t, f, &wifiBoxClaim{})
	if loc := claimed(t, d); loc != "/claim/wifi" {
		t.Fatalf("claim sent the phone to %q", loc)
	}
	if err := d.claimWiFi(); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if f.writes != 1 || apnet.ValidPassword(f.rotated) != nil {
		t.Fatalf("setup network rotated %d times to %q", f.writes, f.rotated)
	}
	if st, loc, _, err := d.get("/setup"); err != nil || st == http.StatusSeeOther && loc == "/claim/wifi" {
		t.Fatalf("setup still waits on the step: %d %q %v", st, loc, err)
	}

	// The box has none: the page sends the phone on to /setup and the
	// driver goes on without a write.
	f = &fakeSetupWiFi{none: true}
	d = wifiDriver(t, f, &wifiBoxClaim{})
	claimed(t, d)
	if err := d.claimWiFi(); err != nil || f.writes != 0 {
		t.Fatalf("no setup network: %v, %d writes", err, f.writes)
	}

	// A 303 elsewhere is not the skip: a phone that is not the claimant
	// is sent to /claim, and the step fails.
	f = &fakeSetupWiFi{}
	c := &wifiBoxClaim{}
	claimed(t, wifiDriver(t, f, c))
	if err := wifiDriver(t, f, c).claimWiFi(); err == nil || !strings.Contains(err.Error(), `"/claim"`) || f.writes != 0 {
		t.Fatalf("not the claimant: %v, %d writes", err, f.writes)
	}

	// A rotation agentosd refuses fails the step.
	f = &fakeSetupWiFi{rotateErr: errors.New("agentosd down")}
	d = wifiDriver(t, f, &wifiBoxClaim{})
	claimed(t, d)
	if err := d.claimWiFi(); err == nil || !strings.Contains(err.Error(), "POST /claim/wifi 503") {
		t.Fatalf("refused rotation: %v", err)
	}
}
