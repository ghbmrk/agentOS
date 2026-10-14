package main

// REQ: HW-10, HW-1

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localui"
)

// claimBox is one box's disk across starts: the claim state the seller
// flow sealed (empty on a download box) and the card latch.
type claimBox struct {
	claim, latch change.MemStore
	code         string
	download     bool // the download's image (firstboot.BoxConfig.Download)
}

func sealedClaimBox(t *testing.T) *claimBox {
	t.Helper()
	code, err := claim.NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &claimBox{code: code}
	if err := claim.Seal(&b.claim, code, nil, nil); err != nil {
		t.Fatal(err)
	}
	return b
}

// claimSetup is a setup mode whose first boot is the page's process's:
// firstboot.Begin routes the box and hands its card step to setup, and its
// claim and card to the setup page served here over localui.sock.
type claimSetup struct {
	m    setupMode
	f    *cardFixture
	fb   chan *firstboot.FirstBoot
	ui   *localui.Server
	done chan runResult
}

func startClaimSetup(t *testing.T, b *claimBox) *claimSetup {
	t.Helper()
	m := newBareSetupMode(t)
	cs := &claimSetup{m: m, f: &cardFixture{vault: &cardVault{dir: filepath.Dir(m.OwnerState)}},
		fb: make(chan *firstboot.FirstBoot, 1)}
	cs.m.Card = func() (cardHold, error) {
		fb, err := firstboot.Begin(firstboot.BoxConfig{
			Claim:    claim.Config{Store: &b.claim, BootID: func() (string, error) { return "boot-1", nil }},
			Latch:    &b.latch,
			Reset:    cs.f.vault.Reset,
			Download: b.download,
			Card: card.DisplayConfig{Provision: cs.f.vault.Provision,
				Generate: func(r io.Reader) (*card.Card, error) {
					c, err := card.Generate(r)
					if err == nil {
						cs.f.shown = *c
					}
					return c, err
				}},
		})
		if err != nil {
			return nil, err
		}
		cs.fb <- fb
		return fb.Card, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cs.done = start(ctx, cs.m)
	fb := <-cs.fb
	setupCall(t, cs.m)
	ui, err := localui.New(localui.Config{
		AP: localui.APConfig{Iface: "wlan0", Uplink: "eth0", Addr: netip.MustParsePrefix("10.42.0.1/24"),
			SSID: "AgentOS-7K3M", Password: "ABCD-EFGH-JKLM-NPQR"},
		Port:  80,
		Hooks: localui.AgentosdSetup{Owner: localui.Socket{Path: filepath.Join(cs.m.Dir, localapi.Socket)}},
		Store: &localui.MemStore{},
		Claim: fb.Claim,
		Card:  fb.Card,
	})
	if err != nil {
		t.Fatal(err)
	}
	cs.ui = ui
	cs.fb <- fb
	return cs
}

func (cs *claimSetup) firstBoot() *firstboot.FirstBoot {
	fb := <-cs.fb
	cs.fb <- fb
	return fb
}

// phone is one client on the box's Wi-Fi, holding its own cookies.
type phone struct {
	ip      string
	cookies []*http.Cookie
}

func (p *phone) do(t *testing.T, s *localui.Server, method, path string, form url.Values, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "http://10.42.0.1"+path, body)
	req.RemoteAddr = p.ip
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range p.cookies {
		req.AddCookie(c)
	}
	for _, m := range mod {
		m(req)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	p.cookies = append(p.cookies, w.Result().Cookies()...)
	return w
}

// Through agentosd's setup path, an unclaimed preloaded box serves only the
// claim screen: every setup page sends the phone to /claim, setup posts
// are refused, a foreign Host never reaches the counter and finish waits.
// The sticker's code claims the box for that phone alone.
func TestAPreloadedBoxServesOnlyTheClaimScreen(t *testing.T) {
	b := sealedClaimBox(t)
	cs := startClaimSetup(t, b)
	if fb := cs.firstBoot(); fb.Route != firstboot.RouteClaim {
		t.Fatalf("route %q", fb.Route)
	}
	owner := &phone{ip: "10.42.0.23:51000"}
	for _, p := range []string{"/", "/setup", "/setup/card"} {
		if w := owner.do(t, cs.ui, "GET", p, nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/claim" {
			t.Fatalf("GET %s before the claim: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := owner.do(t, cs.ui, "POST", "/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}}); w.Code != http.StatusForbidden {
		t.Fatalf("setup post before the claim: %d", w.Code)
	}
	foreign := func(q *http.Request) { q.Host = "attacker.example" }
	if w := owner.do(t, cs.ui, "GET", "/claim", nil, foreign); w.Code == http.StatusOK {
		t.Fatalf("/claim under a foreign Host: %d", w.Code)
	}
	if w := owner.do(t, cs.ui, "POST", "/claim", url.Values{"code": {b.code}}, foreign); w.Code != http.StatusForbidden {
		t.Fatalf("claim under a foreign Host: %d", w.Code)
	}
	if st := cs.firstBoot().Claim.Status(); st.Claimed || st.TriesLeft != claim.MaxWrong {
		t.Fatalf("a refused request reached the counter: %+v", st)
	}
	call := setupCall(t, cs.m)
	if err := call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err == nil || !strings.Contains(err.Error(), errCardPending) {
		t.Fatalf("finish before the claim: %v", err)
	}

	if w := owner.do(t, cs.ui, "POST", "/claim", url.Values{"code": {b.code}}); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" {
		t.Fatalf("the sticker's code: %d %s", w.Code, w.Body.String())
	}
	if w := owner.do(t, cs.ui, "GET", "/setup", nil); w.Code != http.StatusOK {
		t.Fatalf("claimant's setup: %d", w.Code)
	}
	other := &phone{ip: "10.42.0.77:52000"}
	if w := other.do(t, cs.ui, "GET", "/setup", nil); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "already claimed") {
		t.Fatalf("another phone's setup: %d", w.Code)
	}
	if cs.firstBoot().Card.Display() == nil {
		t.Fatal("no card after the claim")
	}
}

// R4: a box that was claimed and lost claim.json routes to "already
// claimed, reinstall me": no phone reaches setup or pairs, the claim is
// refused, finish waits for ever and the vault is never reset.
func TestALostClaimStateRoutesToReinstall(t *testing.T) {
	b := sealedClaimBox(t)
	cs := startClaimSetup(t, b)
	owner := &phone{ip: "10.42.0.23:51000"}
	if w := owner.do(t, cs.ui, "POST", "/claim", url.Values{"code": {b.code}}); w.Code != http.StatusSeeOther {
		t.Fatalf("claim: %d", w.Code)
	}
	if err := cs.f.confirm(t, cs.firstBoot().Card.(*firstboot.ClaimedCard).Card()); err != nil {
		t.Fatal(err)
	}
	resets := cs.f.vault.resets

	b.claim = change.MemStore{} // claim.json lost
	cs2 := startClaimSetup(t, b)
	if fb := cs2.firstBoot(); fb.Route != firstboot.RouteReinstall {
		t.Fatalf("route %q", fb.Route)
	}
	for _, p := range []*phone{owner, {ip: "10.42.0.77:52000"}} {
		for _, path := range []string{"/setup", "/setup/approvals", "/setup/card"} {
			w := p.do(t, cs2.ui, "GET", path, nil)
			if body := w.Body.String(); w.Code != http.StatusForbidden || !strings.Contains(body, "already claimed") || !strings.Contains(body, "reinstall me") {
				t.Fatalf("GET %s: %d", path, w.Code)
			} else if strings.Contains(body, "Setup continues") { // R4: no phone holds this setup
				t.Fatalf("GET %s on a reinstall box points at a claiming phone: %s", path, body)
			}
		}
		if w := p.do(t, cs2.ui, "POST", "/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}}); w.Code != http.StatusForbidden {
			t.Fatalf("setup post: %d", w.Code)
		}
		w := p.do(t, cs2.ui, "POST", "/claim", url.Values{"code": {b.code}})
		if w.Code != http.StatusConflict || len(w.Result().Cookies()) != 0 {
			t.Fatalf("claim on a reinstall box: %d", w.Code)
		}
		reinstallOnly(t, "POST /claim", w.Body.String())
		reinstallOnly(t, "GET /claim", p.do(t, cs2.ui, "GET", "/claim", nil).Body.String())
	}
	err := setupCall(t, cs2.m)(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil)
	if err == nil || !strings.Contains(err.Error(), errCardPending) {
		t.Fatalf("finish on a reinstall box: %v", err)
	}
	if !errors.Is(cs2.firstBoot().Card.Hold(), firstboot.ErrReinstall) {
		t.Fatalf("hold %v", cs2.firstBoot().Card.Hold())
	}
	if cs2.f.vault.resets != 0 || cs.f.vault.resets != resets {
		t.Fatal("a reinstall box reset its vault")
	}
}

// reinstallOnly checks a reinstall box's claim page says only "already
// claimed, reinstall me" (R4), never that a phone continues setup.
func reinstallOnly(t *testing.T, what, body string) {
	t.Helper()
	if !strings.Contains(body, "I am already claimed. To set me up again, reinstall me.") || strings.Contains(body, "Setup continues") || strings.Contains(body, "<form") {
		t.Fatalf("%s on a reinstall box: %s", what, body)
	}
}

// A bare flasher install of the download's image (no claim state, no
// latch) takes the download path: no claim screen, the card at once.
func TestABareInstallTakesTheDownloadPath(t *testing.T) {
	cs := startClaimSetup(t, &claimBox{download: true})
	fb := cs.firstBoot()
	if fb.Route != firstboot.RouteDownload || fb.Claim != nil {
		t.Fatalf("route %q", fb.Route)
	}
	p := &phone{ip: "10.42.0.23:51000"}
	if w := p.do(t, cs.ui, "GET", "/setup", nil); w.Code != http.StatusOK {
		t.Fatalf("setup on a download box: %d", w.Code)
	}
	if w := p.do(t, cs.ui, "GET", "/claim", nil); w.Code == http.StatusOK {
		t.Fatalf("claim screen on a download box: %d", w.Code)
	}
	if fb.Card.Display() == nil {
		t.Fatal("no card on a download box")
	}
}

// ARC-2: the claim and card code runs in the page's process; agentosd
// links neither (its tests may).
func TestAgentosdLinksNoClaimOrCard(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		for _, bad := range []string{"/broker/card", "/broker/firstboot", "/broker/claim", "/broker/localui"} {
			if strings.HasSuffix(p, bad) {
				t.Errorf("agentosd links %s", p)
			}
		}
	}
}
