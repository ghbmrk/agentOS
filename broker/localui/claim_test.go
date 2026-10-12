package localui

// REQ: HW-10

import (
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
)

// claimCode is a synthetic sticker code.
const claimCode = "CANA-RYCL-AXMC-KDE2"

// boxClaim is what firstboot.ClaimedCard gives the UI, without the card.
type boxClaim struct{ cl *claim.Claim }

func (b boxClaim) Status() claim.Status              { return b.cl.Status() }
func (b boxClaim) Claim(code string) (string, error) { return b.cl.Try(code) }
func (b boxClaim) Claimant(tok string) bool          { return b.cl.Claimant(tok) }

// claimRig is a rig whose box waits to be claimed; boot is its kernel
// boot ID and reopen starts the UI again from the same disk.
type claimRig struct {
	*rig
	st   change.FileStore
	boot string
}

func newClaimRig(t *testing.T) *claimRig {
	t.Helper()
	cr := &claimRig{rig: newRig(t), st: change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")}, boot: "boot-1"}
	if err := claim.Seal(cr.st, claimCode, rand.New(rand.NewSource(3)), nil); err != nil {
		t.Fatal(err)
	}
	cr.reopen()
	return cr
}

func (cr *claimRig) reopen() {
	cr.t.Helper()
	cl, err := claim.Open(claim.Config{Store: cr.st, BootID: func() (string, error) { return cr.boot, nil },
		Rand: rand.New(rand.NewSource(4))})
	if err != nil {
		cr.t.Fatal(err)
	}
	s, err := New(Config{AP: testAP(), Hooks: cr.hooks, SetupSecret: cr.card.SetupSecret, Store: &MemStore{},
		Claim: boxClaim{cl}, Now: cr.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		cr.t.Fatal(err)
	}
	cr.srv = s
}

// otherPhone switches the rig to a second phone on the box's Wi-Fi.
func (cr *claimRig) otherPhone() {
	cr.jar, _ = cookiejar.New(nil)
	cr.ip = "10.42.0.77:52000"
}

func TestSetupWaitsForClaim(t *testing.T) {
	r := newClaimRig(t)
	for _, p := range []string{"/", "/setup"} {
		if w := r.do("GET", p, nil); w.Code != 303 || w.Header().Get("Location") != "/claim" {
			t.Fatalf("GET %s before the claim: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}}); w.Code != 403 {
		t.Fatalf("setup post before the claim: %d", w.Code)
	}
	if r.hooks.joined != "" {
		t.Fatal("a setup step ran before the claim")
	}
	if !strings.Contains(r.get("/claim"), "claim code from the sticker") {
		t.Fatal("claim page does not ask for the sticker code")
	}
	// The sticker's QR link fills the form in; only pressing Claim tries it.
	if !strings.Contains(r.get("/claim?code="+claimCode), `value="`+claimCode+`"`) || r.srv.cfg.Claim.Status().Claimed {
		t.Fatal("the QR link did not prefill the form, or claimed on GET")
	}

	// A wrong code is refused and counted.
	w := r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}})
	if w.Code != 422 || !strings.Contains(w.Body.String(), "4 wrong codes left") {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	}

	// The right code, typed loosely, claims the box for this phone.
	w = r.post("/claim", url.Values{"code": {"cana rycl axmc kde2"}})
	if w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatalf("right code: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := r.do("GET", "/setup", nil); w.Code != 200 {
		t.Fatalf("claimant's setup page: %d", w.Code)
	}
	if w := r.do("GET", "/claim", nil); w.Code != 303 {
		t.Fatalf("claimant's claim page: %d", w.Code)
	}

	// Another phone on the Wi-Fi can neither set up nor claim again, also
	// after a restart.
	r.reopen()
	r.otherPhone()
	if w := r.do("GET", "/setup", nil); w.Code != 403 || !strings.Contains(w.Body.String(), "already claimed") {
		t.Fatalf("other phone's setup page: %d %s", w.Code, w.Body.String())
	}
	if w := r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}}); w.Code != 403 {
		t.Fatalf("other phone's setup post: %d", w.Code)
	}
	w = r.post("/claim", url.Values{"code": {claimCode}})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "already claimed") {
		t.Fatalf("second claim: %d %s", w.Code, w.Body.String())
	}
	if c := w.Result().Cookies(); len(c) != 0 {
		t.Fatalf("second claim set cookies: %v", c)
	}
	// A forged claimant cookie is not the claimant.
	w = r.do("GET", "/setup", nil, func(q *http.Request) {
		q.AddCookie(&http.Cookie{Name: claimCookie, Value: strings.Repeat("0", 64)})
	})
	if w.Code != 403 {
		t.Fatalf("forged claimant cookie: %d", w.Code)
	}
}

func TestClaimScreenLocksUntilRestart(t *testing.T) {
	r := newClaimRig(t)
	for i := 0; i < claim.MaxWrong; i++ {
		r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}})
	}
	w := r.post("/claim", url.Values{"code": {claimCode}})
	if w.Code != 423 || !strings.Contains(w.Body.String(), "Restart me") {
		t.Fatalf("right code while locked: %d %s", w.Code, w.Body.String())
	}
	// Restarting the UI alone does not lift the lock; restarting the box does.
	r.reopen()
	if w := r.post("/claim", url.Values{"code": {claimCode}}); w.Code != 423 {
		t.Fatalf("after a UI restart: %d", w.Code)
	}
	r.boot = "boot-2"
	r.reopen()
	if w := r.post("/claim", url.Values{"code": {claimCode}}); w.Code != 303 {
		t.Fatalf("after a box restart: %d %s", w.Code, w.Body.String())
	}
}

func TestClaimRefusesCrossSitePost(t *testing.T) {
	r := newClaimRig(t)
	w := r.do("POST", "/claim", url.Values{"code": {claimCode}}, func(q *http.Request) {
		q.Header.Set("Origin", "http://evil.example")
	})
	if w.Code != 403 || r.srv.cfg.Claim.Status().Claimed {
		t.Fatalf("cross-site claim: %d claimed=%v", w.Code, r.srv.cfg.Claim.Status().Claimed)
	}
}
