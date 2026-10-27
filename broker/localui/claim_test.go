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
	if w := r.post("/setup/number", url.Values{"number": {ownerNum}}); w.Code != 403 {
		t.Fatalf("setup post before the claim: %d", w.Code)
	}
	if len(r.hooks.sent) != 0 {
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
	if w := r.do("GET", "/setup", nil); w.Code != 403 || !strings.Contains(w.Body.String(), "already claimed") || !strings.Contains(w.Body.String(), "Setup continues on the phone that claimed me") {
		t.Fatalf("other phone's setup page: %d %s", w.Code, w.Body.String())
	}
	if w := r.post("/setup/number", url.Values{"number": {ownerNum}}); w.Code != 403 {
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
	w := r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-EEEE"}})
	if w.Code != 423 || !strings.Contains(w.Body.String(), "Restart me") {
		t.Fatalf("a code while locked: %d %s", w.Code, w.Body.String())
	}
	// Restarting the UI alone does not lift the lock; restarting the box does.
	r.reopen()
	if w := r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}); w.Code != 423 {
		t.Fatalf("after a UI restart: %d", w.Code)
	}
	r.boot = "boot-2"
	r.reopen()
	if w := r.post("/claim", url.Values{"code": {claimCode}}); w.Code != 303 {
		t.Fatalf("after a box restart: %d %s", w.Code, w.Body.String())
	}
}

// R3 (CTRL-claim-wire): after three locks each boot allows one wrong
// code. Another client on the Wi-Fi that posts one after every restart
// does not lock out the phone holding the sticker: the locked page still
// takes the sticker's code, which claims the box.
func TestALockedScreenStillTakesTheStickersCode(t *testing.T) {
	r := newClaimRig(t)
	for boot := 1; boot <= 3; boot++ {
		r.boot = "boot-" + string(rune('0'+boot))
		r.reopen()
		for i := 0; i < claim.MaxWrong && r.srv.cfg.Claim.Status().TriesLeft > 0; i++ {
			r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}})
		}
	}
	r.boot = "boot-4"
	r.reopen()
	owner := r.jar
	r.otherPhone()
	if w := r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}); w.Code != 423 {
		t.Fatalf("the other client's try: %d", w.Code)
	}
	r.jar, r.ip = owner, phoneIP
	page := r.get("/claim")
	if !strings.Contains(page, "Restart me") || !strings.Contains(page, "If you hold my sticker") || !strings.Contains(page, `action="/claim"`) {
		t.Fatalf("locked page offers the sticker holder nothing: %s", page)
	}
	// A typo in the last group spends a reserve try, not the lock.
	w := r.post("/claim", url.Values{"code": {claimCode[:len(claimCode)-1] + "3"}})
	if w.Code != 422 || !strings.Contains(w.Body.String(), "did not match") {
		t.Fatalf("the owner's typo: %d %s", w.Code, w.Body.String())
	}
	if w := r.post("/claim", url.Values{"code": {claimCode}}); w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatalf("the sticker's code on a burned boot: %d %s", w.Code, w.Body.String())
	}
	if w := r.do("GET", "/setup", nil); w.Code != 200 {
		t.Fatalf("claimant's setup: %d", w.Code)
	}
}

// Condition 1 of the brief: /claim is the setup server's own page, behind
// its access-point and Host checks, so only a client on the box's Wi-Fi,
// asking for the box by its address, reaches the counter.
func TestClaimIsOnlyOnTheBoxsWiFi(t *testing.T) {
	r := newClaimRig(t)
	foreign := func(q *http.Request) { q.Host = "attacker.example" }
	if w := r.do("GET", "/claim", nil, foreign); w.Code == 200 {
		t.Fatalf("GET with a foreign Host: %d", w.Code)
	}
	if w := r.do("POST", "/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}, foreign); w.Code != 403 {
		t.Fatalf("POST with a foreign Host: %d", w.Code)
	}
	r.ip = "192.168.1.20:40000"
	if w := r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}); w.Code != 403 {
		t.Fatalf("POST from off the Wi-Fi: %d", w.Code)
	}
	if st := r.srv.cfg.Claim.Status(); st.Claimed || st.TriesLeft != claim.MaxWrong {
		t.Fatalf("a refused request reached the counter: %+v", st)
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
