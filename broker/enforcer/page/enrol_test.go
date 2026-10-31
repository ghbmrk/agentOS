package page

// REQ: NET-4, NET-6, HW-10

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
)

// caseCode is a synthetic canary, never a real code.
const caseCode = "CANARY-CASE-CODE-AAAA-BBBB"

type fakeNetwork struct{ n int }

func (f *fakeNetwork) Replace() (enrol.Card, error) {
	f.n++
	// A synthetic canary password, never a real one.
	return enrol.Card{SSID: "Home", Shown: "CANA RYOW NER0", QR: "WIFI:T:WPA;S:Home;P:CANARYOWNER0;;"}, nil
}

type nopAlerts struct{ recovery bool }

func (n *nopAlerts) Raise(alert.Kind, string) (alert.Record, error) { return alert.Record{}, nil }
func (n *nopAlerts) Recovery(p bool)                                { n.recovery = p }

// enrolRig is a page in factory state over a real enrolment book and
// policy engine.
type enrolRig struct {
	*rig
	book *enrol.Book
	cert Cert
}

func newEnrolRig(t *testing.T) *enrolRig {
	t.Helper()
	bs := &memStore{}
	if err := enrol.Provision(bs, caseCode, nil); err != nil {
		t.Fatal(err)
	}
	g := &enrolRig{rig: &rig{t: t, now: time.UnixMilli(1_800_000_000_000), remote: ownerAddr, ch: &fakeChannel{}}}
	b, err := enrol.Open(enrol.Config{Name: rp, Store: bs, Network: &fakeNetwork{}, Alerts: &nopAlerts{}, Now: func() time.Time { return g.now }})
	if err != nil {
		t.Fatal(err)
	}
	if g.e, err = b.OpenPolicy(&memStore{}); err != nil {
		t.Fatal(err)
	}
	g.book = b
	if g.cert, err = NewCert(rp, g.now); err != nil {
		t.Fatal(err)
	}
	g.build()
	return g
}

// build is the daemon building the page for the passkey in force.
func (g *enrolRig) build() {
	g.t.Helper()
	s, err := New(Config{
		Name: rp, Owner: g.book.Owner(), Enrol: g.book, CA: g.cert.Root,
		Addrs:  []netip.AddrPort{netip.AddrPortFrom(ownerAddr, 443)},
		Allow:  []netip.Prefix{netip.PrefixFrom(ownerAddr, 32)},
		Policy: g.e, Channel: g.ch, Cert: g.cert.Leaf, Zone: zone,
		Now: func() time.Time { return g.now },
	})
	if err != nil {
		g.t.Fatal(err)
	}
	g.s = s
}

// enrolAs is the enrolment screen's script for passkey a with code.
func (g *enrolRig) enrolAs(a *authenticator, code string) (int, map[string]any) {
	g.t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&a.priv.PublicKey)
	if err != nil {
		g.t.Fatal(err)
	}
	w := g.do(http.MethodPost, "/enrol/begin", map[string]string{"code": code, "public_key": base64.RawURLEncoding.EncodeToString(der)})
	var b map[string]string
	json.Unmarshal(w.Body.Bytes(), &b)
	if w.Code != http.StatusOK {
		return w.Code, map[string]any{"error": b["error"]}
	}
	as := a.get(b["challenge"])
	as.ID = b["id"]
	w = g.do(http.MethodPost, "/enrol/finish", as)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// tapAct is the home page's act button for action, tapped by a.
func (g *enrolRig) tapAct(a *authenticator, action string) (int, map[string]any) {
	g.t.Helper()
	w := g.do(http.MethodPost, "/challenge", map[string]string{"action": action, "target": ""})
	if w.Code != http.StatusOK {
		return w.Code, nil
	}
	var c map[string]string
	json.Unmarshal(w.Body.Bytes(), &c)
	as := a.get(c["challenge"])
	as.ID = c["id"]
	body := map[string]any{"id": as.ID, "action": action, "authenticator_data": as.AuthenticatorData, "client_data_json": as.ClientDataJSON, "signature": as.Signature}
	w = g.do(http.MethodPost, "/act", body)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// TestEnrolmentScreens: in factory state only the enrolment screens
// answer; the case code and a new passkey's tap enrol it and show the
// recovery code and the Owner network once; a recovery shows on the home
// page with a cancel, and once it applies the old passkey's page takes no
// tap; the new passkey keeps the policy; a reset leaves only enrolment.
func TestEnrolmentScreens(t *testing.T) {
	g := newEnrolRig(t)
	if w := g.do(http.MethodGet, "/", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/enrol" {
		t.Errorf("home in factory state: %d", w.Code)
	}
	for _, p := range []string{"/p?d=e30", "/a"} {
		if w := g.do(http.MethodGet, p, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s in factory state: %d", p, w.Code)
		}
	}
	w := g.do(http.MethodGet, "/enrol", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Code printed inside the enforcer's case") ||
		w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("enrolment screen: %d\n%s", w.Code, w.Body)
	}
	if w := g.do(http.MethodGet, "/enrol/enforcer.crt", nil); w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Errorf("certificate: %d", w.Code)
	}
	// From another segment, nothing answers.
	g.remote = others["household"]
	func() {
		defer func() { recover() }()
		g.do(http.MethodGet, "/enrol", nil)
		t.Error("the enrolment screen answered the Household network")
	}()
	g.remote = ownerAddr

	a := newAuthenticator(t)
	if code, out := g.enrolAs(a, "WRONG"); code != http.StatusForbidden {
		t.Errorf("wrong code: %d %v", code, out)
	}
	// A cross-origin post is refused before the book sees it.
	der, _ := x509.MarshalPKIXPublicKey(&a.priv.PublicKey)
	if w := g.do(http.MethodPost, "/enrol/begin", map[string]string{"code": caseCode, "public_key": base64.RawURLEncoding.EncodeToString(der)},
		"Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin begin: %d", w.Code)
	}
	code, out := g.enrolAs(a, caseCode)
	if code != http.StatusOK {
		t.Fatalf("enrol: %d %v", code, out)
	}
	net, _ := out["network"].(map[string]any)
	if rec, _ := out["recovery"].(string); len(strings.ReplaceAll(rec, " ", "")) != enrol.CodeLen || net["ssid"] != "Home" || net["qr"] == nil {
		t.Fatalf("enrolment result %v", out)
	}
	recovery := strings.ReplaceAll(out["recovery"].(string), " ", "")
	// The page built before enrolment still takes no tap; the daemon
	// builds it again for the passkey in force.
	if w := g.do(http.MethodGet, "/", nil); w.Code != http.StatusSeeOther {
		t.Errorf("stale page: %d", w.Code)
	}
	g.build()
	if w := g.do(http.MethodGet, "/", nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "Keep my rules") {
		t.Fatalf("home after enrolment: %d\n%s", w.Code, w.Body)
	}

	// a puts a policy in force.
	_, id, ch := g.open(home(0), "add the tv")
	if w := g.approve(id, a.get(ch)); w.Code != http.StatusOK {
		t.Fatalf("owner's approval: %d %s", w.Code, w.Body)
	}
	g.now = g.now.Add(enrol.Wait)
	if _, err := g.e.Tick(g.now.UnixMilli()); err != nil || g.e.Current().Device("tv") == nil {
		t.Fatalf("policy not in force: %v", err)
	}

	// A recovery shows on the home page and a's tap cancels it.
	b := newAuthenticator(t)
	if code, out := g.enrolAs(b, recovery); code != http.StatusOK || out["due"] == nil || out["network"] != nil {
		t.Fatalf("recovery: %d %v", code, out)
	}
	if w := g.do(http.MethodGet, "/", nil); !strings.Contains(w.Body.String(), "Cancel the recovery") || !strings.Contains(w.Body.String(), "PST") {
		t.Errorf("home does not show the recovery:\n%s", w.Body)
	}
	if code, _ := g.tapAct(b, ActCancelRecovery); code != http.StatusForbidden {
		t.Errorf("the waiting passkey cancelled: %d", code)
	}
	code, out = g.tapAct(a, ActCancelRecovery)
	fresh, _ := out["recovery"].(string)
	if code != http.StatusOK || len(strings.ReplaceAll(fresh, " ", "")) != enrol.CodeLen {
		t.Fatalf("cancel: %d %v", code, out)
	}
	if _, ok := g.book.Recovery(); ok {
		t.Fatal("recovery still waiting after cancel")
	}
	// The code that started it is spent; the owner was shown its successor.
	if code, _ := g.enrolAs(b, recovery); code != http.StatusForbidden {
		t.Errorf("spent recovery code: %d", code)
	}
	recovery = strings.ReplaceAll(fresh, " ", "")

	// Uncancelled, it applies after the wait; a's page takes no tap.
	if code, _ := g.enrolAs(b, recovery); code != http.StatusOK {
		t.Fatal(code)
	}
	g.now = g.now.Add(enrol.Wait)
	if done, err := g.book.Tick(); !done || err != nil {
		t.Fatalf("tick: %v %v", done, err)
	}
	if code, _ := g.tapAct(a, ActKeep); code != http.StatusForbidden {
		t.Errorf("old passkey's page after recovery: %d", code)
	}
	g.build()
	if w := g.do(http.MethodGet, "/", nil); !strings.Contains(w.Body.String(), "Keep my rules") {
		t.Errorf("home does not ask to keep the rules:\n%s", w.Body)
	}
	if code, _ := g.tapAct(a, ActKeep); code != http.StatusForbidden {
		t.Errorf("old passkey kept: %d", code)
	}
	if code, _ := g.tapAct(b, ActKeep); code != http.StatusOK || !g.book.Kept() {
		t.Fatalf("keep: %d", code)
	}
	// The policy is b's: b approves a change.
	next := home(0)
	next.Devices[0].Allow = append(next.Devices[0].Allow, "tv2.example")
	_, id, ch = g.open(next, "widen the tv")
	if w := g.approve(id, b.get(ch)); w.Code != http.StatusOK {
		t.Errorf("new owner's approval: %d %s", w.Code, w.Body)
	}

	// A factory reset by the case code leaves only enrolment.
	if w := g.do(http.MethodPost, "/enrol/reset", map[string]string{"code": recovery}); w.Code == http.StatusOK {
		t.Error("reset by a wrong code")
	}
	if w := g.do(http.MethodPost, "/enrol/reset", map[string]string{"code": caseCode}); w.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	if code, _ := g.tapAct(b, ActResume); code != http.StatusForbidden {
		t.Errorf("tap after reset: %d", code)
	}
	if w := g.do(http.MethodGet, "/enrol", nil); !strings.Contains(w.Body.String(), "factory reset") {
		t.Errorf("enrolment screen after reset:\n%s", w.Body)
	}
}
