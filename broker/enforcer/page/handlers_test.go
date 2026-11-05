package page

// REQ: NET-4, NET-6, NET-2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// answer is the one JSON value w holds: a handler that answers twice (an
// error, then carrying on) is caught here.
func answer(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(w.Body.Bytes()))
	var out map[string]any
	if err := dec.Decode(&out); err != nil || dec.More() {
		t.Fatalf("not one JSON answer (%v): %q", err, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("a JSON answer typed %q", ct)
	}
	return out
}

// within fails t if f does not return in time: a lock the page left held
// hangs the next request.
func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the page hangs; a lock was left held", what)
	}
}

// NET-4: the page's answers each carry every header that keeps them out
// of frames, caches and other origins, and it serves its script and style
// typed, and nothing at any other path.
func TestHeadersAndStatic(t *testing.T) {
	g := newRig(t)
	w := g.do(http.MethodGet, "/", nil)
	for k, v := range map[string]string{
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cache-Control":                "no-store",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s: %q, want %q", k, got, v)
		}
	}
	for path, ct := range map[string]string{"/page.js": "text/javascript; charset=utf-8", "/page.css": "text/css; charset=utf-8"} {
		want, err := files.ReadFile("static" + path)
		if err != nil {
			t.Fatal(err)
		}
		w := g.do(http.MethodGet, path, nil)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != ct || !bytes.Equal(w.Body.Bytes(), want) {
			t.Errorf("%s: %d %q, %d bytes, want %d", path, w.Code, w.Header().Get("Content-Type"), w.Body.Len(), len(want))
		}
	}
	if w := g.do(http.MethodGet, "/nothing", nil); w.Code != http.StatusNotFound {
		t.Errorf("/nothing: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	g.s.static(w, httptest.NewRequest(http.MethodGet, "https://"+rp+"/nothing.js", nil))
	if w.Code != http.StatusNotFound || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("a missing static file: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	// A refused request is answered once, with the refusal alone.
	if w := g.do(http.MethodGet, "/", nil, "Host", "other.example"); w.Code != http.StatusMisdirectedRequest || w.Body.String() != "wrong host\n" {
		t.Errorf("another host: %d %q", w.Code, w.Body)
	}
	if w := g.do(http.MethodPost, "/approve", map[string]string{}, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden || w.Body.String() != "cross-origin\n" {
		t.Errorf("cross-site post: %d %q", w.Code, w.Body)
	}
	// sameOrigin holds the same line itself.
	r := httptest.NewRequest(http.MethodPost, "https://"+rp+"/approve", nil)
	r.Header.Set("Origin", "https://"+rp)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-site")
	if g.s.sameOrigin(r) {
		t.Error("sameOrigin took a same-site request")
	}
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if !g.s.sameOrigin(r) {
		t.Error("sameOrigin refused the page's own request")
	}
	// Home says an open channel is open.
	if body := g.do(http.MethodGet, "/", nil).Body.String(); !strings.Contains(body, "The channel is open.") {
		t.Errorf("home does not say the channel is open:\n%s", body)
	}
}

// Before a passkey is enrolled the enrolment screen and the static files
// are answered once each, and a missing certificate is not found.
func TestEnrolScreensAnswerOnce(t *testing.T) {
	g := newEnrolRig(t)
	want, _ := files.ReadFile("static/page.js")
	if w := g.do(http.MethodGet, "/page.js", nil); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), want) {
		t.Errorf("/page.js before enrolment: %d, %d bytes, want %d", w.Code, w.Body.Len(), len(want))
	}
	if w := g.do(http.MethodGet, "/enrol", nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "404 page not found") {
		t.Errorf("/enrol: %d\n%s", w.Code, w.Body)
	}
	if w := g.do(http.MethodGet, "/enrol/core.crt", nil); w.Code != http.StatusNotFound {
		t.Errorf("no core certificate served: %d %q", w.Code, w.Body)
	}
	w := g.do(http.MethodGet, "/enrol/enforcer.crt", nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/x-x509-ca-cert" || !bytes.Equal(w.Body.Bytes(), g.cert.Root) {
		t.Errorf("enforcer certificate: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

// New refuses a config that names no DNS name, no policy, or an allowed
// prefix that is invalid or everything, even where no passkey is checked;
// a nil clock is the system's.
func TestNewRefusesBadConfig(t *testing.T) {
	g := newEnrolRig(t)
	base := g.s.cfg
	base.Lock = nil
	for name, f := range map[string]func(c *Config){
		"bad name":         func(c *Config) { c.Name = "Enforcer_Home" },
		"no policy":        func(c *Config) { c.Policy = nil },
		"allow everything": func(c *Config) { c.Allow = append(c.Allow, netip.MustParsePrefix("0.0.0.0/0")) },
		"invalid allow":    func(c *Config) { c.Allow = append(c.Allow, netip.Prefix{}) },
	} {
		c := base
		c.Allow = append([]netip.Prefix(nil), base.Allow...)
		f(&c)
		if _, err := New(c); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := base
	c.Now = nil
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(time.UnixMilli(s.nowMS())); d < 0 || d > time.Minute {
		t.Errorf("a nil clock reads %v off", d)
	}
	for _, n := range []string{"", ".home.arpa", "home.arpa.", "Home.arpa", "home_arpa", strings.Repeat("a", 254)} {
		if dnsName(n) {
			t.Errorf("dnsName(%q)", n)
		}
	}
	if !dnsName(rp) {
		t.Errorf("dnsName(%q) is false", rp)
	}
	if !allowed([]netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}, netip.MustParseAddr("::ffff:127.0.0.2")) {
		t.Error("an IPv4-mapped address is not the IPv4 address it maps")
	}
}

// NET-4: a link whose encoding is corrupt after a whole document is
// malformed, not the document before the corruption.
func TestCorruptLinkRefused(t *testing.T) {
	g := newRig(t)
	for n := 0; ; n++ {
		next := edit(2, func(d *policy.Document) { d.Destinations = append(d.Destinations, strings.Repeat("b", n+1)+".example") })
		b, err := policy.Encode(next)
		if err != nil {
			t.Fatal(err)
		}
		if len(b)%3 != 0 {
			continue // the corruption must follow whole groups to decode a document
		}
		link := "/p?d=" + base64.RawURLEncoding.EncodeToString(b) + "*"
		if w := g.do(http.MethodGet, link, nil); w.Code != http.StatusBadRequest || reChal.MatchString(w.Body.String()) {
			t.Errorf("a corrupt link: %d %s", w.Code, w.Body)
		}
		return
	}
}

// NET-4: an assertion with a field whose encoding is corrupt after whole
// bytes is refused, never read as the bytes before the corruption.
func TestCorruptAssertionRefused(t *testing.T) {
	a := newAuthenticator(t)
	for {
		as := a.get("Y2hhbGxlbmdl")
		if _, _, err := parseAssertion(as); err != nil {
			t.Fatal(err)
		}
		sig, _ := base64.RawURLEncoding.DecodeString(as.Signature)
		if len(sig)%3 != 0 {
			continue
		}
		as.Signature += "*"
		if _, _, err := parseAssertion(as); !errors.Is(err, errRefused) {
			t.Errorf("a corrupt signature: %v", err)
		}
		return
	}
}

// NET-4: challenge IDs are random and distinct; at most MaxLive are live,
// and an expired one is dropped to make room.
func TestChallengesBounded(t *testing.T) {
	g := newRig(t)
	next := edit(2, func(d *policy.Document) { d.Destinations = append(d.Destinations, "b.example") })
	seen := map[string]bool{}
	for i := 0; i < MaxLive; i++ {
		if i > 0 && i%LinkLimit == 0 {
			g.now = g.now.Add(LinkWindow)
		}
		_, id, _ := g.open(next, "")
		if seen[id] || strings.Trim(id, "0") == "" {
			t.Fatalf("challenge ID %q again or blank", id)
		}
		seen[id] = true
	}
	if w := g.do(http.MethodGet, linkFor(next, ""), nil); w.Code != http.StatusTooManyRequests || w.Body.String() != errLimited.Error()+"\n" {
		t.Errorf("challenge %d: %d %s", MaxLive+1, w.Code, w.Body)
	}
	if w := g.do(http.MethodPost, "/challenge", map[string]string{"action": ActResume}); w.Code != http.StatusTooManyRequests {
		t.Errorf("an action challenge past MaxLive: %d %s", w.Code, w.Body)
	} else {
		answer(t, w)
	}
	g.now = g.now.Add(ChalLife)
	g.open(next, "")
	// The link limit refused, the page still answers.
	g.now = g.now.Add(LinkWindow)
	for i := 0; i < LinkLimit; i++ {
		g.do(http.MethodGet, linkFor(next, ""), nil)
	}
	if w := g.do(http.MethodGet, linkFor(next, ""), nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("link %d: %d", LinkLimit+1, w.Code)
	}
	within(t, "home after the link limit", func() { g.do(http.MethodGet, "/", nil) })
}

// version draws above a loosening waiting with a higher version than any
// the page drew.
func TestVersionAbovePending(t *testing.T) {
	g := newRig(t)
	high := uint64(g.now.UnixMilli()) * 10
	b, err := policy.Encode(home(high))
	if err != nil {
		t.Fatal(err)
	}
	if v := g.s.version(home(1), []policy.Pending{{Signed: policy.Signed{Doc: b}}}); v <= high {
		t.Errorf("version %d, not above the pending %d", v, high)
	}
}

// heard returns the canonical document, and a heard name the policy
// refuses is refused with the policy's reason.
func TestHeardCanonical(t *testing.T) {
	g := newRig(t)
	g.heard["vlan104"] = [][]string{{"zz", "local"}, {"a", "_http", "_tcp", "local"}}
	next, _, err := g.s.heard(home(1), pairedTV(2))
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Encode(next)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := policy.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := next.Device("tv").MDNS, canon.Device("tv").MDNS; len(got) != 2 || !equalNames(got, want) {
		t.Errorf("heard's tv pins %q, canonical %q", got, want)
	}
	g.heard["vlan104"] = [][]string{{"_bad", "local"}}
	if _, _, err := g.s.heard(home(1), pairedTV(2)); err == nil || !strings.Contains(err.Error(), "mDNS name") {
		t.Errorf("a malformed heard name: %v", err)
	}
}

func equalNames(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.Join(a[i], ".") != strings.Join(b[i], ".") {
			return false
		}
	}
	return true
}

// NET-4: an approve answer is one JSON value: a refused tap, an unknown
// field, a loosening while another waits each answer only their refusal,
// and a loosening's answer names the one now waiting.
func TestApproveAnswers(t *testing.T) {
	g := newRig(t)
	addB := edit(2, func(d *policy.Document) { d.Destinations = append(d.Destinations, "b.example") })
	addC := edit(2, func(d *policy.Document) { d.Destinations = append(d.Destinations, "c.example") })
	_, idB, chB := g.open(addB, "")

	bad := g.a.get(chB)
	bad.ID = idB
	if w := g.do(http.MethodPost, "/approve", map[string]any{"id": idB, "authenticator_data": bad.AuthenticatorData, "client_data_json": bad.ClientDataJSON, "signature": bad.Signature, "extra": 1}); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown field: %d %s", w.Code, w.Body)
	}
	_, idB, chB = g.open(addB, "")
	other := newAuthenticator(t)
	if w := g.approve(idB, other.get(chB)); w.Code != http.StatusForbidden || answer(t, w)["error"] != errRefused.Error() {
		t.Errorf("another passkey: %d %s", w.Code, w.Body)
	}
	_, idB, chB = g.open(addB, "")
	w := g.approve(idB, g.a.get(chB))
	if w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if p := g.e.Pending(); len(p) != 1 || answer(t, w)["pending"] != p[0].ID {
		t.Errorf("the answer names %v, waiting %+v", answer(t, w)["pending"], p)
	}
	// The screen withholds the button while B waits; a tap posted anyway
	// is refused.
	if w := g.do(http.MethodGet, linkFor(addC, ""), nil); w.Code != http.StatusOK || reChal.MatchString(w.Body.String()) {
		t.Fatalf("a blocked screen: %d %s", w.Code, w.Body)
	}
	var idC, chC string
	for id, c := range g.s.chals {
		if strings.Contains(string(c.prop.Diff), "c.example") {
			idC, chC = id, chal(c.msg)
		}
	}
	if w := g.approve(idC, g.a.get(chC)); w.Code != http.StatusConflict || !strings.Contains(answer(t, w)["error"].(string), "another loosening is waiting") {
		t.Errorf("a second loosening: %d %s", w.Code, w.Body)
	}
}

// fakeSecrets is a device-secret store whose Admit fails with admit,
// counting Prune calls.
type fakeSecrets struct {
	admit  error
	prunes int
}

func (f *fakeSecrets) Admit(string, []byte, policy.Proposal, []byte) error { return f.admit }
func (f *fakeSecrets) Prune() error                                        { f.prunes++; return nil }

// NET-2 slice r: an approve prunes the store once, whatever happened; an
// envelope that does not hash to the link's, or one the store refuses,
// gets one refusal.
func TestApprovePrunesOnce(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		g := newRig(t)
		fs := &fakeSecrets{}
		if refuse {
			fs.admit = errors.New("refused")
		}
		cfg := g.s.cfg
		cfg.Secrets, cfg.Lock = fs, nil
		var err error
		if g.s, err = New(cfg); err != nil {
			t.Fatal(err)
		}
		env := []byte("SYNTHETIC-ENVELOPE")
		link := sealedLink(addFront, "front", pairseal.HashHex(env))
		_, id, ch := g.openSealed(link)
		if w := g.approveSealed(id, g.a.get(ch), []byte("other")); w.Code != http.StatusBadRequest || answer(t, w)["error"] != errSealed.Error() {
			t.Errorf("a wrong envelope: %d %s", w.Code, w.Body)
		}
		_, id, ch = g.openSealed(link)
		w := g.approveSealed(id, g.a.get(ch), env)
		out := answer(t, w)
		switch {
		case refuse && (w.Code != http.StatusConflict || out["error"] != errSealed.Error()):
			t.Errorf("refused: %d %v", w.Code, out)
		case !refuse && w.Code != http.StatusOK:
			t.Errorf("admitted: %d %v", w.Code, out)
		}
		if fs.prunes != 1 {
			t.Errorf("refused %v: pruned %d times", refuse, fs.prunes)
		}
	}
}

// failChannel's Resume fails.
type failChannel struct{}

func (failChannel) Paused() bool  { return true }
func (failChannel) Resume() error { return errors.New("resume failed") }

// NET-4, NET-6: each page action's challenge signs that action, its target
// and its ID; an unknown action, a target where none is taken, or an
// action the page has no state for is refused with one answer; a tap
// whose action fails says so.
func TestChallengeAnswers(t *testing.T) {
	g := newRig(t)
	g.ch.paused = true
	w := g.do(http.MethodPost, "/challenge", map[string]string{"action": ActResume})
	c := answer(t, w)
	if want := chal(actMsg(ActResume, "", c["id"].(string))); w.Code != http.StatusOK || c["challenge"] != want {
		t.Errorf("resume challenge %v, want %s", c, want)
	}
	as := g.a.get(c["challenge"].(string))
	w = g.do(http.MethodPost, "/act", map[string]any{"id": c["id"], "action": ActResume, "authenticator_data": as.AuthenticatorData, "client_data_json": as.ClientDataJSON, "signature": as.Signature})
	if w.Code != http.StatusOK || w.Body.String() != "{\"done\":true}\n" {
		t.Errorf("resume: %d %q", w.Code, w.Body)
	}
	for _, req := range []map[string]string{
		{"action": "bogus"},
		{"action": ActResume, "target": "x"},
		{"action": ActCancel, "target": "nothing"},
		{"action": ActCancelRecovery},
		{"action": ActKeep},
	} {
		w := g.do(http.MethodPost, "/challenge", req)
		if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", req, w.Code, w.Body)
			continue
		}
		answer(t, w)
	}
	// A cancel whose loosening went meanwhile fails at the tap.
	_, id, ch := g.open(edit(2, func(d *policy.Document) { d.Destinations = append(d.Destinations, "b.example") }), "")
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	pid := g.e.Pending()[0].ID
	w = g.do(http.MethodPost, "/challenge", map[string]string{"action": ActCancel, "target": pid})
	c = answer(t, w)
	if err := g.e.Cancel(pid); err != nil {
		t.Fatal(err)
	}
	as = g.a.get(c["challenge"].(string))
	w = g.do(http.MethodPost, "/act", map[string]any{"id": c["id"], "action": ActCancel, "authenticator_data": as.AuthenticatorData, "client_data_json": as.ClientDataJSON, "signature": as.Signature})
	if w.Code != http.StatusConflict {
		t.Errorf("a cancel of a gone loosening: %d %s", w.Code, w.Body)
	}
	answer(t, w)
	// A channel whose resume fails.
	cfg := g.s.cfg
	cfg.Channel, cfg.Lock = failChannel{}, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	w = g.do(http.MethodPost, "/challenge", map[string]string{"action": ActResume})
	c = answer(t, w)
	as = g.a.get(c["challenge"].(string))
	w = g.do(http.MethodPost, "/act", map[string]any{"id": c["id"], "action": ActResume, "authenticator_data": as.AuthenticatorData, "client_data_json": as.ClientDataJSON, "signature": as.Signature})
	if w.Code != http.StatusConflict || answer(t, w)["error"] != "resume failed" {
		t.Errorf("a failed resume: %d %s", w.Code, w.Body)
	}
}

// HW-10: the enrolment routes refuse with one answer each: a malformed or
// wrong-kind key, a wrong code, a corrupt tap, a wrong reset code; no
// recovery to cancel; and a keep once kept.
func TestEnrolRefusals(t *testing.T) {
	g := newEnrolRig(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	a := newAuthenticator(t)
	der, _ := x509.MarshalPKIXPublicKey(&a.priv.PublicKey)
	e := base64.RawURLEncoding.EncodeToString
	for _, c := range []struct {
		name, code, pk, want string
		status               int
	}{
		{"corrupt key", caseCode, e(der) + "*", errMalformed.Error(), http.StatusBadRequest},
		{"P-384 key", caseCode, e(der384), "this passkey's kind is not one the enforcer takes", http.StatusBadRequest},
		{"wrong code", "CANARY-WRONG-CODE", e(der), "", http.StatusForbidden},
	} {
		w := g.do(http.MethodPost, "/enrol/begin", map[string]string{"code": c.code, "public_key": c.pk})
		out := answer(t, w)
		if w.Code != c.status || c.want != "" && out["error"] != c.want {
			t.Errorf("%s: %d %v", c.name, w.Code, out)
		}
	}
	w := g.do(http.MethodPost, "/enrol/finish", assertion{ID: "x", AuthenticatorData: "!", ClientDataJSON: "!", Signature: "!"})
	if out := answer(t, w); w.Code != http.StatusForbidden || out["error"] != errRefused.Error() {
		t.Errorf("a corrupt tap: %d %v", w.Code, out)
	}
	w = g.do(http.MethodPost, "/enrol/reset", map[string]string{"code": "CANARY-WRONG-CODE"})
	if answer(t, w); w.Code == http.StatusOK {
		t.Errorf("a wrong reset code: %d", w.Code)
	}

	f := fullRig(t)
	if w := f.do(http.MethodPost, "/challenge", map[string]string{"action": ActCancelRecovery}); w.Code != http.StatusNotFound || answer(t, w)["error"] != enrol.ErrPhase.Error() {
		t.Errorf("no recovery to cancel: %d %s", w.Code, w.Body)
	}
	if !f.book.Kept() {
		t.Fatal("a first enrolment did not keep the policy")
	}
	if w := f.do(http.MethodPost, "/challenge", map[string]string{"action": ActKeep}); w.Code != http.StatusConflict {
		t.Errorf("keep once kept: %d %s", w.Code, w.Body)
	} else {
		answer(t, w)
	}
	if w := f.do(http.MethodPost, "/enrol/reset", map[string]string{"code": caseCode}); w.Code != http.StatusOK || w.Body.String() != "{\"done\":true}\n" {
		t.Errorf("reset: %d %q", w.Code, w.Body)
	}
	if got := grouped("ABCDEFGHIJ"); got != "ABCD EFGH IJ" {
		t.Errorf("grouped: %q", got)
	}
}

// qrOf draws every module of the code, row by row, and refuses text no
// code holds.
func TestQRModules(t *testing.T) {
	c, err := qrOf("WIFI:T:WPA;S:Home;P:CANARYOWNER0;;")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Modules) != c.Size*c.Size || strings.Trim(c.Modules, "01") != "" || !strings.Contains(c.Modules, "0") || !strings.Contains(c.Modules, "1") {
		t.Fatalf("qr %d: %q", c.Size, c.Modules)
	}
	// The finder pattern: the top-left corner's first row is seven dark modules, then a light one.
	if c.Modules[:8] != "11111110" || c.Modules[c.Size:c.Size+8] != "10000010" {
		t.Errorf("no finder pattern: %q %q", c.Modules[:8], c.Modules[c.Size:c.Size+8])
	}
	if _, err := qrOf(strings.Repeat("A", 8000)); err == nil {
		t.Error("a QR of 8000 characters")
	}
}

// actRig is a live page with asserted actions on act, logging to logs, over
// home(1) with a drone added.
func actRig(t *testing.T, act action.Actuator, logs *[]string) *rig {
	t.Helper()
	g := newRig(t)
	next := edit(2, func(d *policy.Document) {
		d.Devices = append(d.Devices, policy.Device{ID: "drone", Network: policy.NetDevices, WiFi: "vlan120", Class: policy.ClassDrone})
	})
	g.now = g.now.Add(time.Second)
	p := policy.Proposal{Doc: next, Diff: []byte("v2")}
	r, _ := p.Root(g.a.Public())
	if _, err := g.e.Propose(p, g.a.signMsg(key.RootMsg(r)), g.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(time.Duration(policy.Wait) * time.Millisecond)
	if _, err := g.e.Tick(g.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	cfg := g.s.cfg
	var mu sync.Mutex
	cfg.Act, cfg.Log, cfg.Lock = act, func(s string) { mu.Lock(); *logs = append(*logs, s); mu.Unlock() }, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	return g
}

// errActuator fails every act.
type errActuator struct{}

func (errActuator) Act(context.Context, string, action.Act, string) error {
	return errors.New("radio down")
}

// NET-2 slice s: an action link names only d, a and r once each, counts
// against its own limit, names a known act on a device that takes it, and
// shows a drone's route; the page answers after each; a tap on a gone
// challenge is gone, a malformed one malformed, and an act that may have
// run is logged.
func TestActionLinks(t *testing.T) {
	var logs []string
	g := actRig(t, nopActuator{}, &logs)
	for _, bad := range []string{"/a?d=lock&a=unlock&x=1", "/a?d=lock&a=unlock&a=unlock"} {
		if w := g.do(http.MethodGet, bad, nil); w.Code != http.StatusBadRequest || w.Body.String() != errMalformed.Error()+"\n" {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	if w := g.do(http.MethodGet, "/a?d=lock&a=bogus", nil); w.Code != http.StatusBadRequest || w.Body.String() != errMalformed.Error()+"\n" {
		t.Errorf("an unknown act: %d %q", w.Code, w.Body)
	}
	if w := g.do(http.MethodGet, "/a?d=nothing&a=unlock", nil); w.Code != http.StatusBadRequest || reChal.MatchString(w.Body.String()) {
		t.Errorf("an unknown device: %d %s", w.Code, w.Body)
	}
	w := g.do(http.MethodGet, "/a?d=drone&a=fly&r=home-loop", nil)
	if body := html.UnescapeString(w.Body.String()); w.Code != http.StatusOK || !strings.Contains(body, "Fly drone, a drone, on the route home-loop") {
		t.Errorf("a drone's route: %d\n%s", w.Code, body)
	}
	within(t, "home after an action link", func() { g.do(http.MethodGet, "/", nil) })
	// LinkLimit action links a window; a tap on a challenge never drawn is gone.
	g.now = g.now.Add(LinkWindow)
	for i := 1; i < LinkLimit; i++ {
		if w := g.do(http.MethodGet, "/a?d=lock&a=unlock", nil); w.Code != http.StatusOK {
			t.Fatalf("action link %d: %d %s", i, w.Code, w.Body)
		}
	}
	w = g.do(http.MethodGet, "/a?d=lock&a=unlock", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("action link %d: %d", LinkLimit, w.Code)
	}
	if w := g.do(http.MethodGet, "/a?d=lock&a=unlock", nil); w.Code != http.StatusTooManyRequests || w.Body.String() != errLimited.Error()+"\n" {
		t.Errorf("action link %d: %d %q", LinkLimit+1, w.Code, w.Body)
	}
	// MaxLive in the book: 10 + 6 within the window, then the book's limit.
	g.now = g.now.Add(LinkWindow + time.Second)
	for i := 0; i < action.MaxLive-LinkLimit+1; i++ {
		g.do(http.MethodGet, "/a?d=lock&a=unlock", nil)
	}
	if w := g.do(http.MethodGet, "/a?d=lock&a=unlock", nil); w.Code != http.StatusTooManyRequests || w.Body.String() != action.ErrLimited.Error()+"\n" {
		t.Errorf("past the book's limit: %d %s", w.Code, w.Body)
	}
	if w := g.do(http.MethodPost, "/do", map[string]any{"id": "nothing", "x": 1}); w.Code != http.StatusBadRequest {
		t.Errorf("a malformed tap: %d %s", w.Code, w.Body)
	} else {
		answer(t, w)
	}
	if w := g.do(http.MethodPost, "/do", map[string]any{"id": "nothing"}); w.Code != http.StatusGone {
		t.Errorf("a tap on no challenge: %d %s", w.Code, w.Body)
	} else {
		answer(t, w)
	}

	if minutes(2*time.Minute) != "2 minutes" || minutes(time.Minute) != "1 minute" {
		t.Errorf("minutes: %q %q", minutes(2*time.Minute), minutes(time.Minute))
	}
	if !strings.Contains(actConsequence(action.Off), "stop the device's alerts") || !strings.Contains(actConsequence(action.On), "only within") {
		t.Errorf("consequences: %q %q", actConsequence(action.Off), actConsequence(action.On))
	}
}

// NET-2: an act whose actuator fails may have run, so it is logged.
func TestActionMayHaveRunLogged(t *testing.T) {
	var logs []string
	g := actRig(t, errActuator{}, &logs)
	w := g.do(http.MethodGet, "/a?d=lock&a=unlock", nil)
	body := w.Body.String()
	id, ch := reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if id == nil || ch == nil {
		t.Fatalf("no challenge:\n%s", body)
	}
	as := g.a.get(ch[1])
	as.ID = id[1]
	if w := g.do(http.MethodPost, "/do", as); w.Code != http.StatusBadGateway || answer(t, w)["error"] != action.ErrUnsure.Error() {
		t.Errorf("a failed act: %d %s", w.Code, w.Body)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "action: unlock on lock may have run") {
		t.Errorf("logged %q", logs)
	}
}

// #4601: more names heard than a device has room for are offered with
// "and more", and the offer's card says how many are left out.
func TestOfferSaysMore(t *testing.T) {
	g := newRig(t)
	g.heard["vlan104"] = [][]string{{"tv", "local"}}
	_, id, ch := g.open(pairedTV(2), "pair")
	g.sign(id, ch)
	for i := 0; i < policy.MaxMDNS+2; i++ {
		g.heard["vlan104"] = append(g.heard["vlan104"], []string{"n" + strconv.Itoa(100+i), "local"})
	}
	if home := html.UnescapeString(g.do(http.MethodGet, "/", nil).Body.String()); !strings.Contains(home, " and more: let it?") {
		t.Errorf("the offer does not say more:\n%s", home)
	}
	w := g.do(http.MethodGet, "/heard?d=tv", nil)
	if body := html.UnescapeString(w.Body.String()); w.Code != http.StatusOK ||
		!strings.Contains(body, "3 more names tv announces are left out of this change, since one device pins at most 32 names.") {
		t.Errorf("the offer's card: %d\n%s", w.Code, body)
	}
}

// Renew refuses a leaf or a root it cannot read, and a root key that is
// not the root's; NewCert refuses a name a certificate cannot carry,
// naming it.
func TestCertRefusals(t *testing.T) {
	now := time.Now()
	c, err := NewCert(rp, now)
	if err != nil {
		t.Fatal(err)
	}
	late := now.Add(LeafLife)
	bad := c
	bad.Leaf.Certificate = [][]byte{[]byte("not a certificate")}
	if _, err := bad.Renew(rp, late); err == nil {
		t.Error("renewed past an unreadable leaf")
	}
	bad = c
	bad.Root = []byte("not a certificate")
	if _, err := bad.Renew(rp, late); err == nil {
		t.Error("renewed under an unreadable root")
	}
	other, err := NewCert(rp, now)
	if err != nil {
		t.Fatal(err)
	}
	bad = c
	bad.RootKey = other.RootKey
	if got, err := bad.Renew(rp, late); err == nil || !bytes.Equal(got.Leaf.Certificate[0], c.Leaf.Certificate[0]) {
		t.Errorf("renewed under another root's key: %v", err)
	}
	if _, err := NewCert("é.home.arpa", now); err == nil || !strings.Contains(err.Error(), "é.home.arpa") {
		t.Errorf("a name no certificate carries: %v", err)
	}
}

// unhashable is a policy whose document in force cannot be encoded.
type unhashable struct{ Policy }

func (u unhashable) Current() policy.Document {
	d := u.Policy.Current()
	dev(&d, "cam").Control = []policy.Port{{Proto: "sctp", Num: 1}}
	return d
}

// A policy in force the page cannot hash draws no screen: the diff and
// the tap would be against nothing the policy could check.
func TestUnhashablePolicyDrawsNothing(t *testing.T) {
	g := newRig(t)
	cfg := g.s.cfg
	cfg.Policy, cfg.Lock = unhashable{g.e}, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	next := edit(2, func(d *policy.Document) { d.Destinations = append(d.Destinations, "b.example") })
	if w := g.do(http.MethodGet, linkFor(next, ""), nil); w.Code != http.StatusBadRequest || reChal.MatchString(w.Body.String()) {
		t.Errorf("drawn against an unhashable policy: %d %s", w.Code, w.Body)
	}
}

// hungActuator never answers until its call's deadline.
type hungActuator struct{}

func (hungActuator) Act(ctx context.Context, _ string, _ action.Act, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

// tapAction opens an action link and taps it with a.
func (g *rig) tapAction(link string, a *authenticator) *httptest.ResponseRecorder {
	g.t.Helper()
	body := g.do(http.MethodGet, link, nil).Body.String()
	id, ch := reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if id == nil || ch == nil {
		g.t.Fatalf("no challenge:\n%s", body)
	}
	as := a.get(ch[1])
	as.ID = id[1]
	return g.do(http.MethodPost, "/do", as)
}

// NET-2 slice s: a tap by another passkey, on a device the policy changed
// since, or on an act that did not answer in time each gets its own one
// answer, and a timeout is logged as such.
func TestActionTapAnswers(t *testing.T) {
	var logs []string
	g := actRig(t, nopActuator{}, &logs)
	if w := g.tapAction("/a?d=lock&a=unlock", newAuthenticator(t)); w.Code != http.StatusForbidden || answer(t, w)["error"] != action.ErrNotOwner.Error() {
		t.Errorf("another passkey: %d %s", w.Code, w.Body)
	}
	// The lock is isolated (a tightening, in force at once) between the
	// link and the tap.
	body := g.do(http.MethodGet, "/a?d=lock&a=unlock", nil).Body.String()
	id, ch := reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if id == nil || ch == nil {
		t.Fatalf("no challenge:\n%s", body)
	}
	cur := g.e.Current()
	next := clone(cur)
	next.Version = cur.Version + 1
	dev(&next, "lock").Isolated = true
	p := policy.Proposal{Doc: next, Diff: []byte("isolate")}
	r, _ := p.Root(g.a.Public())
	if _, err := g.e.Propose(p, g.a.signMsg(key.RootMsg(r)), g.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if g.e.Current().Device("lock").Isolated != true {
		t.Fatal("the isolation is not in force")
	}
	as := g.a.get(ch[1])
	as.ID = id[1]
	if w := g.do(http.MethodPost, "/do", as); w.Code != http.StatusConflict || answer(t, w)["error"] != action.ErrMoved.Error() {
		t.Errorf("a moved device: %d %s", w.Code, w.Body)
	}

	logs = nil
	g = actRig(t, hungActuator{}, &logs)
	cfg := g.s.cfg
	cfg.ActTimeout, cfg.Lock = 50*time.Millisecond, nil
	var err error
	if g.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	if w := g.tapAction("/a?d=lock&a=unlock", g.a); w.Code != http.StatusGatewayTimeout || answer(t, w)["error"] != action.ErrTimeout.Error() {
		t.Errorf("a hung act: %d %s", w.Code, w.Body)
	}
	if len(logs) != 1 || !strings.HasSuffix(logs[0], "may have run: no answer in time") {
		t.Errorf("logged %q", logs)
	}
}

// The page's words for a class, a change's consequence, a drone policy
// removed, and the status each enrolment error answers with.
func TestWordsAndStatuses(t *testing.T) {
	for c, want := range map[string]string{
		policy.ClassFeedValve:      "a valve that feeds sprinklers, heating or a medical supply",
		policy.ClassPrimaryHeating: "primary heating",
		policy.ClassAlarm:          "an alarm",
		policy.ClassOven:           "an oven",
		policy.ClassPlug:           "a plug",
	} {
		if got := classWords(c); got != want {
			t.Errorf("classWords(%q) = %q, want %q", c, got, want)
		}
	}
	for c, want := range map[policy.Class]string{
		{Tightening: true, Owner: true}: "This closes something on a safety-list device. It applies as soon as you approve.",
		{Tightening: true}:              "This only closes something. It applies as soon as you approve.",
		{}:                              "This opens something. It applies 10 minutes after you approve, and you can cancel it on this page until then.",
	} {
		if got := consequence(c); got != want {
			t.Errorf("consequence(%+v) = %q", c, got)
		}
	}
	wantLines(t, "drone removed", Describe(policy.Document{Drone: "abc"}, policy.Document{}, zone),
		[]string{"Remove the drone flight policy: the drone stays docked."}, nil)
	for err, want := range map[error]int{
		enrol.ErrLimited: http.StatusTooManyRequests, enrol.ErrBusy: http.StatusTooManyRequests,
		enrol.ErrCode: http.StatusForbidden, enrol.ErrProof: http.StatusForbidden,
		enrol.ErrGone:  http.StatusGone,
		enrol.ErrPhase: http.StatusConflict, enrol.ErrKept: http.StatusConflict,
		enrol.ErrKey:               http.StatusBadRequest,
		errors.New("other"):        http.StatusInternalServerError,
		errors.Join(enrol.ErrGone): http.StatusGone,
	} {
		if got := status(err); got != want {
			t.Errorf("status(%v) = %d, want %d", err, got, want)
		}
	}
}
