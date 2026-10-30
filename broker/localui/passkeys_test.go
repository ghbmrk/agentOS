package localui

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"html"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: KEY-4, CH-3, CH-7, REC-3

// fakePasskeys stands in for agentosd's passkey ops.
type fakePasskeys struct {
	list     localapi.PasskeyList
	sessions []string
	points   [][]byte
	finished [][3][]byte
	cut      []string
	cutTaps  [][3][]byte
	err      error // every op but List answers it
}

func (f *fakePasskeys) List(_ context.Context, session string) (localapi.PasskeyList, error) {
	f.sessions = append(f.sessions, session)
	return f.list, nil
}

func (f *fakePasskeys) Begin(_ context.Context, session string, point []byte) ([]byte, error) {
	f.sessions = append(f.sessions, session)
	f.points = append(f.points, point)
	return []byte("0123456789abcdef0123456789abcdef"), f.err
}

func (f *fakePasskeys) Finish(_ context.Context, session string, ad, cd, sig []byte) error {
	f.sessions = append(f.sessions, session)
	f.finished = append(f.finished, [3][]byte{ad, cd, sig})
	return f.err
}

func (f *fakePasskeys) CutOff(_ context.Context, session, id string, ad, cd, sig []byte) error {
	f.sessions = append(f.sessions, session)
	f.cut = append(f.cut, id)
	f.cutTaps = append(f.cutTaps, [3][]byte{ad, cd, sig})
	return f.err
}

var (
	anchorKey = localapi.Passkey{ID: strings.Repeat("a1", 32), Fingerprint: "a1a1 a1a1 a1a1", Alg: "es256"}
	phoneKey  = localapi.Passkey{ID: strings.Repeat("b2", 32), Fingerprint: "b2b2 b2b2 b2b2", Alg: "es256", By: "a1a1 a1a1 a1a1",
		CutChallenge: []byte("fedcba9876543210fedcba9876543210")}
)

// passkeyRig is a set-up box whose local UI serves the passkey page.
func passkeyRig(t *testing.T) (*rig, *fakePasskeys) {
	t.Helper()
	r := newRig(t)
	fp := &fakePasskeys{list: localapi.PasskeyList{Anchors: []localapi.Passkey{anchorKey}, Enrolled: []localapi.Passkey{phoneKey}}}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Passkeys: fp, PasskeyRPID: DefaultPageName,
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, fp
}

// Without an RP ID the page is not mounted, and the page and its ops go
// together.
func TestPasskeyPageOffWithoutRPID(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	r.signIn()
	if w := r.do("GET", "/passkeys/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("passkey page without an RP ID: %d", w.Code)
	}
	if strings.Contains(r.get("/home"), "/passkeys/") {
		t.Fatal("home links the passkey page")
	}
	if _, err := New(Config{Page: testPage(), Passkeys: &fakePasskeys{}}); err == nil {
		t.Fatal("passkeys without an RP ID")
	}
	if _, err := New(Config{Page: testPage(), PasskeyRPID: DefaultPageName}); err == nil {
		t.Fatal("an RP ID without passkeys")
	}
}

// The page runs exactly one script, the one its CSP's hash admits; the
// script reaches nothing but its own page, and other pages admit none.
func TestPasskeyScriptMatchesItsCSPHash(t *testing.T) {
	r, _ := passkeyRig(t)
	r.signIn()
	for _, w := range []*httptest.ResponseRecorder{r.do("GET", "/passkeys/", nil), r.post("/passkeys/", url.Values{"step": {"begin"},
		"point": {base64.StdEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...))}})} {
		page := w.Body.String()
		m := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(page, -1)
		if len(m) != 1 || strings.Count(strings.ToLower(page), "<script") != 1 {
			t.Fatalf("scripts: %d", len(m))
		}
		h := sha256.Sum256([]byte(m[0][1]))
		if csp := w.Header().Get("Content-Security-Policy"); csp != cspWith(base64.StdEncoding.EncodeToString(h[:])) || csp != passkeyCSP {
			t.Fatalf("CSP %q does not admit exactly the page's script", csp)
		}
		for _, bad := range []string{"fetch", "XMLHttpRequest", "http", "eval", "Function(", "innerHTML", "cookie", "localStorage", "src"} {
			if strings.Contains(m[0][1], bad) {
				t.Fatalf("passkey script uses %q", bad)
			}
		}
	}
	if csp := r.do("GET", "/home", nil).Header().Get("Content-Security-Policy"); csp != pageCSP {
		t.Fatalf("home's CSP %q", csp)
	}
}

// Enrolling: the page's create() point goes to agentosd under the phone's
// session, the tap step carries the challenge and the RP ID, and the
// hardware key's answer goes back as sent.
func TestPasskeyPageRunsTheCeremony(t *testing.T) {
	r, fp := passkeyRig(t)
	if w := r.post("/passkeys/", url.Values{"step": {"begin"}}); w.Code != http.StatusSeeOther || len(fp.points) != 0 {
		t.Fatalf("a post without sign-in: %d", w.Code)
	}
	r.signIn()
	point := append([]byte{4}, make([]byte, 64)...)
	p := html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"begin"}, "point": {base64.StdEncoding.EncodeToString(point)}}).Body.String())
	if len(fp.points) != 1 || string(fp.points[0]) != string(point) {
		t.Fatalf("points %v", fp.points)
	}
	for _, want := range []string{`id="pk-finish"`, `data-rp="` + DefaultPageName + `"`,
		`data-challenge="` + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + `"`, `id="pk-tap"`} {
		if !strings.Contains(p, want) {
			t.Errorf("tap step lacks %q", want)
		}
	}
	enc := base64.StdEncoding.EncodeToString
	p = r.post("/passkeys/", url.Values{"step": {"finish"}, "ad": {enc([]byte("ad"))}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}}).Body.String()
	if len(fp.finished) != 1 || string(fp.finished[0][2]) != "sig" || !strings.Contains(p, "passkey is added") {
		t.Fatalf("finish %v\n%s", fp.finished, p)
	}
	for _, s := range fp.sessions {
		if s == "" || len(s) != 2*localapi.TokenBytes {
			t.Fatalf("session %q", s)
		}
	}
	// A point or assertion past its bound never reaches agentosd.
	big := enc(make([]byte, localapi.MaxPasskeyAssertion+1))
	r.post("/passkeys/", url.Values{"step": {"begin"}, "point": {enc(make([]byte, 64))}})
	r.post("/passkeys/", url.Values{"step": {"finish"}, "ad": {big}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}})
	r.post("/passkeys/", url.Values{"step": {"finish"}, "ad": {"not base64!"}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}})
	if len(fp.points) != 1 || len(fp.finished) != 1 {
		t.Fatal("an unbounded frame reached agentosd")
	}
	// A cross-origin post is refused before anything runs.
	w := r.do("POST", "/passkeys/", url.Values{"step": {"cutoff"}, "id": {phoneKey.ID}}, func(q *http.Request) {
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		q.Header.Set("Origin", "http://evil.example")
	})
	if w.Code != http.StatusForbidden || len(fp.cut) != 0 {
		t.Fatalf("a cross-origin cut off: %d %v", w.Code, fp.cut)
	}
}

// Cutting off a hardware key shows the recovery reply in its fixed words;
// a phone passkey is confirmed first, then cut off.
func TestCutOffAnAnchorShowsTheRecoveryReply(t *testing.T) {
	if AnchorReply != "That is one of your hardware keys. A hardware key is replaced only through recovery, with your Owner Card. To stop a lost phone, cut off the phone's passkey instead." {
		t.Fatal("the anchor reply's words changed")
	}
	r, fp := passkeyRig(t)
	r.signIn()
	p := html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"confirm"}, "id": {phoneKey.ID}}).Body.String())
	if len(fp.cut) != 0 || !strings.Contains(p, "cut off for good") || !strings.Contains(p, `name="step" value="cutoff"`) {
		t.Fatalf("confirm:\n%s", p)
	}
	p = html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"cutoff"}, "id": {phoneKey.ID}}).Body.String())
	if len(fp.cut) != 1 || fp.cut[0] != phoneKey.ID || !strings.Contains(p, "cut off for good") {
		t.Fatalf("cut off %v", fp.cut)
	}
	fp.err = Refused(localapi.ErrPasskeyAnchor)
	p = html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"cutoff"}, "id": {anchorKey.ID}}).Body.String())
	if !strings.Contains(p, AnchorReply) {
		t.Fatalf("no recovery reply:\n%s", p)
	}
	// Every refusal shows fixed words, never agentosd's.
	for _, c := range append(append([]string{}, localapi.PasskeyCodes...), "kernel: an anchor is cut off only by recovery") {
		fp.err = Refused(c)
		p = r.post("/passkeys/", url.Values{"step": {"cutoff"}, "id": {phoneKey.ID}}).Body.String()
		if strings.Contains(p, "kernel") || strings.Contains(p, c) {
			t.Errorf("%s shown as is", c)
		}
	}
	// A key not listed is stale and reaches nothing.
	n := len(fp.cut)
	r.post("/passkeys/", url.Values{"step": {"cutoff"}, "id": {strings.Repeat("c3", 32)}})
	if len(fp.cut) != n {
		t.Fatal("an unlisted key reached agentosd")
	}
}

// The list shows each key's fingerprint and algorithm only; the ID goes
// only in a form's hidden field, and listed text is escaped.
func TestPasskeyPageRendersOnlyFingerprints(t *testing.T) {
	r, fp := passkeyRig(t)
	fp.list.CutOff = []localapi.Passkey{{ID: strings.Repeat("d4", 32), Fingerprint: "<b>d4</b>", Alg: "es256"}}
	r.signIn()
	p := r.get("/passkeys/")
	for _, want := range []string{anchorKey.Fingerprint, phoneKey.Fingerprint, "added with hardware key " + phoneKey.By, "&lt;b&gt;d4&lt;/b&gt;"} {
		if !strings.Contains(p, want) {
			t.Errorf("list lacks %q", want)
		}
	}
	for _, id := range []string{anchorKey.ID, phoneKey.ID} {
		if strings.Count(p, id) != 1 || !strings.Contains(p, `name="id" value="`+id+`"`) {
			t.Errorf("ID %s shown outside its form", id)
		}
	}
	if strings.Contains(p, strings.Repeat("d4", 32)) || strings.Contains(p, "<b>d4") {
		t.Fatal("a cut-off key is offered or unescaped")
	}
}

// A phone passkey's cut-off asks for a hardware key's tap over its
// CutChallenge, and posts that assertion as the enrol step does (#3209); a
// hardware key's confirm has no tap, and a malformed tap reaches nothing.
func TestCutOffAPhoneAsksForAHardwareKeyTap(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString
	r, fp := passkeyRig(t)
	r.signIn()
	p := html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"confirm"}, "id": {phoneKey.ID}}).Body.String())
	if !strings.Contains(p, `id="pk-tap"`) || !strings.Contains(p, `data-challenge="`+enc(phoneKey.CutChallenge)+`"`) ||
		!strings.Contains(p, `id="pk-finish"`) || !strings.Contains(p, `name="step" value="cutoff"`) {
		t.Fatalf("the phone's confirm asks for no hardware key tap:\n%s", p)
	}
	p = html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"confirm"}, "id": {anchorKey.ID}}).Body.String())
	if strings.Contains(p, `id="pk-tap"`) {
		t.Fatalf("a hardware key's confirm asks for a tap:\n%s", p)
	}
	tap := url.Values{"step": {"cutoff"}, "id": {phoneKey.ID}, "ad": {enc([]byte("ad"))}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}}
	r.post("/passkeys/", tap)
	if len(fp.cutTaps) != 1 || string(fp.cutTaps[0][0]) != "ad" || string(fp.cutTaps[0][1]) != "cd" || string(fp.cutTaps[0][2]) != "sig" {
		t.Fatalf("the tap did not reach agentosd: %q", fp.cutTaps)
	}
	tap.Set("sig", "not base64!")
	r.post("/passkeys/", tap)
	tap.Set("sig", "")
	r.post("/passkeys/", tap)
	if len(fp.cut) != 1 {
		t.Fatal("a malformed tap reached agentosd")
	}
}

// Picking the wrong passkey at the tap step keeps the owner there, with
// the begun challenge, to tap again: the phone's own new passkey or another
// phone's (#3175 item 2). Any other refusal goes back to the list.
func TestAWrongTapStaysOnTheTapStep(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString
	r, fp := passkeyRig(t)
	r.signIn()
	ch := enc([]byte("0123456789abcdef0123456789abcdef"))
	p := html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"begin"}, "point": {enc(append([]byte{4}, make([]byte, 64)...))}}).Body.String())
	if !strings.Contains(p, `name="ch" value="`+ch+`"`) {
		t.Fatalf("the finish form lacks the challenge:\n%s", p)
	}
	m := regexp.MustCompile(`name="tok" value="([0-9a-f]{64})"`).FindStringSubmatch(p)
	if m == nil {
		t.Fatalf("the finish form lacks the token:\n%s", p)
	}
	tap := url.Values{"step": {"finish"}, "ch": {ch}, "tok": {m[1]}, "ad": {enc([]byte("ad"))}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}}
	for _, c := range []string{localapi.ErrPasskeyBadAssertion, localapi.ErrPasskeyNotAnchor} {
		fp.err = Refused(c)
		p = html.UnescapeString(r.post("/passkeys/", tap).Body.String())
		if !strings.Contains(p, TapAgainText) || !strings.Contains(p, `id="pk-tap"`) || !strings.Contains(p, `data-challenge="`+ch+`"`) ||
			!strings.Contains(p, `name="step" value="finish"`) {
			t.Fatalf("%s: not back on the tap step:\n%s", c, p)
		}
	}
	if !strings.Contains(TapAgainText, "choose your hardware key, not this phone's passkey") {
		t.Fatal("the tap-again words changed")
	}
	// Another refusal, or a challenge that isn't one, goes back to the list.
	fp.err = Refused(localapi.ErrPasskeyStale)
	if p = r.post("/passkeys/", tap).Body.String(); strings.Contains(p, `id="pk-tap"`) {
		t.Fatal("a stale finish stayed on the tap step")
	}
	// A challenge this UI did not give out is never shown back (#3239
	// item 2): one the form made up, or one without its token.
	fp.err = Refused(localapi.ErrPasskeyBadAssertion)
	made := enc([]byte("fedcba9876543210fedcba9876543210"))
	for _, bad := range []url.Values{{"ch": {made}, "tok": {m[1]}}, {"ch": {ch}, "tok": {""}}, {"ch": {made}, "tok": {r.srv.passkeyToken("another phone", made)}}} {
		tap.Set("ch", bad.Get("ch"))
		tap.Set("tok", bad.Get("tok"))
		if p = r.post("/passkeys/", tap).Body.String(); strings.Contains(p, `id="pk-tap"`) || strings.Contains(p, made) {
			t.Fatalf("a challenge not given out was shown back: %v", bad)
		}
	}
	// The script asks the browser for a security key at the tap.
	if !strings.Contains(passkeyJS, `hints: ["security-key"]`) || strings.Count(passkeyJS, "navigator.credentials.get(") != 1 {
		t.Fatal("get() does not hint a security key")
	}
}

// A phone passkey's cut-off tap that picks the wrong passkey stays on its
// confirm step to tap again (#3175 item 2).
func TestAWrongCutOffTapStaysOnTheConfirmStep(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString
	r, fp := passkeyRig(t)
	r.signIn()
	fp.err = Refused(localapi.ErrPasskeyNotAnchor)
	p := html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"cutoff"}, "id": {phoneKey.ID},
		"ad": {enc([]byte("ad"))}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}}).Body.String())
	if !strings.Contains(p, TapAgainText) || !strings.Contains(p, `data-challenge="`+enc(phoneKey.CutChallenge)+`"`) ||
		!strings.Contains(p, `name="step" value="cutoff"`) {
		t.Fatalf("not back on the confirm step:\n%s", p)
	}
}

// A hardware key's confirm step gives the recovery reply and offers no
// cut-off: it never says "for good", which is untrue for one (#3175 item 3).
func TestAHardwareKeysConfirmGivesTheRecoveryReply(t *testing.T) {
	r, fp := passkeyRig(t)
	r.signIn()
	p := html.UnescapeString(r.post("/passkeys/", url.Values{"step": {"confirm"}, "id": {anchorKey.ID}}).Body.String())
	if !strings.Contains(p, AnchorReply) || strings.Contains(p, "for good") || strings.Contains(p, `value="cutoff"`) {
		t.Fatalf("a hardware key's confirm:\n%s", p)
	}
	if len(fp.cut) != 0 {
		t.Fatal("the confirm cut something off")
	}
}
