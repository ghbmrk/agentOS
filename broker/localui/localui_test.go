package localui

import (
	"context"
	crand "crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"github.com/ghbmrk/agentos/broker/control"
	"html"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

const (
	boxNum   = "+15550000100"
	ownerNum = "+15550000001"
	phoneIP  = "10.42.0.23:51000"
	// apiCanary is a synthetic key; no response may ever echo it.
	apiCanary = "sk-synthetic-CANARY-9f3b2c71d0e44a8b"
)

func testAP() APConfig {
	return APConfig{Iface: "wlan0", Uplink: "eth0", Addr: netip.MustParsePrefix("10.42.0.1/24"),
		SSID: "AgentOS-7K3M", Password: "ABCD-EFGH-JKLM-NPQR"}
}

func testPage() Page { return Page{Iface: "eth0"} }

// The box's own addresses in these tests: the one the phone reaches and
// another on a second port.
func init() {
	ownAddrs = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("192.168.50.2"), netip.MustParseAddr("172.20.0.9")}, nil
	}
}

// boxReached is the address a phone's connection reaches on the box's
// port 1.
var boxReached = &net.TCPAddr{IP: net.IPv4(10, 42, 0, 1), Port: 80}

// reaching is r as the server sees it on port 1: its connection reached
// boxReached.
func reaching(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, boxReached))
}

// fakeHooks stands in for the uplink, modem, vault, host trust and provider
// adapters.
type fakeHooks struct {
	mu           sync.Mutex
	progress     Progress
	sent         []modem.SMS
	now          func() time.Time
	seed         []byte // the vault's sealed code-generator seed
	pending      []byte // the newest seed waiting for a code
	enrolls      int
	trusted      *bool
	trustErr     error // returned by TrustHost, which then saves nothing
	keys         map[string]string
	finished     string
	connected    bool
	device       bool // the device-code sign-in completes on the provider's site
	private      map[string]bool
	setUp        bool
	finishes     int
	finishCalls  int                    // Finish calls, refused ones too
	onConfirm    func()                 // runs inside ConfirmCode, for races
	finishErr    error                  // returned by Finish after the owner channel exists
	refuseFinish func() error           // when set and it errs, Finish refuses with it and sets nothing up
	sendFails    func(text string) bool // a send whose text it matches fails (after being recorded)
	// unavailable: the vault's enrollment was never opened for setup.
	unavailable bool
	noTexts     bool            // the box cannot text: BoxNumber answers "", false
	keyErr      error           // ConnectAPIKey's answer when set; nothing is stored
	deviceErr   error           // StartDeviceCode's answer when set
	deviceLink  string          // StartDeviceCode's link when set
	privateErr  error           // SetPrivateOK's answer when set; nothing is recorded
	privates    int             // SetPrivateOK calls
	byConfig    map[string]bool // PrivateByConfig per provider
	// owed is agentosd's owed answers (#1544): each answer is owed before
	// the vault hears it and cleared once it records it; Finish refuses
	// while any is owed.
	owed map[string]bool
	// down is agentosd's socket down: SetPrivateOK fails before agentosd
	// hears the answer, so nothing is owed either (ONB-private-save-fail s3).
	down bool
}

func (f *fakeHooks) Progress() Progress { f.mu.Lock(); defer f.mu.Unlock(); return f.progress }
func (f *fakeHooks) BoxNumber() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noTexts {
		return "", false
	}
	return boxNum, true
}
func (f *fakeHooks) HostInfo() string { return "GEEKOM Air12, 8 GB" }
func (f *fakeHooks) Send(to, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, modem.SMS{To: to, Text: text})
	if f.sendFails != nil && f.sendFails(text) {
		return errors.New("modem busy")
	}
	return nil
}

// EnrollCode and ConfirmCode act as the vault process does (egress K17):
// each enroll makes a new seed, only the newest confirms, and a confirmed
// seed is sealed.
func (f *fakeHooks) EnrollCode() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolls++
	if f.unavailable {
		return "", ErrCodesUnavailable
	}
	if f.seed != nil {
		return "", ErrCodesEnrolled
	}
	f.pending = make([]byte, 20)
	if _, err := crand.Read(f.pending); err != nil {
		return "", err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(f.pending)
	return "otpauth://totp/AgentOS:AgentOS?secret=" + secret + "&issuer=AgentOS&algorithm=SHA1&digits=6&period=30", nil
}
func (f *fakeHooks) ConfirmCode(code string) (bool, error) {
	if f.onConfirm != nil {
		f.onConfirm()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.unavailable:
		return false, ErrCodesUnavailable
	case f.seed != nil:
		return false, ErrCodesEnrolled
	case f.pending == nil:
		return false, ErrNoCodeEnrollment
	}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if code == owner.TOTP(f.pending, f.now().Add(d)) {
			f.seed, f.pending = f.pending, nil
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeHooks) TrustHost(t bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.trustErr != nil {
		return f.trustErr
	}
	f.trusted = &t
	return nil
}
func (f *fakeHooks) Providers() []Provider {
	f.mu.Lock()
	defer f.mu.Unlock()
	ps := []Provider{{ID: "anthropic", Name: "Anthropic", APIKey: true, DeviceCode: true, Connected: f.connected, PrivateOK: f.private["anthropic"], SigningIn: !f.connected},
		{ID: "openai", Name: "OpenAI", APIKey: true}}
	for i := range ps {
		ps[i].PrivateByConfig = f.byConfig[ps[i].ID]
		if ok, owed := f.owed[ps[i].ID]; owed {
			ps[i].Owed = &ok
		}
	}
	return ps
}
func (f *fakeHooks) SetPrivateOK(id string, ok bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.privates++
	if f.down {
		return errors.New("localui.sock: connection refused")
	}
	if f.owed == nil {
		f.owed = map[string]bool{}
	}
	f.owed[id] = ok
	if f.privateErr != nil {
		return f.privateErr
	}
	if f.private == nil {
		f.private = map[string]bool{}
	}
	f.private[id] = ok
	delete(f.owed, id)
	return nil
}
func (f *fakeHooks) AlreadySetUp() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.setUp }
func (f *fakeHooks) ConnectAPIKey(id, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keyErr != nil {
		return f.keyErr
	}
	if f.keys == nil {
		f.keys = map[string]string{}
	}
	f.keys[id] = key
	f.connected = true
	return nil
}
func (f *fakeHooks) StartDeviceCode(id string) (string, string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deviceErr != nil {
		return "", "", "", f.deviceErr
	}
	if f.device {
		f.connected = true // the owner finishes on the provider's site
	}
	if f.deviceLink != "" {
		return f.deviceLink, "WXYZ-1234", "Example", nil
	}
	return "https://example.invalid/device", "WXYZ-1234", "Example", nil
}
func (f *fakeHooks) Finish(n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finishCalls++
	if len(f.owed) > 0 {
		return errors.New("answer owed")
	}
	if f.refuseFinish != nil {
		if err := f.refuseFinish(); err != nil {
			return err
		}
	}
	f.finished = n
	f.finishes++
	f.setUp = true
	return f.finishErr
}

type fakeEngine struct {
	mu      sync.Mutex
	stopped bool
}

func (e *fakeEngine) Stop(context.Context) (control.StopReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
	return control.StopReport{}, nil
}
func (e *fakeEngine) Resume() error          { e.mu.Lock(); defer e.mu.Unlock(); e.stopped = false; return nil }
func (e *fakeEngine) Stopped() bool          { e.mu.Lock(); defer e.mu.Unlock(); return e.stopped }
func (e *fakeEngine) List() []control.Status { return nil }

type rig struct {
	t     *testing.T
	mu    sync.Mutex
	now   time.Time
	hooks *fakeHooks
	srv   *Server
	card  *card.Card
	eng   *fakeEngine
	ch    *owner.Channel
	// served is the channel behind the in-process socket (page).
	served *swapOwner
	// paused are the gate's paused grants behind the socket (page).
	paused fakePaused
	jar    http.CookieJar
	ip     string   // the phone's address on the box's Wi-Fi
	seen   []string // every page body served, for the ONB-1 scan
	// via, when set, replaces hooks as the server's Hooks.
	via Hooks
	// owned, when set, is the server's Owner Card step.
	owned OwnerCard
	// rot, when set, is the server's card rotation.
	rot RotationCard
}

func newRig(t *testing.T) *rig {
	t.Helper()
	c, err := card.Generate(rand.New(rand.NewSource(7)))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), card: c, eng: &fakeEngine{},
		hooks: &fakeHooks{progress: Progress{Phase: "updating"}}}
	r.hooks.now = r.clock
	r.srv = r.open(&MemStore{})
	r.jar, _ = cookiejar.New(nil)
	r.ip = phoneIP
	return r
}

func (r *rig) open(st SetupStore) *Server {
	var h Hooks = r.hooks
	if r.via != nil {
		h = r.via
	}
	s, err := New(Config{Page: testPage(), Hooks: h, SetupSecret: r.card.SetupSecret, Store: st, Card: r.owned, Rotation: r.rot,
		Defaults: "spend cap $20 a day; payments need approval.", Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *rig) clock() time.Time        { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *rig) advance(d time.Duration) { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

// do sends one request as the phone on the box's Wi-Fi.
func (r *rig) do(method, path string, form url.Values, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	r.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "http://10.42.0.1"+path, body)
	req.RemoteAddr = r.ip
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	u := req.URL
	for _, c := range r.jar.Cookies(u) {
		req.AddCookie(c)
	}
	for _, m := range mod {
		m(req)
	}
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, reaching(req))
	r.jar.SetCookies(u, w.Result().Cookies())
	r.mu.Lock()
	r.seen = append(r.seen, w.Body.String())
	r.mu.Unlock()
	return w
}

func (r *rig) get(path string) string {
	r.t.Helper()
	w := r.do("GET", path, nil)
	if w.Code != 200 {
		r.t.Fatalf("GET %s: %d %s", path, w.Code, w.Header().Get("Location"))
	}
	return w.Body.String()
}

func (r *rig) post(path string, form url.Values) *httptest.ResponseRecorder {
	r.t.Helper()
	return r.do("POST", path, form)
}

func (r *rig) setupErr() string {
	m := regexp.MustCompile(`class="err">([^<]*)<`).FindStringSubmatch(r.get("/setup"))
	if m == nil {
		return ""
	}
	return m[1]
}

// startChannel is what Hooks.Finish's caller does: start the owner channel
// with the enrolled seed and attach it.
func (r *rig) startChannel(m modem.Modem) {
	r.t.Helper()
	ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: m, Engine: r.eng, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: r.hooks.seed, GridSeed: r.card.GridSeed}, Now: r.clock, Location: time.UTC})
	if err != nil {
		r.t.Fatal(err)
	}
	r.ch = ch
	r.srv.SetOwner(r.page(ch))
}

// code is the owner's code generator; each call moves to the next step.
func (r *rig) code() string {
	r.advance(30 * time.Second)
	return owner.TOTP(r.hooks.seed, r.clock())
}

// runSetup walks §8.1 steps 5 and 6 as the owner would.
func (r *rig) runSetup() {
	r.t.Helper()
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if p := r.get("/setup"); !strings.Contains(p, "WXYZ-1234") {
		r.t.Fatalf("device code not shown: %s", p)
	}
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
	if r.hooks.keys["anthropic"] != apiCanary || r.hooks.finished != ownerNum || !r.hooks.private["anthropic"] {
		r.t.Fatalf("setup did not finish: keys=%v finished=%q", len(r.hooks.keys), r.hooks.finished)
	}
}

// runSetupToAI walks setup up to Connect AI, with the update finished.
func (r *rig) runSetupToAI() {
	t := r.t
	t.Helper()
	r.runSetupToHost()
	r.post("/setup/host", url.Values{})
	if r.hooks.trusted == nil || !*r.hooks.trusted {
		t.Fatal("PC not trusted by default")
	}
	// Connect AI waits for the first-boot update (ONB-4), nothing else.
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	if !strings.Contains(r.setupErr(), "still updating") || r.hooks.keys != nil {
		t.Fatal("AI connected before the first-boot update finished")
	}
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "ready", Updated: true, Online: true}
	r.hooks.mu.Unlock()
	// CAP-9: the private-data question is asked, unticked on an API key
	// (D-115: ticked only on a plan sign-in, privatedefault_test.go).
	if p := setupForms(t, r.get("/setup"))["ai-key openai"]; !strings.Contains(p, `name="private" value="1">`) || strings.Contains(p, "checked") {
		t.Fatalf("no private-data question, or ticked by default: %s", p)
	}
}

// runSetupToHost walks setup up to its host step.
func (r *rig) runSetupToHost() {
	t := r.t
	t.Helper()
	if loc := r.do("GET", "/", nil).Header().Get("Location"); loc != "/setup" {
		t.Fatalf("root before setup: %q", loc)
	}
	// The number step is first: the box's uplink is its cable to the
	// enforcer, so setup has no network step (D-178).
	if page := r.get("/setup"); !strings.Contains(page, "1. Text your box") || strings.Contains(page, "Wi-Fi") {
		t.Fatalf("number step not first: %s", page)
	}
	r.hooks.progress.Online = true
	// Text my box: the sms: link carries the box's number and a pairing code.
	page := html.UnescapeString(r.get("/setup"))
	m := regexp.MustCompile(`href="sms:(\+[0-9]+)\?&body=PAIR%20([A-Z2-9]{8})"`).FindStringSubmatch(page)
	if m == nil || m[1] != boxNum {
		t.Fatalf("no sms: link: %s", page)
	}
	reply, ok := r.srv.OfferText(ownerNum, "PAIR "+m[2])
	if !ok || !strings.Contains(reply, "GEEKOM Air12, 8 GB") {
		t.Fatalf("pairing reply %q", reply)
	}
	if n, gsm := modem.Segments(reply); !gsm || n > 1 {
		t.Fatalf("pairing reply breaks CH-12: %q", reply)
	}
	// Approval codes: the otpauth link, then one entered code.
	page = html.UnescapeString(r.get("/setup"))
	m = regexp.MustCompile(`href="otpauth://totp/AgentOS:AgentOS\?secret=([A-Z2-7]+)&issuer=AgentOS`).FindStringSubmatch(page)
	if m == nil || !strings.Contains(page, "<svg") {
		t.Fatalf("no otpauth link or QR: %s", page)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	r.post("/setup/codes", url.Values{"code": {"000000"}})
	if !strings.Contains(r.setupErr(), "did not match") {
		t.Fatal("wrong enrollment code accepted")
	}
	r.post("/setup/codes", url.Values{"code": {owner.TOTP(seed, r.clock())}})
	if string(r.hooks.seed) != string(seed) {
		t.Fatal("the vault did not seal the seed the page showed")
	}
	if strings.Contains(r.get("/setup"), m[1]) {
		t.Fatal("seed shown again after enrollment")
	}
	// Recovery sheet.
	r.post("/setup/recovery", url.Values{})
	if r.setupErr() == "" {
		t.Fatal("recovery step passed without the acknowledgment")
	}
	r.post("/setup/recovery", url.Values{"stored": {"1"}})
	// This PC: trusted by default, with the defaults stated in one line.
	page = r.get("/setup")
	if !strings.Contains(page, "This is not my PC") || !strings.Contains(page, "Defaults: spend cap") {
		t.Fatalf("host step: %s", page)
	}
}

// REQ: ONB-3, ONB-6, ONB-4, CH-8

// ONB-3's minimum path: the network, the owner's number from their first
// text, code enrollment confirmed by one code, the recovery sheet, one AI
// provider. Nothing else is asked.
func TestSetupMinimumPath(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	if !r.srv.setup.done() {
		t.Fatal("not done")
	}
	// Setup pages close once setup is done (CH-7).
	if loc := r.do("GET", "/setup", nil).Header().Get("Location"); loc != "/status" {
		t.Fatalf("setup still open: %q", loc)
	}
	n := r.hooks.enrolls
	r.post("/setup/codes", url.Values{"code": {"123456"}, "enrolled": {"1"}})
	if string(r.hooks.seed) == "" || r.hooks.pending != nil || n != r.hooks.enrolls {
		t.Fatal("enrollment reopened after setup")
	}
	// The API key never comes back in any page.
	for _, b := range r.seen {
		if strings.Contains(b, apiCanary) {
			t.Fatal("API key echoed in a page")
		}
	}
}

// Setup progress survives a restart; the code seed does not, since it lives
// only in the vault once enrolled.
func TestSetupResumesAfterRestart(t *testing.T) {
	r := newRig(t)
	st := &MemStore{}
	r.srv = r.open(st)
	r.get("/setup")
	r.hooks.progress.Online = true
	page := r.get("/setup")
	code := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(page)[1]
	r.srv.OfferText(ownerNum, "pair "+strings.ToLower(code)+".")
	r.srv = r.open(st)
	if !strings.Contains(r.get("/setup"), "Add approval codes") {
		t.Fatal("restart lost setup progress")
	}
	if strings.Contains(string(mustJSON(t, st)), "seed") {
		t.Fatal("setup state holds a seed")
	}
}

func mustJSON(t *testing.T, st *MemStore) []byte {
	s, _ := st.Load()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ONB-6 typing fallbacks: the card's setup code by text, and entering the
// number on the page.
func TestPairingFallbacks(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	if _, ok := r.srv.OfferText("+15550009999", "hello"); ok {
		t.Fatal("non-pairing text handled")
	}
	reply, ok := r.srv.OfferText(ownerNum, "PAIR "+strings.ToLower(r.card.SetupCode))
	if !ok || !strings.HasPrefix(reply, "agentOS is running on") {
		t.Fatalf("card setup code: %q", reply)
	}
	// Once paired, nobody else can pair.
	if _, ok := r.srv.OfferText("+15550009999", "PAIR "+r.card.SetupCode); ok {
		t.Fatal("second pairing handled")
	}

	r = newRig(t)
	r.hooks.progress.Online = true
	r.get("/setup")
	r.post("/setup/number", url.Values{"number": {"+1 555 000 0001"}})
	if len(r.hooks.sent) != 1 || r.hooks.sent[0].To != ownerNum {
		t.Fatalf("no code texted: %+v", r.hooks.sent)
	}
	code := regexp.MustCompile(`[0-9]{6}`).FindString(r.hooks.sent[0].Text)
	r.post("/setup/number-code", url.Values{"code": {code}})
	if r.srv.setup.st.Owner != ownerNum {
		t.Fatal("typed number not paired")
	}
	if last := r.hooks.sent[len(r.hooks.sent)-1]; !strings.HasPrefix(last.Text, "agentOS is running on") {
		t.Fatalf("no reply from the box's number: %q", last.Text)
	}
}

// Pairing guesses by text are bounded: after PairTriesPerHour wrong codes
// the box stays silent, even for the right code, until the hour passes. A
// wrong code itself gets no reply (P2-2w c4c s2, #1290).
func TestPairingGuessesAreBounded(t *testing.T) {
	r := newRig(t)
	for i := 0; i < PairTriesPerHour; i++ {
		if reply, ok := r.srv.OfferText("+15550009999", "PAIR AAAA-AAAA"); reply != "" || !ok {
			t.Fatalf("try %d: %q %v", i, reply, ok)
		}
	}
	if reply, ok := r.srv.OfferText(ownerNum, "PAIR "+r.card.SetupCode); reply != "" || !ok || r.srv.setup.st.Owner != "" {
		t.Fatalf("over the bound: %q", reply)
	}
	r.advance(time.Hour)
	if _, _ = r.srv.OfferText(ownerNum, "PAIR "+r.card.SetupCode); r.srv.setup.st.Owner != ownerNum {
		t.Fatal("not paired after the hour")
	}
}

// REQ: CH-7, CH-11, CH-18

// Wi-Fi membership is not authority: without sign-in only setup (until it
// is done), unlock and status answer; everything else goes to sign-in.
// Sign-in is remembered on that device for the CH-3 unlock period.
func TestSignInGatesEverythingButSetupUnlockAndStatus(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	carrier := modem.NewCarrier()
	r.startChannel(carrier.Line(boxNum))
	r.srv.Mount("/review", "Review changes", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "diffs")
	}))
	for _, p := range []string{"/status", "/unlock"} {
		r.get(p)
	}
	for _, p := range []string{"/home", "/review/", "/review/x"} {
		w := r.do("GET", p, nil)
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") {
			t.Fatalf("%s without sign-in: %d %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := r.post("/unlock", url.Values{"code": {"000000"}, "next": {"/review/"}}); !strings.Contains(w.Body.String(), html.EscapeString(wrongCodeText)) {
		t.Fatalf("wrong code: %s", w.Body.String())
	}
	w := r.post("/unlock", url.Values{"code": {r.code()}, "next": {"/review/"}})
	if w.Header().Get("Location") != "/review/" {
		t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
	}
	ck := w.Result().Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.MaxAge != int(owner.DefaultUnlockFor/time.Second) {
		t.Fatalf("cookie %+v", ck)
	}
	if got := r.get("/review/"); got != "diffs" {
		t.Fatalf("mounted page: %q", got)
	}
	if !strings.Contains(r.get("/home"), "Review changes") {
		t.Fatal("home does not list the mounted page")
	}
	// Signing in here also unlocks chat by text (CH-14).
	if !r.ch.SessionUnlocked(r.clock()) {
		t.Fatal("session not unlocked")
	}
	// The device is forgotten when the unlock period ends.
	r.advance(owner.DefaultUnlockFor)
	if w := r.do("GET", "/home", nil); w.Code != http.StatusSeeOther {
		t.Fatal("sign-in outlived the unlock period")
	}
	// Open redirects stay on the box.
	w = r.post("/unlock", url.Values{"code": {r.code()}, "next": {"//evil.example/"}})
	if w.Header().Get("Location") != "/home" {
		t.Fatalf("next not kept local: %s", w.Header().Get("Location"))
	}
}

// P1-5 carry-forward (O4): the local UI offers RESUME and a local unlock
// that clears challenge mode.
func TestLocalUnlockClearsChallengeModeAndResume(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	carrier := modem.NewCarrier()
	phone := carrier.Line(ownerNum)
	r.startChannel(carrier.Line(boxNum))
	// Spoofed wrong codes put the channel into challenge mode.
	for i := 0; i < owner.WrongToChallenge; i++ {
		r.ch.Handle(context.Background(), ownerNum, "status "+strings.Repeat(string(rune('1'+i%9)), 6))
	}
	if !r.ch.LocalStatus().Challenged {
		t.Fatal("setup: not challenged")
	}
	if !strings.Contains(r.get("/status"), "Approvals by text are paused") {
		t.Fatal("status page does not say codes are locked")
	}
	// STOP needs no sign-in (CH-3: its worst case is a pause).
	r.post("/stop", url.Values{})
	if !r.eng.Stopped() {
		t.Fatal("STOP from the status page")
	}
	page := r.get("/status?m=stopped")
	if !strings.Contains(page, "RESUME") || !strings.Contains(page, `name="code"`) {
		t.Fatalf("no RESUME with a code field: %s", page)
	}
	// RESUME without sign-in needs a code; a wrong one resumes nothing.
	r.post("/resume", url.Values{"code": {"000000"}})
	if !r.eng.Stopped() {
		t.Fatal("resumed with a wrong code")
	}
	w := r.post("/resume", url.Values{"code": {r.code()}})
	if r.eng.Stopped() {
		t.Fatal("RESUME with a right code did not resume")
	}
	// The page shows the channel's own reply, which names held actions
	// and their UNDO IDs (CH-16).
	if !strings.Contains(w.Body.String(), "Resumed. Stopped actions may now run.") {
		t.Fatalf("RESUME page: %s", w.Body.String())
	}
	st := r.ch.LocalStatus()
	if st.Challenged || st.LowLocked || !st.Unlocked {
		t.Fatalf("challenge mode not cleared: %+v", st)
	}
	// A signed-in device resumes with one tap.
	r.post("/stop", url.Values{})
	r.post("/resume", url.Values{})
	if r.eng.Stopped() {
		t.Fatal("signed-in RESUME")
	}
	// Once the sign-in is old, agentosd asks for a code (Security S2 on
	// P2-2w a), and the page asks for it on the same page (UX).
	r.post("/stop", url.Values{})
	r.advance(localapi.FreshFor)
	w = r.post("/resume", url.Values{})
	if body := w.Body.String(); !r.eng.Stopped() || !strings.Contains(body, html.EscapeString(resumeCodeText)) || !strings.Contains(body, `name="code"`) {
		t.Fatalf("old sign-in resumed without a code, or no code field: %v %s", r.eng.Stopped(), body)
	}
	r.post("/resume", url.Values{"code": {"000000"}})
	if !r.eng.Stopped() {
		t.Fatal("resumed with a wrong code on an old sign-in")
	}
	r.post("/resume", url.Values{"code": {r.code()}})
	if r.eng.Stopped() {
		t.Fatal("a right code on an old sign-in did not resume")
	}
	_ = phone
}

// REQ: CH-9, CH-7

// The listener is bound to port 1's interface: binding to an interface
// that does not exist fails rather than falling back to every
// interface.
func TestListenerIsBoundToTheInterface(t *testing.T) {
	if _, err := listenOn(context.Background(), "agentosnope0", "127.0.0.1:0"); err == nil {
		t.Fatal("listening on a missing interface succeeded")
	}
	l, err := listenOn(context.Background(), "lo", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("SO_BINDTODEVICE needs privilege on this kernel")
		}
		t.Fatal(err)
	}
	defer l.Close()
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	resp, err := http.Get("http://" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := Listen(context.Background(), Page{Iface: "lo"}, 0); err == nil {
		t.Fatal("Listen accepted loopback as port 1")
	}
}

// Captive-portal checks and DNS-rebinding requests (any other host name)
// are refused and never act (ONB-5, D-178); cross-site posts are refused.
func TestForeignHostsAndCrossSitePosts(t *testing.T) {
	r := newRig(t)
	for _, u := range []string{"http://captive.apple.com/hotspot-detect.html", "http://connectivitycheck.gstatic.com/generate_204", "http://evil.example/status"} {
		req := httptest.NewRequest("GET", u, nil)
		req.RemoteAddr = phoneIP
		w := httptest.NewRecorder()
		r.srv.ServeHTTP(w, reaching(req))
		if w.Code != http.StatusMisdirectedRequest || w.Header().Get("Location") != "" {
			t.Fatalf("%s: %d %s", u, w.Code, w.Header().Get("Location"))
		}
	}
	req := httptest.NewRequest("POST", "http://evil.example/stop", nil)
	req.RemoteAddr = phoneIP
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, reaching(req))
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign-host POST: %d", w.Code)
	}
	r.runSetup()
	r.startChannel(nil)
	for _, h := range []map[string]string{{"Origin": "http://evil.example"}, {"Sec-Fetch-Site": "cross-site"}} {
		w := r.do("POST", "/stop", url.Values{}, func(q *http.Request) {
			for k, v := range h {
				q.Header.Set(k, v)
			}
		})
		if w.Code != http.StatusForbidden || r.eng.Stopped() {
			t.Fatalf("cross-site %v: %d", h, w.Code)
		}
	}
	w = r.do("GET", "/status", nil)
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "Cache-Control"} {
		if w.Header().Get(h) == "" {
			t.Fatalf("missing %s", h)
		}
	}
}

// REQ: ONB-1, ONB-8

// ONB-1: every page setup and daily use serve is complete in itself: no
// script, and nothing fetched from outside the box.
func TestPagesNeedNothingOutsideTheBox(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(nil)
	r.post("/unlock", url.Values{"code": {r.code()}})
	for _, p := range []string{"/status", "/unlock", "/home"} {
		r.get(p)
	}
	ext := regexp.MustCompile(`(?i)(src|href|action)\s*=\s*["']?\s*(https?:)?//|url\(\s*["']?(https?:)?//|@import|<script`)
	for _, b := range r.seen {
		for _, m := range ext.FindAllString(b, -1) {
			// The provider's own device-code page is the one link out,
			// opened by the owner on their phone (§8.1 step 6).
			if !strings.Contains(b, `href="https://example.invalid/device"`) || !strings.HasPrefix(strings.ToLower(m), "href=") {
				t.Fatalf("page reaches outside the box: %q", m)
			}
		}
	}
}

func TestAllSetText(t *testing.T) {
	for _, conn := range [][]string{nil, {"email"}, {"email", "calendar", "files"}} {
		s := AllSetText(conn, true)
		if n, gsm := modem.Segments(s); !gsm || n > 3 {
			t.Fatalf("breaks CH-12: %d segments: %q", n, s)
		}
		if !strings.HasSuffix(s, "HELP for commands.") || strings.Count(s, "\n") != 4 {
			t.Fatalf("not three examples and HELP: %q", s)
		}
		for _, c := range conn {
			if !strings.Contains(s, accountExamples[c]) {
				t.Fatalf("no example for %s: %q", c, s)
			}
		}
	}
}

// asOther runs f as a second phone on the box's Wi-Fi (another card
// holder), then switches back.
func (r *rig) asOther(f func()) {
	jar, ip := r.jar, r.ip
	r.jar, _ = cookiejar.New(nil)
	r.ip = "10.42.0.77:52000"
	defer func() { r.jar, r.ip = jar, ip }()
	f()
}

// REQ: ONB-6, CH-4, CRED-8, CH-7

// Once the owner's number is known, only the phone that paired continues
// setup: a second phone on the Wi-Fi can neither replace the number nor
// see the code-generator seed.
func TestOnlyThePairedPhoneContinuesSetup(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	page := html.UnescapeString(r.get("/setup"))
	code := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(page)[1]
	var otherCode string
	r.asOther(func() {
		p := html.UnescapeString(r.get("/setup"))
		otherCode = regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(p)[1]
	})
	if otherCode == code {
		t.Fatal("two phones share a pairing code")
	}
	r.srv.OfferText(ownerNum, "PAIR "+code)
	page = r.get("/setup")
	if !strings.Contains(page, "otpauth://") || !strings.Contains(page, "ending 0001") {
		t.Fatalf("paired phone does not continue: %s", page)
	}
	r.asOther(func() {
		p := r.get("/setup")
		if strings.Contains(p, "otpauth") || strings.Contains(p, "secret=") || !strings.Contains(p, "Setup is continuing on the phone") {
			t.Fatalf("second phone sees enrollment: %s", p)
		}
		r.post("/setup/number", url.Values{"number": {"+15550009999"}})
		r.post("/setup/number-code", url.Values{"code": {"123456"}})
		r.post("/setup/codes", url.Values{"code": {"123456"}})
		if !strings.Contains(r.setupErr(), "continuing on the phone") {
			t.Fatal("second phone's post not refused")
		}
	})
	if r.srv.setup.st.Owner != ownerNum || len(r.hooks.sent) != 0 || r.srv.setup.st.Codes {
		t.Fatalf("second phone changed setup: owner %q, texts %d", r.srv.setup.st.Owner, len(r.hooks.sent))
	}
	// The number fallback is refused once a number is paired, even from
	// the paired phone.
	r.post("/setup/number", url.Values{"number": {"+15550009999"}})
	if len(r.hooks.sent) != 0 || r.srv.setup.st.Owner != ownerNum {
		t.Fatal("number replaced after pairing")
	}
}

// Pairing by the card's setup code texts a page code; the phone that types
// it continues. Wrong page codes text a fresh one, within a bound.
func TestCardCodePairingIsClaimedWithThePageCode(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	r.get("/setup")
	reply, _ := r.srv.OfferText(ownerNum, "PAIR "+r.card.SetupCode)
	pc := regexp.MustCompile(`Page code: ([0-9]{6})\.`).FindStringSubmatch(reply)
	if pc == nil {
		t.Fatalf("no page code: %q", reply)
	}
	if n, gsm := modem.Segments(reply); !gsm || n > 2 {
		t.Fatalf("reply breaks CH-12: %q", reply)
	}
	if !strings.Contains(r.get("/setup"), "page code") {
		t.Fatal("no claim step")
	}
	r.asOther(func() {
		r.get("/setup")
		for i := 0; i < numberCodeTries; i++ {
			r.post("/setup/claim", url.Values{"code": {"000000"}})
		}
	})
	if len(r.hooks.sent) != 1 || !strings.HasPrefix(r.hooks.sent[0].Text, "agentOS page code:") || r.hooks.sent[0].To != ownerNum {
		t.Fatalf("no fresh page code texted to the owner: %+v", r.hooks.sent)
	}
	r.post("/setup/claim", url.Values{"code": {pc[1]}})
	if r.srv.setup.st.Device != "" {
		t.Fatal("replaced page code still accepted")
	}
	fresh := regexp.MustCompile(`[0-9]{6}`).FindString(r.hooks.sent[0].Text)
	r.post("/setup/claim", url.Values{"code": {fresh}})
	if !strings.Contains(r.get("/setup"), "otpauth://") {
		t.Fatal("claiming phone does not continue")
	}
	r.asOther(func() {
		if !strings.Contains(r.get("/setup"), "Setup is continuing on the phone") {
			t.Fatal("other phone not shut out after the claim")
		}
	})
}

// §8.1 step 6: a device-code sign-in alone finishes setup, once the
// provider reports it connected, when the owner comes back to the page.
func TestDeviceCodeSignInAloneFinishesSetup(t *testing.T) {
	r := newRig(t)
	r.hooks.device = true
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if r.hooks.finished != ownerNum {
		t.Fatal("setup did not finish after a device-code sign-in")
	}
	for i := 0; i < 3; i++ {
		r.do("GET", "/setup", nil)
		r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {"x"}})
	}
	if r.hooks.finishes != 1 {
		t.Fatalf("Finish called %d times", r.hooks.finishes)
	}
	// Device-code completion seen only on a later page load.
	r = newRig(t)
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	if r.hooks.finished != "" || r.hooks.private["anthropic"] {
		t.Fatal("finished before the sign-in, or private allowed while unticked")
	}
	r.hooks.mu.Lock()
	r.hooks.connected = true
	r.hooks.mu.Unlock()
	if loc := r.do("GET", "/setup", nil).Header().Get("Location"); loc != "/status" || r.hooks.finished != ownerNum {
		t.Fatalf("page load did not finish setup: %q", loc)
	}
}

// A lost setup state file never reopens setup on a box that has an owner.
func TestLostSetupStateDoesNotReopenSetup(t *testing.T) {
	r := newRig(t)
	r.hooks.setUp = true
	r.srv = r.open(&MemStore{})
	if loc := r.do("GET", "/setup", nil).Header().Get("Location"); loc != "/status" {
		t.Fatalf("setup reopened: %q", loc)
	}
}

// A reboot mid-setup resumes setup even though a code seed is already in
// the vault, and so does a reboot after starting over: AlreadySetUp counts
// only a completed Finish (second re-review on #32).
func TestRebootMidSetupKeepsSetupOpen(t *testing.T) {
	r := newRig(t)
	st := &MemStore{}
	r.srv = r.open(st)
	r.runSetupToAI()
	r.srv = r.open(st)
	if r.srv.setup.done() || !strings.Contains(r.get("/setup"), `name="private"`) {
		t.Fatal("reboot after enrollment closed setup before Finish")
	}
	r.asOther(func() {
		r.get("/setup")
		r.post("/setup/restart", url.Values{"secret": {r.card.SetupSecret}})
	})
	if r.srv.setup.st.Owner != "" {
		t.Fatal("restart refused")
	}
	r.srv = r.open(st)
	if r.srv.setup.done() || r.srv.setup.st.Owner != "" || r.srv.setup.st.Codes {
		t.Fatal("reboot after starting over closed setup or lost the restart")
	}
}

// Pairing codes are evicted oldest first; the setup cookie outlives a
// browser restart; an enrollment checked against a seed that a restart
// replaced is not saved (second re-review on #32).
func TestSetupHousekeeping(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	w := r.do("GET", "/setup", nil)
	var maxAge int
	for _, c := range w.Result().Cookies() {
		if c.Name == setupCookie {
			maxAge = c.MaxAge
		}
	}
	if maxAge != int(SetupCookieFor/time.Second) {
		t.Fatalf("setup cookie Max-Age %d", maxAge)
	}
	pairCode := func() string {
		return regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(html.UnescapeString(r.get("/setup")))[1]
	}
	var second string
	r.asOther(func() { second = pairCode() })
	// With this phone's code that is one past the bound: only the
	// oldest (this phone's) goes.
	for i := 0; i < maxPairDevices-1; i++ {
		r.asOther(func() { pairCode() })
	}
	if r.srv.OfferText(ownerNum, "PAIR "+second); r.srv.setup.st.Owner != ownerNum {
		t.Fatal("newer phones voided a pending pairing code")
	}

	r = newRig(t)
	r.hooks.progress.Online = true
	r.srv.OfferText(ownerNum, "PAIR "+pairCode())
	m := regexp.MustCompile(`secret=([A-Z2-7]+)&`).FindStringSubmatch(html.UnescapeString(r.get("/setup")))
	seed, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	r.hooks.onConfirm = func() {
		r.hooks.onConfirm = nil
		r.asOther(func() {
			r.get("/setup")
			r.post("/setup/restart", url.Values{"secret": {r.card.SetupSecret}})
		})
	}
	r.post("/setup/codes", url.Values{"code": {owner.TOTP(seed, r.clock())}})
	if r.srv.setup.st.Codes || r.srv.setup.st.Owner != "" {
		t.Fatal("enrollment saved after setup started over")
	}
}

// failDone is a setup store whose save of Done fails.
type failDone struct{ MemStore }

func (f *failDone) Save(s SetupState) error {
	if s.Done {
		return errors.New("disk full")
	}
	return f.MemStore.Save(s)
}

// If saving Done fails after Finish, a reboot still finds setup closed and
// Finish is not run again (third re-review on #32).
func TestFailedDoneSaveKeepsSetupClosed(t *testing.T) {
	r := newRig(t)
	st := &failDone{}
	r.srv = r.open(st)
	r.runSetup()
	if s, _ := st.Load(); s.Done {
		t.Fatal("store did not fail")
	}
	r.srv = r.open(st)
	if loc := r.do("GET", "/setup", nil).Header().Get("Location"); loc != "/status" || !r.srv.setup.done() {
		t.Fatalf("setup reopened after reboot: %q", loc)
	}
	r.asOther(func() {
		r.post("/setup/restart", url.Values{"secret": {r.card.SetupSecret}})
	})
	if r.srv.setup.st.Owner != ownerNum || r.hooks.finishes != 1 {
		t.Fatalf("setup restarted or Finish re-run (%d)", r.hooks.finishes)
	}
}

// A Finish that fails after the owner channel exists still closes setup,
// and no setup step changes the state once setup is done, even one that
// passed the handler's check first (fourth re-review on #32).
func TestSetupClosesAfterLateFinishErrorAndStaysClosed(t *testing.T) {
	r := newRig(t)
	r.hooks.finishErr = errors.New("owner channel started, then a later step failed")
	r.runSetup()
	if !r.srv.setup.done() {
		t.Fatal("setup open after Finish failed late")
	}
	req := httptest.NewRequest("POST", "/setup/restart", strings.NewReader("secret="+url.QueryEscape(r.card.SetupSecret)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.srv.setup.restart(req, "other"); err == nil || r.srv.setup.st.Owner != ownerNum {
		t.Fatalf("restart after done: %v", err)
	}
	r.srv.setup.mu.Lock()
	err := r.srv.setup.save(func(s *SetupState) { s.Codes = false })
	r.srv.setup.mu.Unlock()
	if err != errSetupDone || !r.srv.setup.st.Codes {
		t.Fatalf("step changed setup after done: %v", err)
	}

	// A restart while Finish runs is refused.
	r = newRig(t)
	r.runSetupToAI()
	r.srv.setup.mu.Lock()
	r.srv.setup.finishing = true
	r.srv.setup.mu.Unlock()
	if err := r.srv.setup.restart(req, "other"); err == nil || r.srv.setup.st.Owner != ownerNum {
		t.Fatalf("restart during Finish: %v", err)
	}
}

// The owner can always find the box page: its name is in every page's
// footer, and the contact card links it (WIFI-del-a3).
func TestBoxPageAddressIsShown(t *testing.T) {
	r := newRig(t)
	if !strings.Contains(r.get("/status"), "http://"+DefaultPageName+"/") {
		t.Fatal("no box page name in the footer")
	}
	// Until HTTPS is up the name may not resolve, so the card links the
	// address the phone reached.
	if !strings.Contains(r.get("/box.vcf"), "URL:http://10.42.0.1/") {
		t.Fatal("no reached address in the contact card")
	}
}

// A device is signed out when the session locks.
func TestLockSignsDevicesOut(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(nil)
	r.post("/unlock", url.Values{"code": {r.code()}})
	r.get("/home")
	if err := r.ch.RequireUnlock(); err != nil {
		t.Fatal(err)
	}
	// A later unlock by text does not sign the device back in.
	r.ch.Handle(context.Background(), ownerNum, r.code())
	if !r.ch.SessionUnlocked(r.clock()) {
		t.Fatal("text unlock failed")
	}
	if w := r.do("GET", "/home", nil); w.Code != http.StatusSeeOther {
		t.Fatal("device still signed in after the session locked")
	}
}

func TestAllSetTextWithoutPrivateData(t *testing.T) {
	s := AllSetText([]string{"email"}, false)
	if strings.Contains(s, accountExamples["email"]) || strings.Count(s, "PUBLIC ") != 3 {
		t.Fatalf("private tasks suggested without a private-data provider: %q", s)
	}
	if n, gsm := modem.Segments(s); !gsm || n > 3 {
		t.Fatalf("breaks CH-12: %q", s)
	}
}

// The lost-device escape: another phone can start setup over only with the
// card's reset secret (the setup secret); the paired phone can without it.
func TestRestartSetupNeedsTheResetSecretElsewhere(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	page := html.UnescapeString(r.get("/setup"))
	r.srv.OfferText(ownerNum, "PAIR "+regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(page)[1])
	r.asOther(func() {
		if !strings.Contains(r.get("/setup"), "Lost that phone?") {
			t.Fatal("no lost-device escape offered")
		}
		r.post("/setup/restart", url.Values{"secret": {"AAAA-BBBB"}})
		if r.srv.setup.st.Owner != ownerNum {
			t.Fatal("restart without the reset secret")
		}
		r.post("/setup/restart", url.Values{"secret": {strings.ToLower(r.card.SetupSecret)}})
		if r.srv.setup.st.Owner != "" {
			t.Fatal("reset secret did not restart setup")
		}
		p := html.UnescapeString(r.get("/setup"))
		code := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(p)[1]
		r.srv.OfferText("+15550000002", "PAIR "+code)
		if !strings.Contains(r.get("/setup"), "otpauth://") {
			t.Fatal("new phone does not continue after restart")
		}
	})
	if strings.Contains(r.get("/setup"), "otpauth://") {
		t.Fatal("old phone still continues after restart")
	}
	// Wrong reset secrets are bounded.
	for i := 0; i < ResetTriesPerHour+1; i++ {
		r.post("/setup/restart", url.Values{"secret": {"WRONG"}})
	}
	r.post("/setup/restart", url.Values{"secret": {r.card.SetupSecret}})
	if r.srv.setup.st.Owner == "" {
		t.Fatal("reset secret accepted past the bound")
	}
}
