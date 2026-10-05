package localui

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"html"
	"io"
	"math/rand"
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
	"github.com/ghbmrk/agentos/broker/journal"
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

// fakeHooks stands in for the uplink, modem, vault, host trust and provider
// adapters.
type fakeHooks struct {
	mu        sync.Mutex
	progress  Progress
	joined    string
	sent      []modem.SMS
	seed      []byte
	trusted   *bool
	keys      map[string]string
	finished  string
	connected bool
}

func (f *fakeHooks) Progress() Progress { f.mu.Lock(); defer f.mu.Unlock(); return f.progress }
func (f *fakeHooks) Networks() []string { return []string{"Home", "Neighbor"} }
func (f *fakeHooks) JoinNetwork(ssid, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.joined = ssid
	f.progress.Online = true
	return nil
}
func (f *fakeHooks) BoxNumber() string { return boxNum }
func (f *fakeHooks) HostInfo() string  { return "GEEKOM Air12, 8 GB" }
func (f *fakeHooks) Send(to, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, modem.SMS{To: to, Text: text})
	return nil
}
func (f *fakeHooks) SaveCodeSeed(s []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seed = append([]byte(nil), s...)
	return nil
}
func (f *fakeHooks) TrustHost(t bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trusted = &t
	return nil
}
func (f *fakeHooks) Providers() []Provider {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []Provider{{ID: "anthropic", Name: "Anthropic", APIKey: true, DeviceCode: true, Connected: f.connected},
		{ID: "openai", Name: "OpenAI", APIKey: true}}
}
func (f *fakeHooks) ConnectAPIKey(id, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil {
		f.keys = map[string]string{}
	}
	f.keys[id] = key
	f.connected = true
	return nil
}
func (f *fakeHooks) StartDeviceCode(id string) (string, string, error) {
	return "https://example.invalid/device", "WXYZ-1234", nil
}
func (f *fakeHooks) Finish(n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished = n
	return nil
}

type fakeEngine struct {
	mu      sync.Mutex
	stopped bool
}

func (e *fakeEngine) Stop(context.Context) (journal.StopReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
	return journal.StopReport{}, nil
}
func (e *fakeEngine) Resume() error          { e.mu.Lock(); defer e.mu.Unlock(); e.stopped = false; return nil }
func (e *fakeEngine) Stopped() bool          { e.mu.Lock(); defer e.mu.Unlock(); return e.stopped }
func (e *fakeEngine) List() []journal.Status { return nil }

type rig struct {
	t     *testing.T
	mu    sync.Mutex
	now   time.Time
	hooks *fakeHooks
	srv   *Server
	card  *card.Card
	eng   *fakeEngine
	ch    *owner.Channel
	jar   http.CookieJar
	seen  []string // every page body served, for the ONB-1 scan
}

func newRig(t *testing.T) *rig {
	t.Helper()
	c, err := card.Generate(rand.New(rand.NewSource(7)))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), card: c, eng: &fakeEngine{},
		hooks: &fakeHooks{progress: Progress{Phase: "updating"}}}
	r.srv = r.open(&MemStore{})
	r.jar, _ = cookiejar.New(nil)
	return r
}

func (r *rig) open(st SetupStore) *Server {
	s, err := New(Config{AP: testAP(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: st,
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
	req.RemoteAddr = phoneIP
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	u, _ := url.Parse("http://10.42.0.1/")
	for _, c := range r.jar.Cookies(u) {
		req.AddCookie(c)
	}
	for _, m := range mod {
		m(req)
	}
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
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
	r.srv.SetOwner(ch)
}

// code is the owner's code generator; each call moves to the next step.
func (r *rig) code() string {
	r.advance(30 * time.Second)
	return owner.TOTP(r.hooks.seed, r.clock())
}

// runSetup walks §8.1 steps 5 and 6 as the owner would.
func (r *rig) runSetup() {
	t := r.t
	t.Helper()
	if loc := r.do("GET", "/", nil).Header().Get("Location"); loc != "/setup" {
		t.Fatalf("root before setup: %q", loc)
	}
	// Home network.
	if !strings.Contains(r.get("/setup"), "Home network") {
		t.Fatal("network step not first")
	}
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
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
	m = regexp.MustCompile(`href="otpauth://totp/AgentOS:AgentOS-7K3M\?secret=([A-Z2-7]+)&issuer=AgentOS`).FindStringSubmatch(page)
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
		t.Fatal("seed not handed to the vault")
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
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	if p := r.get("/setup"); !strings.Contains(p, "WXYZ-1234") {
		t.Fatalf("device code not shown: %s", p)
	}
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	if r.hooks.keys["anthropic"] != apiCanary || r.hooks.finished != ownerNum {
		t.Fatalf("setup did not finish: keys=%v finished=%q", len(r.hooks.keys), r.hooks.finished)
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
	r.post("/setup/codes", url.Values{"code": {"123456"}})
	if string(r.hooks.seed) == "" || r.srv.setup.seed != nil {
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
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"x"}})
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
	if !ok || !strings.HasPrefix(reply, "AgentOS is running on") {
		t.Fatalf("card setup code: %q", reply)
	}
	// Once paired, nobody else can pair.
	if _, ok := r.srv.OfferText("+15550009999", "PAIR "+r.card.SetupCode); ok {
		t.Fatal("second pairing handled")
	}

	r = newRig(t)
	r.hooks.progress.Online = true
	r.post("/setup/number", url.Values{"number": {"+1 555 000 0001"}})
	if len(r.hooks.sent) != 1 || r.hooks.sent[0].To != ownerNum {
		t.Fatalf("no code texted: %+v", r.hooks.sent)
	}
	code := regexp.MustCompile(`[0-9]{6}`).FindString(r.hooks.sent[0].Text)
	r.post("/setup/number-code", url.Values{"code": {code}})
	if r.srv.setup.st.Owner != ownerNum {
		t.Fatal("typed number not paired")
	}
	if last := r.hooks.sent[len(r.hooks.sent)-1]; !strings.HasPrefix(last.Text, "AgentOS is running on") {
		t.Fatalf("no reply from the box's number: %q", last.Text)
	}
}

// Pairing guesses by text are bounded: after PairTriesPerHour wrong codes
// the box stays silent, even for the right code, until the hour passes.
func TestPairingGuessesAreBounded(t *testing.T) {
	r := newRig(t)
	for i := 0; i < PairTriesPerHour; i++ {
		if reply, _ := r.srv.OfferText("+15550009999", "PAIR AAAA-AAAA"); reply == "" {
			t.Fatalf("try %d: no reply", i)
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
	if w := r.post("/unlock", url.Values{"code": {"000000"}, "next": {"/review/"}}); !strings.Contains(w.Body.String(), "did not work") {
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
	if !strings.Contains(r.get("/status"), "Codes by text are locked") {
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
	r.post("/resume", url.Values{"code": {r.code()}})
	if r.eng.Stopped() {
		t.Fatal("RESUME with a right code did not resume")
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
	_ = phone
}

// REQ: CH-9, CH-7

// CH-9: the local UI answers only clients on the access point's subnet.
func TestOnlyAccessPointClientsReachTheUI(t *testing.T) {
	r := newRig(t)
	for _, from := range []string{"192.168.1.50:4000", "10.42.1.5:4000", "8.8.8.8:4000", "10.42.0.1:4000", "[::1]:4000", "garbage"} {
		w := r.do("GET", "/status", nil, func(q *http.Request) { q.RemoteAddr = from })
		if w.Code != http.StatusForbidden {
			t.Fatalf("request from %s: %d", from, w.Code)
		}
	}
	for _, bad := range []APConfig{
		{Iface: "wlan0", Addr: netip.MustParsePrefix("0.0.0.0/0"), SSID: "x", Password: "12345678"},
		{Iface: "wlan0", Addr: netip.MustParsePrefix("203.0.113.1/24"), SSID: "x", Password: "12345678"},
		{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/8"), SSID: "x", Password: "12345678"},
		{Iface: "", Addr: netip.MustParsePrefix("10.42.0.1/24"), SSID: "x", Password: "12345678"},
	} {
		if _, err := New(Config{AP: bad, Hooks: r.hooks, Store: &MemStore{}}); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

// The listener is bound to the access point interface: binding to an
// interface that does not exist fails rather than falling back to every
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
	if _, err := Listen(context.Background(), APConfig{Iface: "lo", Addr: netip.MustParsePrefix("127.0.0.1/8")}, 0); err == nil {
		t.Fatal("Listen accepted a loopback access point")
	}
}

// Captive-portal checks and DNS-rebinding requests (any other host name)
// are redirected to the box and never act; cross-site posts are refused.
func TestForeignHostsAndCrossSitePosts(t *testing.T) {
	r := newRig(t)
	for _, u := range []string{"http://captive.apple.com/hotspot-detect.html", "http://connectivitycheck.gstatic.com/generate_204", "http://evil.example/status"} {
		req := httptest.NewRequest("GET", u, nil)
		req.RemoteAddr = phoneIP
		w := httptest.NewRecorder()
		r.srv.ServeHTTP(w, req)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "http://10.42.0.1/" {
			t.Fatalf("%s: %d %s", u, w.Code, w.Header().Get("Location"))
		}
	}
	req := httptest.NewRequest("POST", "http://evil.example/stop", nil)
	req.RemoteAddr = phoneIP
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
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
		s := AllSetText(conn)
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
