package localui

import (
	"context"
	"html"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/smsapi"
)

// REQ: ADP-12, CRED-1, CH-7

// sipCanary is a synthetic provider-generated password.
const sipCanary = "canary-sip-pw-7f3a9c21"

// fakeLine stands in for the vault process's second-line routes (egress
// K13): field checks with fixed reasons, a realm recorded by the first
// registration, and confirmation only of that realm.
type fakeLine struct {
	mu         sync.Mutex
	set        bool
	settings   sipsign.Settings
	password   string
	realm      string
	confirmed  bool
	waiting    bool
	removed    int
	calls      int
	setAt      time.Time
	now        func() time.Time
	sms        smsapi.Settings
	smsToken   string
	smsRemoved int
	// failSet and failStatus, when set, are what SetSecondLine and
	// SecondLineStatus return instead.
	failSet, failStatus error
}

func (f *fakeLine) SecondLineStatus(ctx context.Context) (SecondLineStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStatus != nil {
		return SecondLineStatus{}, f.failStatus
	}
	if !f.set {
		return SecondLineStatus{}, nil
	}
	return SecondLineStatus{Set: true, Settings: f.settings, RealmRecorded: f.realm != "", Realm: f.realm,
		RealmConfirmed: f.confirmed, WaitingForRegistration: f.waiting && f.realm == "", SetAt: f.setAt.Unix()}, nil
}

func (f *fakeLine) SetSecondLine(ctx context.Context, s sipsign.Settings, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failSet != nil {
		return f.failSet
	}
	s = s.Normalize()
	if s.Check() == sipsign.ErrServer {
		return &VaultError{400, "Enter the server as a host name and port, like sip.example.net:5061."}
	}
	if len(password) < 12 {
		return &VaultError{400, "Use the SIP password your provider generated, 12 to 256 characters. If it is shorter, have the provider generate a new one."}
	}
	f.set, f.settings, f.password, f.realm, f.confirmed, f.waiting = true, s, password, "", false, true
	if f.now != nil {
		f.setAt = f.now()
	}
	return nil
}

func (f *fakeLine) ConfirmRealm(ctx context.Context, realm string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.realm == "" || realm != f.realm {
		return &VaultError{409, "That is not the provider name the box recorded. Check it again on this page."}
	}
	f.confirmed = true
	return nil
}

func (f *fakeLine) RemoveSecondLine(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.set, f.settings, f.password, f.realm, f.confirmed = false, sipsign.Settings{}, "", "", false
	f.removed++
	return nil
}

func (f *fakeLine) SMSStatus(ctx context.Context) (SMSStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return SMSStatus{Set: f.sms != (smsapi.Settings{}), Settings: f.sms}, nil
}

func (f *fakeLine) SetSMS(ctx context.Context, s smsapi.Settings, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	s = s.Normalize()
	if s.Check() == smsapi.ErrAccount {
		return &VaultError{400, "Copy the account ID exactly from your provider: for Twilio the Account SID (AC and 32 characters), for SignalWire the Project ID."}
	}
	f.sms, f.smsToken = s, token
	return nil
}

func (f *fakeLine) RemoveSMS(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.sms, f.smsToken = smsapi.Settings{}, ""
	f.smsRemoved++
	return nil
}

func (f *fakeLine) register(realm string) {
	f.mu.Lock()
	f.realm = realm
	f.mu.Unlock()
}

// lineRig is a set-up box, signed in on this phone, whose vault is open
// and whose local UI serves the second line's page.
func lineRig(t *testing.T) (*rig, *fakeVault, *fakeLine) {
	t.Helper()
	r := newRig(t)
	fv := newFakeVault(r.card.VaultPassphrase)
	fv.state = "open"
	fl := &fakeLine{now: r.clock}
	s, err := New(Config{AP: testAP(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Vault: fv, SecondLine: fl, Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, fv, fl
}

func (r *rig) signIn() {
	r.t.Helper()
	if w := r.post("/unlock", url.Values{"code": {r.code()}, "next": {"/home"}}); w.Header().Get("Location") != "/home" {
		r.t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
	}
}

func lineForm(server string) url.Values {
	return url.Values{"step": {"set"}, "server": {server}, "domain": {"voip.example.net"}, "user": {"acct1001"},
		"number": {"+1 555 010 4477"}, "password": {sipCanary}}
}

// The owner sets the second line up on the box's Wi-Fi page: the page
// says what to change at the provider first, the box records the realm
// the first registration meets, and texts and calls wait until the owner
// confirms it (sipline SL3, egress K13).
func TestTheSecondLineIsSetUpAndItsRealmConfirmedOnTheWiFiPage(t *testing.T) {
	r, _, fl := lineRig(t)
	if w := r.do("GET", "/second-line/", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") {
		t.Fatalf("without sign-in: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := r.post("/second-line/", lineForm("sip.example.net")); w.Code != http.StatusSeeOther || fl.calls != 0 {
		t.Fatalf("a post without sign-in reached the vault process: %d, %d calls", w.Code, fl.calls)
	}
	r.signIn()
	if !strings.Contains(r.get("/home"), `href="/second-line/"`) {
		t.Fatal("home does not list the second line")
	}
	p := r.get("/second-line/")
	for _, want := range []string{"turn on encrypted calls (SRTP)", "turn off voicemail", `name="password"`, `type="password"`} {
		if !strings.Contains(p, want) {
			t.Fatalf("setup page lacks %q:\n%s", want, p)
		}
	}

	w := r.post("/second-line/", lineForm("sip.example.net"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/second-line/" {
		t.Fatalf("set: %d %s", w.Code, w.Body.String())
	}
	if fl.password != sipCanary || fl.settings.Server != "sip.example.net:5061" || fl.settings.Number != "+15550104477" {
		t.Fatalf("stored %+v", fl.settings)
	}
	p = r.get("/second-line/")
	if !strings.Contains(p, "Waiting for the box to sign in to your provider") || !strings.Contains(p, `http-equiv="refresh"`) {
		t.Fatalf("waiting page:\n%s", p)
	}
	if strings.Contains(p, sipCanary) {
		t.Fatal("the page shows the password")
	}

	fl.register("voip.example.net")
	p = r.get("/second-line/")
	for _, want := range []string{"voip.example.net", "matches the domain you entered", "Texts and calls start once you confirm"} {
		if !strings.Contains(p, want) {
			t.Fatalf("realm page lacks %q:\n%s", want, p)
		}
	}
	if w := r.post("/second-line/", url.Values{"step": {"confirm"}, "realm": {"other.example"}}); !strings.Contains(w.Body.String(), "not the provider name the box recorded") || fl.confirmed {
		t.Fatalf("a different realm: %s", w.Body.String())
	}
	if w := r.post("/second-line/", url.Values{"step": {"confirm"}, "realm": {"voip.example.net"}}); w.Code != http.StatusSeeOther || !fl.confirmed {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	p = r.get("/second-line/")
	if !strings.Contains(p, "The second line is ready") || !strings.Contains(p, "15550104477") {
		t.Fatalf("ready page:\n%s", p)
	}
	for _, p := range r.seen {
		if strings.Contains(p, sipCanary) {
			t.Fatal("a page carried the password")
		}
	}
}

// A realm that differs from the domain is shown with that said, and one
// with control or invisible characters is shown escaped, so a provider
// (or anyone on the path before TLS is checked) cannot make it read as
// another name (security on CRED-1's realm check).
func TestTheRecordedRealmIsShownSoItCannotPassForAnotherName(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	r.post("/second-line/", lineForm("sip.example.net"))
	fl.register("asterisk")
	if p := r.get("/second-line/"); !strings.Contains(p, "differs from the domain you entered") || !strings.Contains(p, "asterisk") {
		t.Fatalf("differing realm:\n%s", p)
	}
	fl.register("voip.example.net\u202egro.live")
	p := r.get("/second-line/")
	shown := regexp.MustCompile(`calls itself <b class="mono">([^<]*)</b>`).FindStringSubmatch(p)
	if shown == nil || strings.Contains(shown[1], "\u202e") || !strings.Contains(shown[1], `\u202e`) {
		t.Fatalf("bidi control shown raw:\n%s", p)
	}
	if strings.Contains(p, "matches the domain") {
		t.Fatal("a spoofed realm reads as matching")
	}
	// The hidden field carries the realm exactly, so confirming still
	// names what the vault process recorded.
	if w := r.post("/second-line/", url.Values{"step": {"confirm"}, "realm": {"voip.example.net\u202egro.live"}}); w.Code != http.StatusSeeOther || !fl.confirmed {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
}

// Refusals show the vault process's fixed reason, keep what the owner
// typed except the password, and never echo the password.
func TestSetupRefusalsKeepTheFormButNotThePassword(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	w := r.post("/second-line/", lineForm("sip example net"))
	b := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(b, "Enter the server as a host name and port") {
		t.Fatalf("refusal: %d %s", w.Code, b)
	}
	if !strings.Contains(b, `value="acct1001"`) || !strings.Contains(b, `value="voip.example.net"`) || strings.Contains(b, sipCanary) {
		t.Fatalf("form not kept, or password echoed:\n%s", b)
	}
	f := lineForm("sip.example.net")
	f.Set("password", "short")
	if b := r.post("/second-line/", f).Body.String(); !strings.Contains(b, "Use the SIP password your provider generated") || fl.set {
		t.Fatalf("weak password: %s", b)
	}
}

// With the vault locked the page asks for an unlock first and sends
// nothing to the vault process; with the vault process down it says the
// box is starting.
func TestTheSecondLinePageNeedsTheVaultOpen(t *testing.T) {
	r, fv, fl := lineRig(t)
	r.signIn()
	fv.mu.Lock()
	fv.state = "locked"
	fv.mu.Unlock()
	p := r.get("/second-line/")
	if !strings.Contains(p, `href="/unlock/vault"`) || strings.Contains(p, `name="password"`) {
		t.Fatalf("locked page:\n%s", p)
	}
	r.post("/second-line/", lineForm("sip.example.net"))
	if fl.calls != 0 {
		t.Fatal("a locked vault was sent the account")
	}
	fv.mu.Lock()
	fv.down = true
	fv.mu.Unlock()
	if p := r.get("/second-line/"); !strings.Contains(p, "still starting") {
		t.Fatalf("down page:\n%s", p)
	}
}

// Past the registration window with no realm, the page says how to start
// again; removing the account clears it, and setting up again shows the
// form.
func TestASilentProviderAndRemoval(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	r.post("/second-line/", lineForm("sip.example.net"))
	fl.mu.Lock()
	fl.waiting = false
	fl.mu.Unlock()
	p := r.get("/second-line/")
	if !strings.Contains(p, "didn't reach your provider") || strings.Contains(p, `http-equiv="refresh"`) {
		t.Fatalf("expired window:\n%s", p)
	}
	if !strings.Contains(p, `name="password"`) {
		t.Fatal("no way to set it up again")
	}
	if w := r.post("/second-line/", url.Values{"step": {"remove"}, "confirm": {"1"}}); w.Code != http.StatusSeeOther || fl.removed != 1 || fl.set {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	if p := r.get("/second-line/"); !strings.Contains(p, "turn off voicemail") {
		t.Fatalf("after removal:\n%s", p)
	}
	if w := r.post("/second-line/", url.Values{"step": {"other"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown step: %d", w.Code)
	}
}

// Without a second line configured the page does not exist, and a second
// line needs the vault socket it lives on.
func TestNoSecondLineWithoutItsSocket(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	r.signIn()
	if strings.Contains(r.get("/home"), "second-line") {
		t.Fatal("home lists a second line")
	}
	if w := r.do("GET", "/second-line/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("page served: %d", w.Code)
	}
	if _, err := New(Config{AP: testAP(), Hooks: r.hooks, Store: &MemStore{}, SecondLine: &fakeLine{}, Now: time.Now}); err == nil {
		t.Fatal("a second line without the vault socket")
	}
}

// confirmAsRendered posts the confirm form's hidden realm exactly as the
// page renders it, as a browser would.
func (r *rig) confirmAsRendered() *httptest.ResponseRecorder {
	r.t.Helper()
	m := regexp.MustCompile(`name="realm" value="([^"]*)"`).FindStringSubmatch(r.get("/second-line/"))
	if m == nil {
		r.t.Fatal("no confirm form")
	}
	return r.post("/second-line/", url.Values{"step": {"confirm"}, "realm": {html.UnescapeString(m[1])}})
}

// L3 SHOULD 4 on #139: the confirm form carries the recorded realm
// exactly, so even a realm shown escaped can be confirmed from the page.
func TestTheConfirmFormCarriesTheRecordedRealm(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	r.post("/second-line/", lineForm("sip.example.net"))
	fl.register("voip.example.net\u202egro.live \"x\" <y>")
	if w := r.confirmAsRendered(); w.Code != http.StatusSeeOther || !fl.confirmed {
		t.Fatalf("confirm as rendered: %d %s", w.Code, w.Body.String())
	}
}

// L3 SHOULD 5 on #139: a realm matches only when it is plain and equal,
// ignoring ASCII case, to the domain or the server's host. A Kelvin sign
// folds to "k" but is not a match.
func TestOnlyAPlainEqualRealmMatches(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	f := lineForm("sip.example.net")
	f.Set("domain", "kite.example.net")
	r.post("/second-line/", f)
	for realm, match := range map[string]bool{
		"kite.example.net":      true,
		"KITE.example.net":      true,
		"sip.example.net":       true,
		"\u212Aite.example.net": false,
		"other.example.net":     false,
		strings.Repeat("a", 81): false,
	} {
		fl.register(realm)
		p := r.get("/second-line/")
		if got := strings.Contains(p, "matches the domain you entered"); got != match {
			t.Errorf("%q: match %v", realm, got)
		}
	}
	// Past 80 bytes even a plain realm is shown quoted.
	fl.register(strings.Repeat("a", 81))
	if p := r.get("/second-line/"); !strings.Contains(p, "&#34;"+strings.Repeat("a", 81)+"&#34;") {
		t.Fatal("a long realm shown unquoted")
	}
}

// L3 SHOULDs 2, 3 and 6 on #139: replies that are not the vault process's
// owner wording never reach the page, a vault that locks mid-request reads
// as locked, and other paths are not found.
func TestTheSecondLinePageHidesInternalReplies(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	for _, err := range []error{
		&VaultError{409, "the vault is locked"},
		&VaultError{500, "internal error"},
		&VaultError{400, ""},
	} {
		fl.mu.Lock()
		fl.failSet = err
		fl.mu.Unlock()
		b := r.post("/second-line/", lineForm("sip.example.net")).Body.String()
		if !strings.Contains(html.UnescapeString(b), "That didn't go through. Try again.") {
			t.Fatalf("%v shown as:\n%s", err, b)
		}
		for _, internal := range []string{"internal error", "the vault is locked", "vault process"} {
			if strings.Contains(b, internal) {
				t.Fatalf("%v shows %q", err, internal)
			}
		}
	}
	fl.mu.Lock()
	fl.failSet, fl.failStatus = nil, &VaultError{409, "the vault is locked"}
	fl.mu.Unlock()
	if p := r.get("/second-line/"); !strings.Contains(p, `href="/unlock/vault"`) || strings.Contains(p, "still starting") {
		t.Fatalf("locked mid-request:\n%s", p)
	}
	if w := r.do("GET", "/second-line/x", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown path: %d", w.Code)
	}
}

// UX-139-1: removing the second line asks first, in fixed wording; a
// single post without the confirmation removes nothing.
func TestRemovingTheSecondLineAsksFirst(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	r.post("/second-line/", lineForm("sip.example.net"))
	w := r.post("/second-line/", url.Values{"step": {"remove"}})
	b := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || fl.removed != 0 || !fl.set {
		t.Fatalf("removed without confirmation: %d, %d removals", w.Code, fl.removed)
	}
	for _, want := range []string{"Remove the second line? Texts and calls from +15550104477 stop, and you'll need the provider's password to add it again.",
		`name="confirm" value="1"`, ">Remove</button>", `href="/second-line/">Cancel</a>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("confirmation lacks %q:\n%s", want, b)
		}
	}
	if w := r.post("/second-line/", url.Values{"step": {"remove"}, "confirm": {"1"}}); w.Code != http.StatusSeeOther || fl.removed != 1 {
		t.Fatalf("confirmed removal: %d", w.Code)
	}
}

// UX-139-2: after 2 minutes of waiting for the first registration the
// page says what to check; the 30-minute line is unchanged.
func TestASlowRegistrationSaysWhatToCheck(t *testing.T) {
	r, _, _ := lineRig(t)
	r.signIn()
	r.post("/second-line/", lineForm("sip.example.net"))
	const still = "Still trying. If this doesn't change in a few minutes, check the server name, port and password with your provider."
	r.advance(119 * time.Second)
	if p := html.UnescapeString(r.get("/second-line/")); strings.Contains(p, still) {
		t.Fatal("the slow line before 2 minutes")
	}
	r.advance(time.Second)
	if p := html.UnescapeString(r.get("/second-line/")); !strings.Contains(p, still) || !strings.Contains(p, "Waiting for the box to sign in") {
		t.Fatalf("no slow line at 2 minutes:\n%s", p)
	}
}

// smsCanary is a synthetic texting token.
const smsCanary = "canary-sms-token-3c8e1f02"

// Potency PL1 on #102 (P2-3c part 5b): a provider whose SIP account
// carries no texts gets a texting account on the same page. The page
// says what US numbers need first, never shows the token, and asks
// before removing it.
func TestATextingAccountIsSetUpOnTheSecondLinePage(t *testing.T) {
	r, _, fl := lineRig(t)
	r.signIn()
	p := html.UnescapeString(r.get("/second-line/"))
	for _, want := range []string{"Texts over your provider's web API", "A2P 10DLC", `name="token"`, `value="twilio"`, `value="signalwire"`} {
		if !strings.Contains(p, want) {
			t.Fatalf("page lacks %q:\n%s", want, p)
		}
	}
	form := url.Values{"step": {"sms-set"}, "provider": {"twilio"}, "account": {"AC1"}, "number": {"+1 555 010 4477"}, "token": {smsCanary}}
	w := r.post("/second-line/", form)
	if b := html.UnescapeString(w.Body.String()); !strings.Contains(b, "Copy the account ID exactly") || strings.Contains(b, smsCanary) || !strings.Contains(b, `value="+1 555 010 4477"`) {
		t.Fatalf("refusal:\n%s", b)
	}
	form.Set("account", "AC" + "0123456789abcdef" + "0123456789abcdef")
	if w := r.post("/second-line/", form); w.Code != http.StatusSeeOther || fl.smsToken != smsCanary || fl.sms.Number != "+15550104477" {
		t.Fatalf("set: %d %+v", w.Code, fl.sms)
	}
	p = html.UnescapeString(r.get("/second-line/"))
	if !strings.Contains(p, "Texts go through Twilio from +15550104477.") || strings.Contains(p, smsCanary) {
		t.Fatalf("set page:\n%s", p)
	}
	w = r.post("/second-line/", url.Values{"step": {"sms-remove"}})
	if b := html.UnescapeString(w.Body.String()); fl.smsRemoved != 0 || !strings.Contains(b, "Remove the texting account? Texts from +15550104477 stop until you add it again with the provider's auth token.") {
		t.Fatalf("removed without asking: %s", b)
	}
	if w := r.post("/second-line/", url.Values{"step": {"sms-remove"}, "confirm": {"1"}}); w.Code != http.StatusSeeOther || fl.smsRemoved != 1 {
		t.Fatalf("confirmed removal: %d", w.Code)
	}
	for _, p := range r.seen {
		if strings.Contains(p, smsCanary) {
			t.Fatal("a page carried the token")
		}
	}
}
