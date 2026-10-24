package localui

import (
	"context"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CLK-9, CLK-1, CH-7, CH-9

// fakeAccounts stands in for the account clerks' sign-in (clerk.SignIn):
// Begin keeps what it was given, Finish answers the detail set.
type fakeAccounts struct {
	mu       sync.Mutex
	begun    []string
	reg      *AccountRegistration
	consent  string
	beginErr string
	pasted   []string
	finish   string
}

func (f *fakeAccounts) Begin(ctx context.Context, account, use string, reg *AccountRegistration) (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun = append(f.begun, account+" "+use)
	f.reg = reg
	if f.beginErr != "" {
		return "", f.beginErr
	}
	return f.consent, ""
}

func (f *fakeAccounts) Finish(ctx context.Context, account, pasted string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pasted = append(f.pasted, account+" "+pasted)
	return f.finish
}

const testConsent = "https://accounts.google.com/o/oauth2/v2/auth?client_id=id-1&scope=gmail.modify&state=s"

// connectRig is a set-up box, signed in on this phone, whose local UI
// serves the Connect page for Gmail.
func connectRig(t *testing.T) (*rig, *fakeAccounts) {
	t.Helper()
	r := newRig(t)
	fa := &fakeAccounts{consent: testConsent, finish: "signedin sort"}
	s, err := New(Config{AP: testAP(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Accounts: fa, Connect: []ConnectDeclaration{GmailConnect},
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, fa
}

func registration() url.Values {
	return url.Values{"step": {"begin"}, "use": {"sort"}, "id": {"id-1.apps.googleusercontent.com"}, "secret": {"GOCSPX-synthetic"},
		"email": {"owner@example.com"}, "check-3": {"1"}}
}

// #2853 (D-150, SPEC §12.1 step 7): the Connect step, drawn from the
// account's declaration. GET only shows; each step that changes anything
// is a form post (CH-9), and only a signed-in phone reaches it (CH-7).
func TestTheOwnerConnectsGmailOnTheLocalPage(t *testing.T) {
	r, fa := connectRig(t)
	if w := r.do("GET", "/accounts/gmail", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") {
		t.Fatalf("without sign-in: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := r.post("/accounts/gmail", registration()); w.Code != http.StatusSeeOther || len(fa.begun) != 0 {
		t.Fatalf("a post without sign-in reached the clerk: %d, %v", w.Code, fa.begun)
	}
	r.signIn()
	if !strings.Contains(r.get("/home"), `href="/accounts/"`) || !strings.Contains(r.get("/accounts/"), `href="/accounts/gmail"`) {
		t.Fatal("home does not lead to the Gmail Connect page")
	}

	// The registration steps, each console link opening on the owner's
	// own device, In production a checked step, and the line about
	// signing in.
	p := html.UnescapeString(r.get("/accounts/gmail"))
	for _, want := range []string{
		`href="https://console.cloud.google.com/projectcreate" target="_blank" rel="noopener noreferrer"`,
		`href="https://console.cloud.google.com/apis/library/gmail.googleapis.com"`,
		"agentOS at home", "In production", `name="check-3" value="1" required`,
		`name="id"`, `name="secret"`, `name="email"`, `value="watch"`, `value="archive"`, `value="sort"`,
		"This also lets me send mail as you.",
		"agentOS never asks you to sign in to Google inside it.",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("Connect page lacks %q", want)
		}
	}
	if len(fa.begun) != 0 {
		t.Fatal("a GET began a sign-in")
	}

	// The consent link, with the names Google's warning shows.
	w := r.post("/accounts/gmail", registration())
	p = html.UnescapeString(w.Body.String())
	if w.Code != 200 || !slices.Equal(fa.begun, []string{"gmail sort"}) || fa.reg == nil ||
		*fa.reg != (AccountRegistration{ID: "id-1.apps.googleusercontent.com", Secret: "GOCSPX-synthetic"}) {
		t.Fatalf("begin: %d %v %+v", w.Code, fa.begun, fa.reg)
	}
	for _, want := range []string{`href="` + testConsent + `" target="_blank" rel="noopener noreferrer"`,
		"agentOS at home", "owner@example.com", `name="step" value="paste"`, `name="pasted"`} {
		if !strings.Contains(p, want) {
			t.Errorf("consent step lacks %q", want)
		}
	}
	if strings.Contains(p, "GOCSPX-synthetic") {
		t.Fatal("the page shows the client secret back")
	}

	// Paste: a confirm screen naming what the box gets and never gets,
	// with Connect as a submit. Nothing reaches the clerk yet.
	const landed = "http://127.0.0.1:8521/agentos?state=s&code=c"
	w = r.post("/accounts/gmail", url.Values{"step": {"paste"}, "use": {"sort"}, "pasted": {landed}})
	p = html.UnescapeString(w.Body.String())
	if w.Code != 200 || len(fa.pasted) != 0 {
		t.Fatalf("paste: %d %v", w.Code, fa.pasted)
	}
	for _, want := range []string{"read every message and attachment", "send mail as you", "move messages to the trash",
		"delete mail forever", "change your Gmail settings", "your Google password or sign-in", "your account recovery",
		`name="step" value="connect"`, `<button>Connect</button>`} {
		if !strings.Contains(p, want) {
			t.Errorf("confirm screen lacks %q", want)
		}
	}

	// Connect hands the clerk the pasted address, and says what it did.
	w = r.post("/accounts/gmail", url.Values{"step": {"connect"}, "pasted": {landed}})
	if p := html.UnescapeString(w.Body.String()); w.Code != 200 || !slices.Equal(fa.pasted, []string{"gmail " + landed}) ||
		!strings.Contains(p, "Gmail is connected") || !strings.Contains(p, "Sort") {
		t.Fatalf("connect: %d %v\n%s", w.Code, fa.pasted, p)
	}
}

// The paste exchange changes state, so it is never a GET (CH-9), and a
// post with no step or another account's name is refused.
func TestConnectChangesNothingOnGet(t *testing.T) {
	r, fa := connectRig(t)
	r.signIn()
	q := url.Values{"step": {"connect"}, "pasted": {"http://127.0.0.1:8521/agentos?code=c"}}
	if w := r.do("GET", "/accounts/gmail?"+q.Encode(), nil); w.Code != 200 || len(fa.pasted) != 0 || len(fa.begun) != 0 {
		t.Fatalf("a GET reached the clerk: %d %v %v", w.Code, fa.begun, fa.pasted)
	}
	for _, form := range []url.Values{{"step": {"other"}}, {}} {
		if w := r.post("/accounts/gmail", form); w.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", form, w.Code)
		}
	}
	if w := r.do("GET", "/accounts/outlook", nil); w.Code != http.StatusNotFound {
		t.Fatalf("an undeclared account: %d", w.Code)
	}
	if w := r.post("/accounts/gmail", url.Values{"step": {"begin"}, "use": {"everything"}, "id": {"i"}, "secret": {"s"}, "check-3": {"1"}}); w.Code != http.StatusBadRequest || len(fa.begun) != 0 {
		t.Fatalf("an undeclared use: %d %v", w.Code, fa.begun)
	}
}

// The first sign-in needs the household's client and the In production
// step ticked (a client left in Testing loses its sign-in after 7 days,
// D-150 item 3); signing in again uses the client the clerk sealed.
func TestTheFirstConnectNeedsTheRegistration(t *testing.T) {
	r, fa := connectRig(t)
	r.signIn()
	for _, drop := range []string{"check-3", "id", "secret"} {
		f := registration()
		f.Del(drop)
		w := r.post("/accounts/gmail", f)
		if p := html.UnescapeString(w.Body.String()); w.Code != 200 || len(fa.begun) != 0 || !strings.Contains(p, `class="err"`) {
			t.Fatalf("without %s: %d %v", drop, w.Code, fa.begun)
		}
	}
	w := r.post("/accounts/gmail", url.Values{"step": {"begin"}, "use": {"watch"}, "again": {"1"}})
	if p := html.UnescapeString(w.Body.String()); w.Code != 200 || !slices.Equal(fa.begun, []string{"gmail watch"}) || fa.reg != nil ||
		!strings.Contains(p, testConsent) || !strings.Contains(p, "the email you gave as the developer contact") {
		t.Fatalf("sign in again: %d %v %+v", w.Code, fa.begun, fa.reg)
	}
}

// Each detail the clerk answers has owner wording that names a step that
// works (CH-12), and none shows the pasted address or a value back.
func TestConnectTextsForEachDetail(t *testing.T) {
	for mine, clerks := range map[string]string{dSignedIn: clerk.DSignedIn, dNoSignIn: clerk.DNoSignIn, dNotOurs: clerk.DNotOurs,
		dState: clerk.DState, dRefused: clerk.DRefused, dScope: clerk.DScope, dNoGrant: clerk.DNoGrant, dExchange: clerk.DExchange,
		dNoAccount: clerk.DNoAccount, dRegistered: clerk.DRegistered} {
		if mine != clerks {
			t.Errorf("page detail %q, clerk's %q", mine, clerks)
		}
	}
	r, fa := connectRig(t)
	r.signIn()
	const landed = "http://127.0.0.1:8521/agentos?state=SECRETSTATE&code=SECRETCODE"
	for _, d := range []string{clerk.DNoSignIn, clerk.DNotOurs, clerk.DState, clerk.DRefused, clerk.DScope, clerk.DNoGrant,
		clerk.DExchange, clerk.DExchange + " http 400", clerk.DCredential, "something new"} {
		fa.finish = d
		p := html.UnescapeString(r.post("/accounts/gmail", url.Values{"step": {"connect"}, "pasted": {landed}}).Body.String())
		if !strings.Contains(p, `class="err"`) || strings.Contains(p, "SECRET") || strings.Contains(p, "Gmail is connected") {
			t.Errorf("%q:\n%s", d, p)
		}
		if d != "something new" && d != clerk.DCredential && connectText(d) == connectText("something new") {
			t.Errorf("%q has no text of its own", d)
		}
	}
	for _, d := range []string{clerk.DRegistered, clerk.DNoAccount, clerk.DUndeclared} {
		fa.beginErr = d
		p := html.UnescapeString(r.post("/accounts/gmail", registration()).Body.String())
		if !strings.Contains(p, `class="err"`) || strings.Contains(p, "GOCSPX") || strings.Contains(p, "accounts.google.com/o/") {
			t.Errorf("begin %q:\n%s", d, p)
		}
	}
}

// The page links consent only on the declared provider's https host: a
// Begin that answered anything else shows no link.
func TestConnectLinksOnlyTheDeclaredConsentHost(t *testing.T) {
	r, fa := connectRig(t)
	r.signIn()
	for _, bad := range []string{"https://evil.example/o/oauth2/v2/auth?x=1", "http://accounts.google.com/o/oauth2/v2/auth",
		"javascript:alert(1)", "https://accounts.google.com.evil.example/", ""} {
		fa.consent = bad
		p := r.post("/accounts/gmail", registration()).Body.String()
		if strings.Contains(p, `name="pasted"`) || !strings.Contains(p, `class="err"`) {
			t.Errorf("%q was linked", bad)
		}
	}
}

// The declaration matches the clerk's: each use the page offers is one
// the Gmail sign-in declares, and the page's details are the clerk's.
func TestGmailConnectMatchesTheClerksDeclaration(t *testing.T) {
	var uses []string
	for _, u := range GmailConnect.Uses {
		uses = append(uses, u.ID)
	}
	slices.Sort(uses)
	sign := inbox.GmailSignIn(inbox.GmailConsent, "https://oauth2.googleapis.com/token", inbox.GmailRevoke, "s", nil, nil)
	var declared []string
	for u := range sign.Uses {
		declared = append(declared, u)
	}
	slices.Sort(declared)
	if !slices.Equal(uses, declared) {
		t.Fatalf("page uses %v, clerk uses %v", uses, declared)
	}
	if u, _ := url.Parse(inbox.GmailConsent); u.Host != GmailConnect.ConsentHost {
		t.Fatalf("consent host %q, clerk's %q", GmailConnect.ConsentHost, u.Host)
	}
	if err := GmailConnect.validate(); err != nil {
		t.Fatal(err)
	}
}

// A declaration that could link off https, repeats an ID or offers no
// use is refused, as is a Connect page with no clerk.
func TestConnectDeclarationsAreChecked(t *testing.T) {
	bad := GmailConnect
	bad.Steps = append(slices.Clone(bad.Steps), ConnectStep{Text: "x", Link: "http://console.cloud.google.com/"})
	noUse := GmailConnect
	noUse.Uses = nil
	for _, c := range []Config{
		{Accounts: &fakeAccounts{}},
		{Connect: []ConnectDeclaration{GmailConnect}},
		{Accounts: &fakeAccounts{}, Connect: []ConnectDeclaration{bad}},
		{Accounts: &fakeAccounts{}, Connect: []ConnectDeclaration{noUse}},
		{Accounts: &fakeAccounts{}, Connect: []ConnectDeclaration{GmailConnect, GmailConnect}},
	} {
		c.AP, c.Now = testAP(), time.Now
		if _, err := New(c); err == nil {
			t.Errorf("accepted %+v", c.Connect)
		}
	}
}
