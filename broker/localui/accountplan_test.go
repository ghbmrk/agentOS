package localui

import (
	"context"
	"errors"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/accounts"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: TN-account-plan-6, CLK-9, CH-7, CH-9, DEV-8

// planClerk is the mail clerk behind agentosd: the Connect page's sign-in,
// and the plan (localsrv.AccountPlanner).
type planClerk struct {
	clerkSignIn
	plan  localapi.AccountPlanned
	err   error
	plans int
}

func (c *planClerk) Plan(context.Context) (localapi.AccountPlanned, error) {
	c.plans++
	return c.plan, c.err
}

// planItems is clerk/run's plan for a Gmail account whose mail shows
// Google, with the device-implied utility: built from the shipped table.
func planItems(t *testing.T, connected bool) []localapi.AccountPlanItem {
	t.Helper()
	tbl, err := accounts.Known()
	if err != nil {
		t.Fatal(err)
	}
	var out []localapi.AccountPlanItem
	for _, it := range accounts.Build(tbl, []string{"accounts.google.com"}, []string{"thermostat"}) {
		out = append(out, localapi.AccountPlanItem{ID: it.ID, Name: it.Name, Kind: it.Kind, Group: it.Group, Source: string(it.Source),
			Preselected: it.Preselected, Label: it.Label, Advice: it.Advice, Connected: connected && it.ID == "gmail"})
	}
	return out
}

// accountPlanRig is a set-up box whose page reaches the plan through agentosd,
// with connect as its declared Connect steps.
func accountPlanRig(t *testing.T, connect ...ConnectDeclaration) (*rig, *planClerk) {
	t.Helper()
	r := newRig(t)
	late := &lateOwner{}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Accounts: AgentosdAccounts{Owner: late}, Connect: connect,
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	c := &planClerk{plan: localapi.AccountPlanned{Items: planItems(t, false)}}
	late.o = r.pageWith(r.ch, localsrv.Config{Accounts: map[string]localsrv.AccountSignIn{"gmail": c}})
	r.srv.SetOwner(late.o)
	return r, c
}

// TN-account-plan-6: one screen, Set up and Later on each item, its label
// and advice. Only a signed-in phone sees it (CH-7) and every choice is a
// form post (CH-9). The card, wallet and mailbox carry no power label
// (#3197 item 3). Set up on Gmail goes to its Connect step; Set up on an
// item with no route lists it with the fixed line; Later leaves it
// unconnected.
func TestAccountPlanScreenSetUpAndLater(t *testing.T) {
	r, c := accountPlanRig(t, GmailConnect)
	if w := r.do("GET", "/account-plan/", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") || c.plans != 0 {
		t.Fatalf("without sign-in: %d %s, %d plan calls", w.Code, w.Header().Get("Location"), c.plans)
	}
	if w := r.post("/account-plan/", url.Values{"id": {"payment-wallet"}, "choice": {"later"}}); w.Code != http.StatusSeeOther || c.plans != 0 {
		t.Fatalf("a post without sign-in: %d, %d plan calls", w.Code, c.plans)
	}
	r.signIn()
	p := html.UnescapeString(r.get("/account-plan/"))
	for _, want := range []string{"Payment card", "Payment wallet", "Give me an email address? About 1 minute.", "Gmail", "Electric utility",
		accounts.LabelNarrower, accounts.AdviceNarrower} {
		if !strings.Contains(p, want) {
			t.Fatalf("the screen lacks %q:\n%s", want, p)
		}
	}
	if n := strings.Count(p, accounts.LabelFull); n != 1 { // the utility's only: the card, wallet and mailbox show none
		t.Fatalf("%d Full power labels, want 1:\n%s", n, p)
	}
	if n := strings.Count(p, `value="setup"`); n != 5 || strings.Count(p, `value="later"`) != 5 {
		t.Fatalf("%d Set up buttons, want one per item:\n%s", n, p)
	}
	// Card (KEY-2), Gmail and the utility (ongoing) are suggested; the
	// wallet and the mailbox are not.
	if n := strings.Count(p, "Suggested"); n != 3 {
		t.Fatalf("%d suggested, want 3:\n%s", n, p)
	}
	if !strings.Contains(p, "Electric utility</b> <span class=\"muted\">Suggested") || strings.Contains(p, "1 minute.</b> <span") {
		t.Fatalf("preselection:\n%s", p)
	}

	w := r.post("/account-plan/", url.Values{"id": {"electric-utility"}, "choice": {"later"}})
	if p := html.UnescapeString(w.Body.String()); w.Code != 200 || !strings.Contains(p, planLater) {
		t.Fatalf("later: %d\n%s", w.Code, p)
	}
	w = r.post("/account-plan/", url.Values{"id": {"payment-wallet"}, "choice": {"setup"}})
	if p := html.UnescapeString(w.Body.String()); w.Code != 200 || !strings.Contains(p, planListed) || strings.Count(p, `value="setup"`) != 4 {
		t.Fatalf("set up with no route: %d\n%s", w.Code, p)
	}
	w = r.post("/account-plan/", url.Values{"id": {"gmail"}, "choice": {"setup"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/accounts/gmail" {
		t.Fatalf("set up Gmail: %d %q", w.Code, w.Header().Get("Location"))
	}
	if len(c.calls) != 0 {
		t.Fatalf("Set up began a sign-in itself: %v", c.calls)
	}
	// The choices stand when the page is opened again.
	if p := html.UnescapeString(r.get("/account-plan/")); !strings.Contains(p, planListed) || !strings.Contains(p, planLater) {
		t.Fatalf("reopened:\n%s", p)
	}

	// A connected account shows so, with no buttons.
	c.plan = localapi.AccountPlanned{Items: planItems(t, true)}
	if p := html.UnescapeString(r.get("/account-plan/")); !strings.Contains(p, "Connected.") || strings.Count(p, `value="setup"`) != 3 {
		t.Fatalf("connected:\n%s", p)
	}
	if w := r.post("/account-plan/", url.Values{"id": {"gmail"}, "choice": {"setup"}}); w.Code != 200 {
		t.Fatalf("set up a connected account: %d", w.Code)
	}

	// An item the plan does not hold, or a choice it does not know.
	for _, f := range []url.Values{{"id": {"bank"}, "choice": {"later"}}, {"id": {"gmail"}, "choice": {"connect"}}} {
		if w := r.post("/account-plan/", f); w.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", f, w.Code)
		}
	}

	// Grant death: no plan, the sign-in ended, and the reconnect step.
	c.plan = localapi.AccountPlanned{Reason: "reconnect"}
	p = html.UnescapeString(r.get("/account-plan/"))
	if !strings.Contains(p, "Your mail sign-in ended") || !strings.Contains(p, `href="/accounts/"`) || strings.Contains(p, "Payment card") {
		t.Fatalf("grant death:\n%s", p)
	}
	if w := r.post("/account-plan/", url.Values{"id": {"payment-wallet"}, "choice": {"later"}}); w.Code != 200 {
		t.Fatalf("a choice with no plan: %d", w.Code)
	}
	// The clerk silent: the fixed text, never its error.
	c.plan, c.err = localapi.AccountPlanned{Items: planItems(t, false)}, errors.New("accountsock: the mail clerk did not answer")
	if p := html.UnescapeString(r.get("/account-plan/")); !strings.Contains(p, planFailed) || strings.Contains(p, "accountsock") || strings.Contains(p, "Payment card") {
		t.Fatalf("silent clerk:\n%s", p)
	}
}

// TN-account-plan-ux (#3226, CH-12): each stop text names only a step that
// works and where to take it, as STATUS does (clerk/run seen.go). The
// Accounts button shows only for reconnect: the Gmail Connect list cannot
// fix an IMAP sign-in, which is set up again on the Wi-Fi page. A reason
// the page does not know gets the fixed failure text and no button.
func TestAccountPlanStopTextsNameOnlyStepsThatWork(t *testing.T) {
	r, c := accountPlanRig(t, GmailConnect)
	r.post("/unlock", url.Values{"code": {r.code()}})
	for _, tc := range []struct {
		reason, place string
		button        bool
	}{
		{"reconnect", "on the Accounts page", true},
		{"sign-in-refused", "on my Wi-Fi page", false},
		{"no-sign-in", "On my Wi-Fi page", false},
		{"something-new", "open this page again in a minute", false},
	} {
		text := planReason(tc.reason)
		if !strings.Contains(text, tc.place) {
			t.Errorf("%s: %q does not name %q", tc.reason, text, tc.place)
		}
		if tc.button != strings.Contains(text, "Accounts page") {
			t.Errorf("%s: %q names the Accounts page against its button (%v)", tc.reason, text, tc.button)
		}
		if tc.reason != "reconnect" && strings.Contains(text, "Sign in again") {
			t.Errorf("%s: %q names the Gmail sign-in", tc.reason, text)
		}
		// A provider that allows only its own sign-in page cannot be used
		// over IMAP; the owner is told so, as STATUS does (#3256, CH-12).
		if caveat := "If your provider only allows signing in through its own page, I can't use this account yet."; (tc.reason == "no-sign-in") != strings.Contains(text, caveat) {
			t.Errorf("%s: %q against the own-page caveat", tc.reason, text)
		}
		c.plan, c.err = localapi.AccountPlanned{Reason: tc.reason}, nil
		p := html.UnescapeString(r.get("/account-plan/"))
		if !strings.Contains(p, text) || strings.Contains(p, `href="/accounts/"`) != tc.button || strings.Contains(p, "Payment card") {
			t.Errorf("%s: page (button %v):\n%s", tc.reason, tc.button, p)
		}
	}
}

// TN-account-plan-6, TN-account-plan-5: Set up opens only a sign-in the
// known-services table declares for the item. A Connect step whose consent
// host is not one of the entry's sign-in hosts, or names a port, is refused
// before any link is shown, and nothing is recorded.
func TestAccountPlanSetUpRefusesUndeclaredLink(t *testing.T) {
	for _, host := range []string{"accounts.google.com.evil.test", "accounts.google.com:8443", "evil.test"} {
		d := GmailConnect
		d.ConsentHost = host
		r, c := accountPlanRig(t, d)
		r.signIn()
		w := r.post("/account-plan/", url.Values{"id": {"gmail"}, "choice": {"setup"}})
		p := html.UnescapeString(w.Body.String())
		if w.Code != 200 || !strings.Contains(p, planRefused) || strings.Contains(p, planListed) || strings.Contains(p, host) || len(c.calls) != 0 {
			t.Fatalf("consent host %q: %d %q\n%s", host, w.Code, w.Header().Get("Location"), p)
		}
	}
	// With no Connect step for it, Gmail is listed, as any item with no
	// route the box has: no link at all.
	r, _ := accountPlanRig(t, ConnectDeclaration{ID: "other", Name: "Other", AppName: "a", ConsentHost: "accounts.other.test",
		Uses: []ConnectUse{{ID: "watch", Name: "Watch", Gets: []string{"x"}}}})
	r.signIn()
	if p := html.UnescapeString(r.post("/account-plan/", url.Values{"id": {"gmail"}, "choice": {"setup"}}).Body.String()); !strings.Contains(p, planListed) {
		t.Fatalf("no Connect step:\n%s", p)
	}
}
