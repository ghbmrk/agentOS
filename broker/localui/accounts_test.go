package localui

import (
	"context"
	"errors"
	"html"
	"math/rand"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CLK-9, CLK-1, CH-7

// clerkSignIn stands in for the mail clerk's owner socket behind agentosd
// (localsrv.AccountSignIn).
type clerkSignIn struct {
	mu     sync.Mutex
	calls  []string
	reg    *localapi.AccountRegistration
	finish string
	err    error
}

func (c *clerkSignIn) Begin(_ context.Context, use string, reg *localapi.AccountRegistration) (string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls, c.reg = append(c.calls, "begin "+use), reg
	return testConsent, "", c.err
}

func (c *clerkSignIn) Finish(_ context.Context, use, pasted string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "finish "+use+" "+pasted)
	return c.finish, c.err
}

// lateOwner is the page's localui.sock, set once the rig's channel runs.
type lateOwner struct{ o Owner }

func (l *lateOwner) Call(ctx context.Context, op string, args, out any) error {
	return l.o.Call(ctx, op, args, out)
}

// agentosdConnectRig is connectRig with the page's Accounts going through
// agentosd's ops (localsrv) to the clerk, as on a box.
func agentosdConnectRig(t *testing.T) (*rig, *clerkSignIn, *lateOwner) {
	t.Helper()
	r := newRig(t)
	late := &lateOwner{}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Accounts: AgentosdAccounts{Owner: late}, Connect: []ConnectDeclaration{GmailConnect},
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	c := &clerkSignIn{finish: "signedin watch"}
	late.o = r.pageWith(r.ch, localsrv.Config{Accounts: map[string]localsrv.AccountSignIn{"gmail": c}})
	r.srv.SetOwner(late.o)
	return r, c, late
}

// #3006: on a box the Connect page's frames go through agentosd, which
// checks the phone's session, to the clerk: the registration at Begin, the
// pasted address and the confirmed use at Finish.
func TestTheConnectPageReachesTheClerkThroughAgentosd(t *testing.T) {
	r, c, _ := agentosdConnectRig(t)
	r.signIn()
	reg := registration()
	reg.Set("use", "watch")
	w := r.post("/accounts/gmail", reg)
	if p := html.UnescapeString(w.Body.String()); w.Code != 200 || !strings.Contains(p, `href="`+testConsent+`"`) {
		t.Fatalf("begin: %d\n%s", w.Code, p)
	}
	if c.reg == nil || *c.reg != (localapi.AccountRegistration{ID: "id-1.apps.googleusercontent.com", Secret: "GOCSPX-synthetic"}) {
		t.Fatalf("registration: %+v", c.reg)
	}
	const landed = "http://127.0.0.1:8521/agentos?state=s&code=c"
	w = r.post("/accounts/gmail", url.Values{"step": {"connect"}, "use": {"watch"}, "pasted": {landed}})
	if p := html.UnescapeString(w.Body.String()); w.Code != 200 || !strings.Contains(p, "Gmail is connected") {
		t.Fatalf("connect: %d\n%s", w.Code, p)
	}
	if !slices.Equal(c.calls, []string{"begin watch", "finish watch " + landed}) {
		t.Fatalf("clerk calls %v", c.calls)
	}
	// Signing in again sends no registration.
	if w := r.post("/accounts/gmail", url.Values{"step": {"begin"}, "use": {"watch"}, "again": {"1"}}); w.Code != 200 || c.reg != nil {
		t.Fatalf("again: %d %+v", w.Code, c.reg)
	}
}

// The page is treated as compromised: a frame without a session agentosd
// minted never reaches the clerk, whatever the page sends, and the page
// shows the generic texts.
func TestAPageWithoutASessionCannotConnectAnAccount(t *testing.T) {
	_, c, late := agentosdConnectRig(t)
	a := AgentosdAccounts{Owner: late}
	ctx := context.Background()
	for _, tok := range []string{"", strings.Repeat("ab", localapi.TokenBytes)} {
		if _, d := a.Begin(ctx, tok, "gmail", "watch", &AccountRegistration{ID: "i", Secret: "s"}); d != localapi.ErrFailed {
			t.Fatalf("begin with token %q: %q", tok, d)
		}
		if d := a.Finish(ctx, tok, "gmail", "watch", "http://127.0.0.1/?code=c"); d != localapi.ErrFailed {
			t.Fatalf("finish with token %q: %q", tok, d)
		}
	}
	if len(c.calls) != 0 {
		t.Fatalf("reached the clerk: %v", c.calls)
	}
	if beginText(localapi.ErrFailed) != "Could not start the sign-in. Try again." || connectText(localapi.ErrFailed) != "That didn't go through. Start again below." {
		t.Fatal("a failure is not the generic text")
	}
}

// A clerk that does not answer shows the page's generic texts, never the
// error.
func TestTheConnectPageSaysTryAgainWhenTheClerkIsSilent(t *testing.T) {
	r, c, _ := agentosdConnectRig(t)
	r.signIn()
	c.err = errors.New("accountsock: the mail clerk did not answer")
	if p := html.UnescapeString(r.post("/accounts/gmail", registration()).Body.String()); !strings.Contains(p, "Could not start the sign-in. Try again.") || strings.Contains(p, "accountsock") {
		t.Fatalf("begin:\n%s", p)
	}
	w := r.post("/accounts/gmail", url.Values{"step": {"connect"}, "use": {"sort"}, "pasted": {"http://127.0.0.1:8521/agentos?state=s&code=c"}})
	if p := html.UnescapeString(w.Body.String()); !strings.Contains(p, "That didn't go through. Start again below.") || strings.Contains(p, "is connected") {
		t.Fatalf("connect:\n%s", p)
	}
}
