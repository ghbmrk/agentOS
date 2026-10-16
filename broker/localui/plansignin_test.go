package localui

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localsrv"
)

// REQ: ONB-3, ONB-9, CRED-5

// pagePlan stands in for agentosd's plan sign-in: open while ready, and
// starting the provider's device-code flow.
type pagePlan struct {
	ready   bool
	err     error
	started int
}

func (p *pagePlan) Ready() bool { return p.ready }
func (p *pagePlan) Start(context.Context) (string, string, string, error) {
	p.started++
	if p.err != nil {
		return "", "", "", p.err
	}
	return "https://auth.openai.com/codex/device", "ABCD-EF23", "OpenAI", nil
}

func planRig(t *testing.T, p *pagePlan) *rig {
	r := newRig(t)
	r.runSetup()
	r.startChannel(nil)
	r.srv.SetOwner(InProcess(localsrv.New(localsrv.Config{Owner: r.ch, Now: r.clock, PlanSignIn: p}).Ops()))
	return r
}

// #1264 item 1: while the plan's sign-in is open the home page offers it
// again, behind a code-generator code, and shows the provider's link and
// code, labelled as the provider's; with the gate closed it offers nothing.
func TestHomeOffersThePlanSignInOnlyWhileOpen(t *testing.T) {
	p := &pagePlan{}
	r := planRig(t, p)
	r.post("/unlock", url.Values{"code": {r.code()}})
	if pg := r.get("/home"); strings.Contains(pg, `action="/plan/signin"`) {
		t.Fatalf("closed gate offers a sign-in:\n%s", pg)
	}
	p.ready = true
	pg := r.get("/home")
	for _, s := range []string{`action="/plan/signin"`, `name="code"`, "Sign in to ChatGPT"} {
		if !strings.Contains(pg, s) {
			t.Errorf("home lacks %q:\n%s", s, pg)
		}
	}
	pg = r.post("/plan/signin", nil).Body.String()
	if !strings.Contains(pg, html.EscapeString(planCodeText)) || p.started != 0 {
		t.Fatalf("started without a code (%d):\n%s", p.started, pg)
	}
	pg = r.post("/plan/signin", url.Values{"code": {"000000"}}).Body.String()
	if !strings.Contains(pg, html.EscapeString(wrongCodeText)) || p.started != 0 {
		t.Fatalf("started on a wrong code (%d):\n%s", p.started, pg)
	}
	pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String()
	for _, s := range []string{`<a href="https://auth.openai.com/codex/device">`, `<span class="mono">ABCD-EF23</span>`, "<p>This code is from OpenAI, not from your code generator.</p>"} {
		if !strings.Contains(pg, s) {
			t.Errorf("started page lacks %q:\n%s", s, pg)
		}
	}
	if p.started != 1 {
		t.Fatalf("started %d", p.started)
	}
	p.err = localsrv.SignInBusy
	if pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String(); !strings.Contains(pg, html.EscapeString(planBusyText)) {
		t.Fatalf("busy:\n%s", pg)
	}
	p.ready, p.err = false, nil
	if pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String(); !strings.Contains(pg, html.EscapeString(planGoneText)) || p.started != 2 {
		t.Fatalf("closed since the page loaded (%d):\n%s", p.started, pg)
	}
}

// Signed out, a post starts nothing; only POST is taken.
func TestThePlanSignInFormNeedsASignIn(t *testing.T) {
	p := &pagePlan{ready: true}
	r := planRig(t, p)
	if w := r.post("/plan/signin", url.Values{"code": {r.code()}}); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock") {
		t.Fatalf("signed out: %d %s", w.Code, w.Header().Get("Location"))
	}
	r.post("/unlock", url.Values{"code": {r.code()}})
	if w := r.do(http.MethodGet, "/plan/signin", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
	if p.started != 0 {
		t.Fatalf("started %d", p.started)
	}
}
