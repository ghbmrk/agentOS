package localui

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
)

// REQ: ONB-3, ONB-9, CRED-5

// pagePlan stands in for agentosd's plan sign-in: open while ready, and
// starting the provider's device-code flow.
type pagePlan struct {
	ready, waiting bool
	err            error
	started        int
}

func (p *pagePlan) Ready() bool   { return p.ready }
func (p *pagePlan) Waiting() bool { return p.waiting }
func (p *pagePlan) Start(context.Context) (string, string, string, error) {
	p.started++
	if p.err != nil {
		return "", "", "", p.err
	}
	p.waiting = true
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
	p.waiting = false // the code expired
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

// REQ: G1-1264-busy-1
//
// #1945: an owner who leaves the page before approving the provider's code
// finds the same link and code on home, with no code and no new start;
// another phone gets them only after a good code. Once the sign-in stops
// waiting, home offers the form again.
func TestHomeShowsTheWaitingPlanSignInAgain(t *testing.T) {
	p := &pagePlan{ready: true}
	r := planRig(t, p)
	r.post("/unlock", url.Values{"code": {r.code()}})
	r.post("/plan/signin", url.Values{"code": {r.code()}})
	kept := []string{`<span class="mono">ABCD-EF23</span>`, `<a href="/home">I signed in</a>`}
	pg := r.get("/home")
	for _, s := range kept {
		if !strings.Contains(pg, s) {
			t.Errorf("home lacks %q:\n%s", s, pg)
		}
	}
	if strings.Contains(pg, `action="/plan/signin"`) {
		t.Errorf("home offers a second start:\n%s", pg)
	}
	if pg = r.post("/plan/signin", nil).Body.String(); !strings.Contains(pg, kept[0]) || p.started != 1 {
		t.Fatalf("a second start without a code (%d):\n%s", p.started, pg)
	}

	first := r.jar
	r.jar, _ = cookiejar.New(nil)
	r.post("/unlock", url.Values{"code": {r.code()}})
	if pg = r.get("/home"); strings.Contains(pg, "ABCD-EF23") {
		t.Fatalf("another phone sees the code without one:\n%s", pg)
	}
	if pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String(); !strings.Contains(pg, kept[0]) || p.started != 1 {
		t.Fatalf("another phone with a good code (%d):\n%s", p.started, pg)
	}
	r.jar = first
	if pg = r.get("/home"); strings.Contains(pg, "ABCD-EF23") {
		t.Fatalf("the code stayed with the first phone too:\n%s", pg)
	}

	p.waiting = false
	r.post("/unlock", url.Values{"code": {r.code()}})
	if pg = r.get("/home"); strings.Contains(pg, "ABCD-EF23") || !strings.Contains(pg, `action="/plan/signin"`) {
		t.Fatalf("an expired sign-in is still shown:\n%s", pg)
	}
}

// REQ: G1-1264-busy-3, CH-12
//
// Every text the plan sign-in form shows names a step that works in its
// state: the code text sits above the form, the failed text above the form
// again, the busy text names the sign-in's own wait, and the limited text
// claims no wrong codes when the bound was starts.
func TestPlanSignInTextsNameOnlyStepsThatWork(t *testing.T) {
	p := &pagePlan{ready: true, err: errors.New("no worker")}
	r := planRig(t, p)
	// The start bound counts on a clock of its own here: each code moves
	// the owner's clock on a step.
	at := r.clock()
	r.srv.SetOwner(InProcess(localsrv.New(localsrv.Config{Owner: r.ch, Now: func() time.Time { return at }, PlanSignIn: p}).Ops()))
	r.post("/unlock", url.Values{"code": {r.code()}})
	form := `action="/plan/signin"`
	pg := r.post("/plan/signin", nil).Body.String()
	if !strings.Contains(pg, html.EscapeString(planCodeText)) || !strings.Contains(pg, form) {
		t.Fatalf("code text without the form:\n%s", pg)
	}
	for i := 0; i < localapi.DeviceCodesPerMinute; i++ {
		pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String()
		if !strings.Contains(pg, html.EscapeString(planFailedText)) || !strings.Contains(pg, form) {
			t.Fatalf("failed text %d without the form:\n%s", i, pg)
		}
	}
	pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String()
	if !strings.Contains(pg, html.EscapeString(planLimitedText)) || p.started != localapi.DeviceCodesPerMinute {
		t.Fatalf("past the start bound (%d):\n%s", p.started, pg)
	}
	if strings.Contains(strings.ToLower(planLimitedText), "wrong") {
		t.Errorf("the limited text blames wrong codes: %q", planLimitedText)
	}
	at = at.Add(time.Minute)
	p.err, p.waiting = nil, true // a sign-in this page does not hold
	pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String()
	if !strings.Contains(pg, html.EscapeString(planBusyText)) || p.started != localapi.DeviceCodesPerMinute {
		t.Fatalf("busy (%d):\n%s", p.started, pg)
	}
	if wait := fmt.Sprintf("in %d minutes", int(localapi.PlanSignInWait/time.Minute)); !strings.Contains(planBusyText, wait) {
		t.Errorf("the busy text %q does not name the sign-in's wait, %q", planBusyText, wait)
	}
	p.ready = false
	if pg = r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String(); !strings.Contains(pg, html.EscapeString(planGoneText)) || strings.Contains(pg, form) {
		t.Fatalf("gone text with the form:\n%s", pg)
	}
}
