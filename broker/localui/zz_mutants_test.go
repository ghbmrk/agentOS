package localui

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: ONB-3, CH-7, NET-2

// codeErrs is the rig's hooks with EnrollCode and ConfirmCode answering
// the given errors; EnrollCode's error comes with a good link, which the
// page must not show.
type codeErrs struct {
	*fakeHooks
	enroll, confirm error
}

func (c *codeErrs) EnrollCode() (string, error) {
	if c.enroll != nil {
		link, _ := c.fakeHooks.EnrollCode()
		return link, c.enroll
	}
	return c.fakeHooks.EnrollCode()
}
func (c *codeErrs) ConfirmCode(code string) (bool, error) {
	if c.confirm != nil {
		return false, c.confirm
	}
	return c.fakeHooks.ConfirmCode(code)
}

// Once setup is done its step is "done", whatever the other steps say,
// and no AI post may begin.
func TestSetupDoneIsTheStepAndRefusesAnAIPost(t *testing.T) {
	u := newRig(t).srv.setup
	u.mu.Lock()
	u.st = SetupState{Done: true, Owner: ownerNum, Codes: true, Recovery: true, Host: true}
	step := u.stepLocked(Progress{})
	u.mu.Unlock()
	if step != "done" {
		t.Fatalf("step %q, want done", step)
	}
	if err := u.begin("anthropic"); !errors.Is(err, errSetupDone) {
		t.Fatalf("begin after done: %v", err)
	}
}

// Each way the vault refuses a code shows its own text on the codes step.
func TestTheCodesStepNamesEachVaultRefusal(t *testing.T) {
	r := newRig(t)
	h := &codeErrs{fakeHooks: r.hooks}
	r.via = h
	u := r.open(&MemStore{}).setup
	u.mu.Lock()
	u.st.Owner = ownerNum
	u.mu.Unlock()
	for err, want := range map[error]string{
		ErrCodesUnavailable:      cannotFinish,
		ErrNoCodeEnrollment:      "That key is no longer waiting.",
		ErrCodesLimited:          "Too many wrong codes.",
		errors.New("vault busy"): "Could not check the code.",
	} {
		h.confirm = err
		u.mu.Lock()
		u.shown = true
		u.mu.Unlock()
		req := httptest.NewRequest("POST", "/setup/codes", strings.NewReader(url.Values{"code": {"123456"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		got := u.codes(req, "")
		if got == nil || !strings.HasPrefix(got.Error(), want) {
			t.Fatalf("%v: %v, want %q", err, got, want)
		}
		u.mu.Lock()
		shown := u.shown
		u.mu.Unlock()
		if shown != (err != ErrNoCodeEnrollment) {
			t.Fatalf("%v: shown %v", err, shown)
		}
	}
}

// The codes step's page says why the vault made no key: unavailable
// cannot finish, and too many new keys asks for a minute.
func TestTheCodesPageNamesWhyNoKeyWasMade(t *testing.T) {
	for err, want := range map[error]string{
		ErrCodesUnavailable: cannotFinish,
		ErrCodesLimited:     "Too many new codes in a minute.",
	} {
		r := newRig(t)
		r.via = &codeErrs{fakeHooks: r.hooks, enroll: err}
		r.srv = r.open(&MemStore{})
		if page := r.toCodes(); !strings.Contains(page, want) {
			t.Fatalf("%v: the page lacks %q:\n%s", err, want, page)
		}
	}
	// Any other failure fails the page load, and shows no step.
	r := newRig(t)
	h := &codeErrs{fakeHooks: r.hooks}
	r.via = h
	r.srv = r.open(&MemStore{})
	h.enroll = errors.New("vault busy")
	r.hooks.mu.Lock()
	r.hooks.progress.Online = true
	r.hooks.mu.Unlock()
	code := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(html.UnescapeString(r.get("/setup")))[1]
	r.srv.OfferText(ownerNum, "PAIR "+code)
	if w := r.do("GET", "/setup", nil); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Setup could not start this step.") ||
		strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("an enroll failure: %d %s", w.Code, w.Body.String())
	}
}

// Sign-in names agentosd's limit, and any other failure, as such: neither
// signs the phone in.
func TestSignInNamesTheLimitAndAFailure(t *testing.T) {
	s := newRig(t).srv
	var wait time.Duration
	for code, want := range map[string]string{localapi.ErrLimited: limitedText, localapi.ErrFailed: "Could not check the code. Try again."} {
		s.SetOwner(ownerAnswers{code, &wait})
		w := httptest.NewRecorder()
		tok, err := s.checkSignIn(w, httptest.NewRequest("POST", "/unlock", nil), "123456")
		if err == nil || err.Error() != want || tok != "" || len(w.Result().Cookies()) != 0 {
			t.Fatalf("%s: %q, %v, cookies %v; want %q", code, tok, err, w.Result().Cookies(), want)
		}
	}
}

// ctxOwner records the context of the call it answers.
type ctxOwner struct{ ctx *context.Context }

func (o ctxOwner) Call(ctx context.Context, _ string, _, _ any) error { *o.ctx = ctx; return nil }

// Plan's bound ends with Plan: the call's context is cancelled once it
// returns, so no timer waits out planFor.
func TestPlanReleasesItsBound(t *testing.T) {
	var ctx context.Context
	if _, ok := (AgentosdAccounts{Owner: ctxOwner{&ctx}}).Plan(context.Background(), "s"); !ok {
		t.Fatal("Plan failed")
	}
	if ctx == nil || ctx.Err() == nil {
		t.Fatal("the plan call's context outlives Plan")
	}
}

// A Connect declaration's uses each need their own ID, a name and what
// they get.
func TestConnectDeclarationRefusesABrokenUse(t *testing.T) {
	if err := GmailConnect.validate(); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*ConnectUse){
		"no name": func(u *ConnectUse) { u.Name = "" },
		"no gets": func(u *ConnectUse) { u.Gets = nil },
		"bad id":  func(u *ConnectUse) { u.ID = "A" },
	} {
		d := GmailConnect
		d.Uses = slices.Clone(d.Uses)
		f(&d.Uses[0])
		if d.validate() == nil {
			t.Errorf("%s: a broken use validates", name)
		}
	}
	d := GmailConnect
	d.Uses = append(slices.Clone(d.Uses), d.Uses[0])
	if d.validate() == nil {
		t.Error("a use twice validates")
	}
}

// The account plan is served at /account-plan/ alone, for GET, HEAD and
// POST: a path below it is not found and another method is refused.
func TestAccountPlanServesItsPathAndMethodsAlone(t *testing.T) {
	r, _ := accountPlanRig(t, GmailConnect)
	r.signIn()
	if w := r.do("GET", "/account-plan/x", nil); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "Gmail") {
		t.Fatalf("GET below the plan: %d %s", w.Code, w.Body.String())
	}
	if w := r.do("PUT", "/account-plan/", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" || strings.Contains(w.Body.String(), "Gmail") {
		t.Fatalf("PUT: %d, Allow %q: %s", w.Code, w.Header().Get("Allow"), w.Body.String())
	}
	if p := html.UnescapeString(r.get("/account-plan/")); !strings.Contains(p, "<b>Gmail</b>") {
		t.Fatalf("the plan:\n%s", p)
	}
}

// With no table, no destination is shown.
func TestPlanSendsOfNoTableIsNone(t *testing.T) {
	if got := planSends(nil, "gmail"); got != nil {
		t.Fatalf("planSends(nil) = %v", got)
	}
}
