package localui

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ARC-2, CH-7
// Also serves the UX-2wb-1 finding (no SPEC ID).

type stillOwner struct{}

func (stillOwner) LocalStatus() owner.LocalStatus {
	return owner.LocalStatus{Stopped: true, LocalLeft: 24}
}
func (stillOwner) LocalGridCell() string { return "C3" }
func (stillOwner) LocalSignIn(string) (time.Time, uint64, error) {
	return time.Time{}, 0, owner.ErrWrongCode
}
func (stillOwner) LocalStop(context.Context) error                          { return nil }
func (stillOwner) StopGen() int64                                           { return 0 }
func (stillOwner) LocalResume(uint64, int64) (string, error)                { return "", nil }
func (stillOwner) LocalRequests() []owner.LocalRequest                      { return nil }
func (stillOwner) LocalWaiting() string                                     { return "" }
func (stillOwner) LocalStatusLines() string                                 { return "" }
func (stillOwner) UnlockPeriod() time.Duration                              { return 7 * 24 * time.Hour }
func (stillOwner) LocalAnswer(string, string, bool, string) (string, error) { return "", nil }

// The page reaches agentosd over localui.sock (P2-2w b): results decode,
// and a refusal comes back as agentosd's fixed code.
func TestThePageCallsAgentosdOverItsSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uid := os.Getuid()
	srv := &sockets.Server{Dir: dir}
	if err := srv.Start(ctx, sockets.Endpoint{Name: localapi.Socket, Peer: sockets.Peer{Kind: "localui"}, PeerUID: &uid,
		Ops: localsrv.New(localsrv.Config{Owner: stillOwner{}}).Ops()}); err != nil {
		t.Fatal(err)
	}
	c := Socket{Path: filepath.Join(dir, localapi.Socket)}
	var st localapi.Status
	if err := c.Call(ctx, localapi.OpStatus, struct{}{}, &st); err != nil || !st.Stopped || st.UnlockDays != 7 {
		t.Fatalf("status: %+v %v", st, err)
	}
	var ses localapi.Session
	if err := c.Call(ctx, localapi.OpSignIn, localapi.SignIn{Code: "000000"}, &ses); err != nil || ses.Refusal != localapi.RefusedWrongCode || ses.Token != "" {
		t.Fatalf("wrong sign-in: %+v %v", ses, err)
	}
	if err := c.Call(ctx, localapi.OpRequests, localapi.Auth{}, nil); !refused(err, localapi.ErrUnauthorized) {
		t.Fatalf("no token: %v", err)
	}
	cancel()
	srv.Wait()
}

// Security L6 on the P2-2w plan: without setup hooks (agentos-localui
// until setup moves into agentosd), every setup route is refused with the
// fixed not-ready page, and nothing pairs in this process.
func TestWithoutSetupHooksEverySetupRouteIsRefused(t *testing.T) {
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://10.42.0.1"+path, strings.NewReader("number=%2B15550000001&code=123456"))
		req.RemoteAddr = "10.42.0.20:5000"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, reaching(req))
		return w
	}
	for _, path := range []string{"/setup", "/setup/", "/setup/number", "/setup/number-code", "/setup/claim",
		"/setup/codes", "/setup/recovery", "/setup/host", "/setup/ai-key", "/setup/ai-device", "/setup/restart", "/setup/anything"} {
		for _, m := range []string{"GET", "POST"} {
			if w := get(m, path); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "not ready yet. This page reloads by itself. If it stays like this for more than a few minutes, turn the PC off and on again.") {
				t.Errorf("%s %s: %d", m, path, w.Code)
			}
		}
	}
	// Before agentosd answers, the box is not ready; once it does, the
	// page serves its status.
	if w := get("GET", "/"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("root without agentosd: %d", w.Code)
	}
	if w := get("GET", "/box.vcf"); w.Code != http.StatusNotFound {
		t.Fatalf("contact without hooks: %d", w.Code)
	}
	s.SetOwner(InProcess(localsrv.New(localsrv.Config{Owner: stillOwner{}}).Ops()))
	if w := get("GET", "/"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/status" {
		t.Fatalf("root with agentosd: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := get("GET", "/status"); w.Code != 200 || !strings.Contains(w.Body.String(), "RESUME") {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	if w := get("POST", "/setup/number"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("setup with agentosd up: %d", w.Code)
	}
}

// UX-2wb-1: when agentosd does not answer, the Approvals page says the box
// isn't answering and that nothing was decided, naming no internal part.
func TestApprovalsSayWhenTheBoxIsNotAnswering(t *testing.T) {
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.Repeat("ab", localapi.TokenBytes)
	s.SetOwner(InProcess{
		localapi.OpSession: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return localapi.Session{Token: tok, Until: time.Now().Add(time.Hour)}, nil
		},
		localapi.OpRequests: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return nil, sockets.ErrFailed
		},
	})
	req := httptest.NewRequest("GET", "http://10.42.0.1/approvals/", nil)
	req.RemoteAddr = "10.42.0.20:5000"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, reaching(req))
	if body := w.Body.String(); w.Code != 200 || !strings.Contains(body, html.EscapeString(unreachableText)) || strings.Contains(body, "owner channel") {
		t.Fatalf("%d %s", w.Code, body)
	}
	if limitedText != "Too many wrong codes were tried on this Wi-Fi. Wait a minute, then try again." {
		t.Fatalf("limited text %q", limitedText) // UX-2wb-4
	}
}

type leftOwner struct {
	stillOwner
	left int
}

func (o leftOwner) LocalStatus() owner.LocalStatus {
	st := owner.LocalStatus{Stopped: true, LocalLeft: o.left}
	if o.left == 0 {
		st.LocalReset = "14:05"
	}
	return st
}

// Security D1: before sign-in, a wrong code's response carries only fixed
// text, and the sign-in and status pages, fetched, never tell the tries
// (the count is told on a signed-in RESUME; see localsrv).
func TestNoTriesLeftShowBeforeSignIn(t *testing.T) {
	for _, c := range []struct {
		left int
		want string
	}{
		{5, wrongCodeText},
		{2, wrongCodeText},
		{0, lockedText},
	} {
		s, err := New(Config{Page: testPage()})
		if err != nil {
			t.Fatal(err)
		}
		s.SetOwner(InProcess(localsrv.New(localsrv.Config{Owner: leftOwner{left: c.left}}).Ops()))
		do := func(method, path, form string) string {
			req := httptest.NewRequest(method, "http://10.42.0.1"+path, strings.NewReader(form))
			req.RemoteAddr = "10.42.0.20:5000"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, reaching(req))
			return w.Body.String()
		}
		body := do("POST", "/unlock", "code=000000")
		if !strings.Contains(body, html.EscapeString(c.want)) || strings.Contains(body, "left today") || strings.Contains(body, "14:05") {
			t.Fatalf("left %d: wrong-code response is not %q:\n%s", c.left, c.want, body)
		}
		for _, p := range []string{"/unlock", "/status"} {
			if body := do("GET", p, ""); strings.Contains(body, "tries left") || strings.Contains(body, "No more codes") || strings.Contains(body, "14:05") {
				t.Fatalf("GET %s tells the tries:\n%s", p, body)
			}
		}
	}
}

// An answer that gets no reply is not reported as undecided: it may have
// taken effect, and the page says so (UX-2wb-1).
func TestAnAnswerWithNoReplyDoesNotClaimNothingHappened(t *testing.T) {
	if strings.Contains(answerUnreachableText, "Nothing was") || answerUnreachableText == unreachableText {
		t.Fatalf("answer wording %q", answerUnreachableText)
	}
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.Repeat("ab", localapi.TokenBytes)
	s.SetOwner(InProcess{
		localapi.OpSession: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return localapi.Session{Token: tok, Until: time.Now().Add(time.Hour)}, nil
		},
		localapi.OpAnswer: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return nil, sockets.ErrFailed
		},
	})
	sess, sum := "sess", strings.Repeat("0", 64)
	_, refusal := s.answer(context.Background(), tok, sess, map[string][]string{
		"id": {"Q2"}, "sum": {sum}, "tok": {s.formToken(sess, "Q2", sum)}, "answer": {"deny"},
	})
	if refusal != answerUnreachableText {
		t.Fatalf("answer with no reply: %q", refusal)
	}
}

// A failed listing after a POST keeps the answer's own message: the page
// never says "Nothing was approved or denied" over (or beside) an answer.
func TestAFailedListingAfterAnAnswerKeepsTheAnswersMessage(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	for _, c := range []struct {
		name   string
		answer func(context.Context, sockets.Peer, json.RawMessage) (any, error)
		want   string
	}{
		{"answer fails", func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return nil, sockets.ErrFailed }, answerUnreachableText},
		{"answer lands", func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return localapi.Answered{Text: "Approved Q2. Your agent can go ahead."}, nil
		}, "Approved Q2."},
	} {
		s, err := New(Config{Page: testPage()})
		if err != nil {
			t.Fatal(err)
		}
		s.SetOwner(InProcess{
			localapi.OpSession: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
				return localapi.Session{Token: tok, Until: time.Now().Add(time.Hour)}, nil
			},
			localapi.OpAnswer: c.answer,
			localapi.OpRequests: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
				return nil, sockets.ErrFailed
			},
		})
		sess := tokenKey(tok)
		sum := strings.Repeat("0", 64)
		form := url.Values{"id": {"Q2"}, "sum": {sum}, "tok": {s.formToken(sess, "Q2", sum)}, "answer": {"deny"}}
		req := httptest.NewRequest("POST", "http://10.42.0.1/approvals/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.42.0.20:5000"
		req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		w := httptest.NewRecorder()
		s.ServeHTTP(w, reaching(req))
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, html.EscapeString(c.want)) || strings.Contains(body, "Nothing was approved or denied") {
			t.Fatalf("%s: %d %s", c.name, w.Code, body)
		}
	}
}

func TestTheInProcessSocketRefusesWhatJSONCannotCarry(t *testing.T) {
	// An argument or a result JSON cannot encode is the
	// marshal error itself, and a handler never runs on an argument that
	// did not encode (#5016: agent.go's two error checks).
	ran := false
	p := InProcess{
		"echo": func(context.Context, sockets.Peer, json.RawMessage) (any, error) { ran = true; return "ok", nil },
		"bad":  func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return make(chan int), nil },
	}
	var out string
	if err := p.Call(context.Background(), "echo", make(chan int), &out); err == nil || ran {
		t.Fatalf("an argument JSON cannot carry: err %v, handler ran %v", err, ran)
	}
	if _, ok := p.Call(context.Background(), "bad", nil, &out).(*json.UnsupportedTypeError); !ok {
		t.Fatalf("a result JSON cannot carry: %v", p.Call(context.Background(), "bad", nil, &out))
	}
	if err := p.Call(context.Background(), "echo", 1, &out); err != nil || out != "ok" || !ran {
		t.Fatalf("echo: %q %v", out, err)
	}
}

func TestACallToAgentosdEndsItsContext(t *testing.T) {
	// A page's call to agentosd is bounded by callTimeout and
	// releases its context when it returns (#5016: agent.go's defer cancel).
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	var held context.Context
	s.SetOwner(InProcess{localapi.OpStatus: func(ctx context.Context, _ sockets.Peer, _ json.RawMessage) (any, error) {
		held = ctx
		return localapi.Status{}, nil
	}})
	var st localapi.Status
	if err := s.call(context.Background(), localapi.OpStatus, struct{}{}, &st); err != nil {
		t.Fatal(err)
	}
	if held == nil {
		t.Fatal("the call never reached agentosd")
	}
	if held.Err() != context.Canceled {
		t.Fatalf("context after the call: %v", held.Err())
	}
	if d, ok := held.Deadline(); !ok || time.Until(d) > callTimeout {
		t.Fatalf("deadline %v %v", d, ok)
	}
}

func TestNewRefusesAnIncompleteConfigAndFillsItsDefaults(t *testing.T) {
	// #5016: each of New's checks and defaults is pinned.
	dir := t.TempDir()
	for name, cfg := range map[string]Config{
		"hooks without a store":    {Page: testPage(), Hooks: &fakeHooks{}},
		"a store without hooks":    {Page: testPage(), Store: &MemStore{}},
		"a card without hooks":     {Page: testPage(), Card: heldCard{}},
		"a short random source":    {Page: testPage(), Rand: strings.NewReader("short")},
		"a store that cannot load": {Page: testPage(), Hooks: &fakeHooks{}, Store: FileStore{Path: dir}},
	} {
		if s, err := New(cfg); err == nil || s != nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := New(Config{Page: testPage(), Rand: strings.NewReader(strings.Repeat("k", 32))})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.Port != UIPort || s.cfg.Now == nil || string(s.formKey) != strings.Repeat("k", 32) {
		t.Fatalf("defaults: port %d, now set %v, form key %q", s.cfg.Port, s.cfg.Now != nil, s.formKey)
	}
	if s, err = New(Config{Page: testPage(), Port: 8080}); err != nil || s.cfg.Port != 8080 {
		t.Fatalf("a set port: %v", err)
	}
}

func TestEveryPageSaysItIsHTMLAndNotToSniffIt(t *testing.T) {
	// The page declares its type rather than leaving it to a
	// sniffer, which would read a body that does not start with markup as
	// text (#5016: server.go's nosniff header, pages.go's Content-Type).
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pages.New("plain").Parse(`{"not": "markup"}`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://10.42.0.1/status", nil)
	req.RemoteAddr = "10.42.0.20:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, reaching(req))
	if w.Code != 200 || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("status page: %d %v", w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	s.render(w, "plain", nil)
	if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type %q", got)
	}
}

func TestSignInChecksTheCodeBeforeAskingAgentosd(t *testing.T) {
	// A phone with no session, an empty or overlong code, and a
	// code with spaces round it: the page asks agentosd only what it must
	// (#5016: server.go's isSignedIn, signIn and checkSignIn checks).
	a := newApprovalRig(t)
	inner := a.srv.getOwner().(InProcess)
	var asked []string
	spy := InProcess{}
	for op, h := range inner {
		op, h := op, h
		spy[op] = func(ctx context.Context, p sockets.Peer, b json.RawMessage) (any, error) {
			asked = append(asked, op+" "+string(b))
			return h(ctx, p, b)
		}
	}
	a.srv.SetOwner(spy)
	signedOut := a.asOther
	signedOut(func() {
		if loc := a.do("GET", "/home", nil).Header().Get("Location"); !strings.HasPrefix(loc, "/unlock") {
			t.Fatalf("home without a session: %q", loc)
		}
	})
	for _, op := range asked {
		if strings.HasPrefix(op, localapi.OpSession+" ") {
			t.Fatalf("a phone with no session token was looked up: %q", asked)
		}
	}
	signedOut(func() {
		for _, code := range []string{"", "   ", strings.Repeat("7", localapi.MaxCode+1)} {
			asked = nil
			w := a.post("/unlock", url.Values{"code": {code}, "next": {"/home"}})
			if w.Code != 200 || !strings.Contains(html.UnescapeString(w.Body.String()), wrongCodeText) {
				t.Fatalf("code %q: %d", code, w.Code)
			}
			for _, op := range asked {
				if strings.HasPrefix(op, localapi.OpSignIn+" ") {
					t.Fatalf("code %q went to agentosd: %q", code, asked)
				}
			}
		}
		asked = nil
		code := a.code()
		w := a.post("/unlock", url.Values{"code": {" " + code + " "}, "next": {"/home"}})
		if w.Header().Get("Location") != "/home" || strings.Contains(w.Body.String(), `name="code"`) {
			t.Fatalf("a code with spaces round it: %d %s", w.Code, w.Body.String())
		}
		want, _ := json.Marshal(localapi.SignIn{Code: code})
		found := false
		for _, op := range asked {
			found = found || op == localapi.OpSignIn+" "+string(want)
		}
		if !found {
			t.Fatalf("agentosd was not asked the trimmed code: %q", asked)
		}
	})
}

func TestTheApprovalsHandlerGuardsItsOwnPathOwnerAndBody(t *testing.T) {
	// #5016: approvals.go's path, owner and body-cap
	// checks, and unlock's own same-origin check, which hold even where
	// ServeHTTP's checks are not in front of them.
	a := newApprovalRig(t)
	if w := a.do("GET", "/approvals/x", nil); w.Code != 404 {
		t.Fatalf("/approvals/x: %d", w.Code)
	}
	if w := a.post("/approvals/", url.Values{"pad": {strings.Repeat("p", 17<<10)}}); w.Code != 400 {
		t.Fatalf("an oversized answer: %d", w.Code)
	}
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.approvals(w, httptest.NewRequest("GET", "http://10.42.0.1/", nil))
	if w.Code != 303 || w.Header().Get("Location") != "/status" {
		t.Fatalf("no owner: %d %q", w.Code, w.Header().Get("Location"))
	}
	req := httptest.NewRequest("POST", "http://10.42.0.1/unlock", strings.NewReader("code=123456"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	a.srv.unlock(w, reaching(req))
	if w.Code != 403 {
		t.Fatalf("a cross-site sign-in: %d", w.Code)
	}
}

func TestTheCardShowsEachOpenItemItsTermsAndItsUndo(t *testing.T) {
	// #5016: requestView skips a done item, says when
	// an item's terms cannot be read, and states every item's undo.
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	v := s.requestView(owner.LocalRequest{ID: "Q1", Done: []bool{true, false, false, false},
		Items: []owner.Item{{Object: "done one"}, {Object: "unreadable", Terms: owner.TermList("not a list")},
			{Object: "by", UndoBy: "Reply UNDO"}, {Object: "window", UndoWindow: time.Hour}}}, "s")
	if len(v.Items) != 3 || v.Items[0].Object != "unreadable" {
		t.Fatalf("items: %+v", v.Items)
	}
	if ts := v.Items[0].Terms; len(ts) != 1 || !strings.Contains(ts[0].Value, "could not be read") {
		t.Fatalf("unreadable terms: %+v", ts)
	}
	for i, want := range []string{"Cannot be undone.", "Reply UNDO", "Undo within"} {
		if !strings.HasPrefix(v.Items[i].Undo, want) {
			t.Errorf("item %d undo %q, want %q", i, v.Items[i].Undo, want)
		}
	}
}
