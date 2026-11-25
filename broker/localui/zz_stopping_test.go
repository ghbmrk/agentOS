package localui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// stopOwner is agentosd once it is stopping: an InProcess that refuses
// every op as stopping, except, with session set, the sign-in check and
// the ops in ok (a stop that begins after those returned).
type stopOwner struct {
	session string
	ok      map[string]bool
}

func (o stopOwner) Call(ctx context.Context, op string, args, out any) error {
	h := func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return nil, sockets.Code(localapi.ErrStopping)
	}
	if o.session != "" && op == localapi.OpSession {
		h = func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return localapi.Session{Token: o.session, Until: time.Now().Add(time.Hour)}, nil
		}
	} else if o.ok[op] {
		h = func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return struct{}{}, nil }
	}
	return InProcess{op: h}.Call(ctx, op, args, out)
}

func stoppingServer(t *testing.T, o Owner) *Server {
	t.Helper()
	s, err := New(Config{Page: testPage(),
		Passkeys: AgentosdPasskeys{Owner: o}, PasskeyRPID: "box.example",
		Cameras: AgentosdCameras{Owner: o}, HomeKit: AgentosdHomeKit{Owner: o}})
	if err != nil {
		t.Fatal(err)
	}
	s.SetOwner(o)
	return s
}

// stoppingActions is every page action served without setup hooks: each
// page's GET, and each form's POST with the fields its handler needs to
// reach agentosd.
var stoppingActions = []struct {
	method, path string
	form         func(s *Server, tok string) url.Values
}{
	{"GET", "/status", nil},
	{"GET", "/unlock", nil},
	{"POST", "/unlock", fixed(url.Values{"code": {"123456"}})},
	{"POST", "/stop", nil},
	{"POST", "/resume", fixed(url.Values{"code": {"123456"}})},
	{"POST", "/signout", nil},
	{"GET", "/home", nil},
	{"POST", "/line/sim", fixed(url.Values{"sim": {"1"}, "code": {"123456"}})},
	{"POST", "/plan/signin", fixed(url.Values{"code": {"123456"}})},
	{"GET", "/approvals/", nil},
	{"POST", "/approvals/", fixed(url.Values{"id": {"r1"}, "sum": {"s"}, "approve": {"1"}})},
	{"POST", "/follow/", func(s *Server, tok string) url.Values {
		d := strings.Repeat("0", localapi.DigestLen)
		return url.Values{"step": {"ask"}, "digest": {d}, "name": {"mine"}, "tok": {s.followToken(tokenKey(tok), d, false)}}
	}},
	{"GET", "/paused/", nil},
	{"POST", "/paused/", fixed(url.Values{"grant": {"g1"}})},
	{"GET", "/held/", nil},
	{"GET", "/inbox/", nil},
	{"GET", "/passkeys/", nil},
	{"GET", "/cameras/", nil},
	{"GET", "/homekit/", nil},
}

func fixed(v url.Values) func(*Server, string) url.Values {
	return func(*Server, string) url.Values { return v }
}

func stoppingRequest(s *Server, tok, method, path string, formFor func(*Server, string) url.Values) *httptest.ResponseRecorder {
	var form url.Values
	if formFor != nil {
		form = formFor(s, tok)
	}
	req := httptest.NewRequest(method, "http://10.42.0.1"+path, strings.NewReader(form.Encode()))
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.RemoteAddr = "10.42.0.20:5000"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, reaching(req))
	return w
}

// REQ: UX-2wb-1 (#6619, from #1752 P8)
// While agentosd is stopping it refuses every page call. Every page action
// then shows that agentOS is stopping or restarting, with a 503, rather
// than its generic failure or a sign-in page: a planned restart never reads
// as a fault. It names no clock, since the stop may be a poweroff.
func TestZEveryPageActionRefusedAsStoppingSaysSo(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	s := stoppingServer(t, stopOwner{})
	for _, a := range stoppingActions {
		w := stoppingRequest(s, tok, a.method, a.path, a.form)
		body := w.Body.String()
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(body, "agentOS is stopping or restarting, so it did not do this") {
			t.Errorf("%s %s: %d %q %.200q", a.method, a.path, w.Code, w.Header().Get("Location"), body)
		}
		if refresh := strings.Contains(body, `http-equiv="refresh"`); refresh != (a.method == "GET") {
			t.Errorf("%s %s: refresh %v", a.method, a.path, refresh)
		}
	}
	if strings.Contains(stoppingText, "minute") || strings.Contains(partwayText, "minute") {
		t.Fatalf("stopping text sets a clock: %q %q", stoppingText, partwayText)
	}
}

// REQ: UX-2wb-1 (#6619; L3 blocker 2 on #6699)
// A stop that begins after the page checked the session refuses the
// action's own call. The session check only reads, so each signed-in
// action still says it did not do this, and never asks the owner to check
// for an effect that cannot have happened.
func TestZEachActionsOwnStoppingRefusalSaysNotDone(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	s := stoppingServer(t, stopOwner{session: tok})
	for _, a := range stoppingActions {
		w := stoppingRequest(s, tok, a.method, a.path, a.form)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "so it did not do this") {
			t.Errorf("%s %s: %d %q %.200q", a.method, a.path, w.Code, w.Header().Get("Location"), w.Body.String())
		}
	}
}

// REQ: UX-2wb-1 (#6619; L3 blocker 2 on #6699)
// Only a form whose acting call returned before the refusal says agentOS
// stopped partway: RESUME recorded, then its status page refused. A page
// view does nothing, so a GET says "did not do this" even when one of its
// calls returned first.
func TestZOnlyAnActionThatReturnedSaysPartway(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	s := stoppingServer(t, stopOwner{session: tok, ok: map[string]bool{localapi.OpResume: true, localapi.OpRequests: true}})
	w := stoppingRequest(s, tok, "POST", "/resume", fixed(url.Values{"code": {"123456"}}))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "partway through") {
		t.Fatalf("RESUME recorded, then refused: %d %.300q", w.Code, w.Body.String())
	}
	w = stoppingRequest(s, tok, "GET", "/home", nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "so it did not do this") {
		t.Fatalf("home view with a listing returned: %d %.300q", w.Code, w.Body.String())
	}
}

// REQ: UX-2wb-1, L18 (#6619; L3 blocker 1 on #6699)
// The buffered page still reaches the connection's deadlines, so the
// upload bound (uploadWindow) a handler sets through ServeHTTP holds.
func TestZABufferedPageKeepsTheConnectionDeadlines(t *testing.T) {
	s := stoppingServer(t, stopOwner{})
	var readErr, writeErr error
	s.mux.HandleFunc("/deadline-probe", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		readErr = rc.SetReadDeadline(time.Now().Add(uploadWindow))
		writeErr = rc.SetWriteDeadline(time.Now().Add(uploadWindow))
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "10.42.0.20:5000"
		r.Host = "10.42.0.1"
		s.ServeHTTP(w, reaching(r))
	}))
	defer ts.Close()
	res, err := http.Get(ts.URL + "/deadline-probe")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || readErr != nil || writeErr != nil {
		t.Fatalf("deadlines through the buffer: %d read %v write %v", res.StatusCode, readErr, writeErr)
	}
}

// REQ: UX-2wb-1 (#6619)
// Any other refusal keeps the action's own text: a failed STOP still says
// to press STOP again, and a page agentosd answered is sent as the handler
// wrote it.
func TestZOnlyAStoppingRefusalShowsTheStoppingPage(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	s := followupServer(t, tok, InProcess{
		localapi.OpStop: func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return nil, sockets.ErrFailed },
	})
	w := stoppingRequest(s, tok, "POST", "/stop", nil)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || loc != "/status?m=stopfailed" {
		t.Fatalf("failed STOP: %d %q", w.Code, loc)
	}
	if w.Header().Get("Content-Security-Policy") != pageCSP {
		t.Fatalf("passed-through page lost its headers: %v", w.Header())
	}
}

// REQ: UX-2wb-1 (#6619)
// The stopping page keeps a session cookie the handler set from a call
// agentosd answered before it stopped, and keeps the page's guards.
func TestZTheStoppingPageKeepsCookiesAndGuards(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	s := stoppingServer(t, stopOwner{})
	r := httptest.NewRequest("GET", "http://10.42.0.1/status", nil)
	r.RemoteAddr = "10.42.0.20:5000"
	w := httptest.NewRecorder()
	s.stopping(w, r, []string{cookieName + "=" + tok}, false)
	if w.Header().Get("Set-Cookie") != cookieName+"="+tok || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stopping page: %d %v", w.Code, w.Header())
	}
	w = stoppingRequest(s, tok, "GET", "/status", nil)
	if w.Header().Get("Content-Security-Policy") != pageCSP || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("stopping page lost its guards: %v", w.Header())
	}
}
