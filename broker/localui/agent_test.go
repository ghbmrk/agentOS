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
	s, err := New(Config{AP: testAP()})
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://10.42.0.1"+path, strings.NewReader("number=%2B15550000001&code=123456"))
		req.RemoteAddr = "10.42.0.20:5000"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
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
	s, err := New(Config{AP: testAP()})
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
	s.ServeHTTP(w, req)
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
		s, err := New(Config{AP: testAP()})
		if err != nil {
			t.Fatal(err)
		}
		s.SetOwner(InProcess(localsrv.New(localsrv.Config{Owner: leftOwner{left: c.left}}).Ops()))
		do := func(method, path, form string) string {
			req := httptest.NewRequest(method, "http://10.42.0.1"+path, strings.NewReader(form))
			req.RemoteAddr = "10.42.0.20:5000"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
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
	s, err := New(Config{AP: testAP()})
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
		s, err := New(Config{AP: testAP()})
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
		s.ServeHTTP(w, req)
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, html.EscapeString(c.want)) || strings.Contains(body, "Nothing was approved or denied") {
			t.Fatalf("%s: %d %s", c.name, w.Code, body)
		}
	}
}
