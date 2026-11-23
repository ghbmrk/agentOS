package localui

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// followupServer is a page whose agentosd signs in with tok and answers
// the ops given.
func followupServer(t *testing.T, tok string, ops InProcess) *Server {
	t.Helper()
	s, err := New(Config{Page: testPage()})
	if err != nil {
		t.Fatal(err)
	}
	ops[localapi.OpSession] = func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return localapi.Session{Token: tok, Until: time.Now().Add(time.Hour)}, nil
	}
	s.SetOwner(ops)
	return s
}

func followupPost(s *Server, tok, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://10.42.0.1"+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.42.0.20:5000"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, reaching(req))
	return w
}

// REQ: UX-2wb-1 (#1752 item 2)
// The no-reply wording never says Reload: the page is a POST's, so a
// reload sends the answer again. It points to the page's Status link and
// to STATUS by text.
func TestTheNoReplyAnswerTextDoesNotSayReload(t *testing.T) {
	if strings.Contains(answerUnreachableText, "Reload") || !strings.Contains(answerUnreachableText, "Open Status") || !strings.Contains(answerUnreachableText, "STATUS") {
		t.Fatalf("answer wording %q", answerUnreachableText)
	}
}

// REQ: UX-2wb-1 (#1752, P3 on #1746)
// An answer whose listing is then refused as unauthorized (its wrong codes
// locked the session) shows its own message instead of redirecting to
// /unlock, which would drop it. Without an answer the redirect stands.
func TestAnAnswerThatLocksTheSessionKeepsItsMessage(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	unauthorized := func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return nil, sockets.Code(localapi.ErrUnauthorized)
	}
	s := followupServer(t, tok, InProcess{
		localapi.OpAnswer: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return localapi.Answered{Text: "Wrong code. Q2 is void after wrong codes."}, nil
		},
		localapi.OpRequests: unauthorized,
	})
	sess, sum := tokenKey(tok), strings.Repeat("0", 64)
	form := url.Values{"id": {"Q2"}, "sum": {sum}, "tok": {s.formToken(sess, "Q2", sum)}, "answer": {"deny"}}
	w := followupPost(s, tok, "/approvals/", form)
	if body := w.Body.String(); w.Code != 200 || !strings.Contains(body, html.EscapeString("Q2 is void")) {
		t.Fatalf("answer then unauthorized listing: %d %q %s", w.Code, w.Header().Get("Location"), body)
	}
	req := httptest.NewRequest("GET", "http://10.42.0.1/approvals/", nil)
	req.RemoteAddr = "10.42.0.20:5000"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	w = httptest.NewRecorder()
	s.ServeHTTP(w, reaching(req))
	if loc := w.Header().Get("Location"); w.Code != 303 || !strings.HasPrefix(loc, "/unlock") {
		t.Fatalf("unauthorized listing alone: %d %q", w.Code, loc)
	}
}

// REQ: UX-2wb-1 (#1752, P8 on #1746)
// A page STOP refused because agentosd is stopping says it is stopping or
// restarting, since any SIGTERM (a restart, a stop, a poweroff) refuses it
// alike and the page cannot tell which; it never claims a restart alone,
// nor tells the owner to retry on a clock. Any other failure keeps the
// generic line.
func TestAStopWhileAgentosdStopsSaysSo(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	for _, c := range []struct {
		err  error
		want string
	}{
		{sockets.Code(localapi.ErrStopping), "stopstopping"},
		{sockets.ErrFailed, "stopfailed"},
	} {
		s := followupServer(t, tok, InProcess{
			localapi.OpStop: func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return nil, c.err },
		})
		w := followupPost(s, tok, "/stop", url.Values{})
		if loc := w.Header().Get("Location"); loc != "/status?m="+c.want {
			t.Fatalf("STOP refused with %v: %d %q", c.err, w.Code, loc)
		}
	}
	text := msgs["stopstopping"]
	if !strings.Contains(text, "stopping or restarting") || strings.Contains(text, "in a minute") || !strings.Contains(text, "press STOP") {
		t.Fatalf("stopping text %q", text)
	}
}

// REQ: UX-2wb-1, CH-7 (#1752; L3 and UX blocker 1 on #6620)
// Only an answer the channel replied to keeps its message over a refused
// listing. A POST from an expired or revoked session (OpAnswer refused as
// unauthorized), or with a stale form token, still goes to /unlock, as on
// main: no "may or may not have gone through" hedge, and no "check the
// request below" over an empty list.
func TestAnUnauthorizedAnswerStillGoesToUnlock(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	unauthorized := func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return nil, sockets.Code(localapi.ErrUnauthorized)
	}
	s := followupServer(t, tok, InProcess{localapi.OpAnswer: unauthorized, localapi.OpRequests: unauthorized})
	sess, sum := tokenKey(tok), strings.Repeat("0", 64)
	for name, form := range map[string]url.Values{
		"expired session": {"id": {"Q2"}, "sum": {sum}, "tok": {s.formToken(sess, "Q2", sum)}, "answer": {"deny"}},
		"stale form":      {"id": {"Q2"}, "sum": {sum}, "tok": {"stale"}, "answer": {"deny"}},
	} {
		w := followupPost(s, tok, "/approvals/", form)
		if loc := w.Header().Get("Location"); w.Code != 303 || loc != "/unlock?next=/approvals/" {
			t.Fatalf("%s: %d %q %s", name, w.Code, loc, w.Body.String())
		}
	}
}
