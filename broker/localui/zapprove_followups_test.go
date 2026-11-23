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
// reload sends the answer again. It points to Approvals and STATUS.
func TestTheNoReplyAnswerTextDoesNotSayReload(t *testing.T) {
	if strings.Contains(answerUnreachableText, "Reload") || !strings.Contains(answerUnreachableText, "Approvals") || !strings.Contains(answerUnreachableText, "STATUS") {
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
// A page STOP refused because agentosd is stopping says agentOS is
// restarting, not the generic failure; any other failure keeps it.
func TestAStopWhileRestartingSaysSo(t *testing.T) {
	tok := strings.Repeat("ab", localapi.TokenBytes)
	for _, c := range []struct {
		err  error
		want string
	}{
		{sockets.Code(refusedStopping), "stoprestarting"},
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
	if !strings.Contains(msgs["stoprestarting"], "restarting") || !strings.Contains(msgs["stoprestarting"], "STOP again") {
		t.Fatalf("restarting text %q", msgs["stoprestarting"])
	}
}
