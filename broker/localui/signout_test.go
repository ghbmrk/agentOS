package localui

// REQ: CH-7, CH-12

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// signOutOwner is agentosd's sign-out alone: a token it holds is revoked
// by OpSignOut, and an unknown or revoked one is refused as unauthorized.
// fail, when set, decides each call's error before (dropped false) or after
// (dropped true) the revocation.
type signOutOwner struct {
	mu      sync.Mutex
	live    map[string]bool
	calls   int
	fail    func(call int) error
	dropped bool
}

func (o *signOutOwner) Call(_ context.Context, op string, args, _ any) error {
	if op != localapi.OpSignOut {
		return errors.New("unexpected op " + op)
	}
	tok := args.(localapi.Auth).Token
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	var err error
	if o.fail != nil {
		err = o.fail(o.calls)
	}
	if err != nil && !o.dropped {
		return err
	}
	if !o.live[tok] {
		return Refused(localapi.ErrUnauthorized)
	}
	delete(o.live, tok)
	return err
}

func (o *signOutOwner) signedIn(tok string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.live[tok]
}

const signOutTok = "00112233445566778899aabbccddeeff"

// signOutRig is a phone holding signOutTok, with o behind the socket.
func signOutRig(t *testing.T, o *signOutOwner) *rig {
	r := newRig(t)
	r.srv.SetOwner(o)
	u, _ := url.Parse("http://10.42.0.1/")
	r.jar.SetCookies(u, []*http.Cookie{{Name: cookieName, Value: signOutTok, Path: "/"}})
	return r
}

func (r *rig) hasSessionCookie() bool {
	u, _ := url.Parse("http://10.42.0.1/")
	for _, c := range r.jar.Cookies(u) {
		if c.Name == cookieName && c.Value != "" {
			return true
		}
	}
	return false
}

// signedOut asserts a sign-out that ended: the cookie cleared and the phone
// sent to the status page.
func signedOut(t *testing.T, r *rig, w interface {
	Result() *http.Response
}) {
	t.Helper()
	res := w.Result()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/status" {
		t.Fatalf("sign-out answered %d %q, want 303 to /status", res.StatusCode, res.Header.Get("Location"))
	}
	if r.hasSessionCookie() {
		t.Fatal("the session cookie was kept after the sign-out ended")
	}
}

// incomplete asserts a sign-out agentosd did not confirm: the cookie stays
// (the retry needs it) and the page says so, with a retry that posts to
// /signout.
func incomplete(t *testing.T, r *rig, body string, code int) {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("unconfirmed sign-out answered %d", code)
	}
	if !strings.Contains(body, "Sign-out incomplete") || !strings.Contains(body, `<form method="post" action="/signout">`) {
		t.Fatalf("unconfirmed sign-out page lacks the notice or the retry:\n%s", body)
	}
	if !r.hasSessionCookie() {
		t.Fatal("the session cookie was cleared although agentosd did not confirm the sign-out")
	}
}

// A sign-out agentosd refuses before revoking (no socket, a fault) is not
// reported as done: the phone may still be signed in, so the page says the
// sign-out is incomplete and offers a retry, and a retry that agentosd
// confirms ends the sign-out (#1725).
func TestSignOutRefusedBeforeRevokeIsIncompleteAndRetries(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"fault", Refused("internal")},
		{"transport", errors.New("connection reset")},
		{"timeout", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &signOutOwner{live: map[string]bool{signOutTok: true}}
			o.fail = func(call int) error {
				if call == 1 {
					return tc.err
				}
				return nil
			}
			r := signOutRig(t, o)
			w := r.post("/signout", url.Values{})
			incomplete(t, r, w.Body.String(), w.Code)
			if !o.signedIn(signOutTok) {
				t.Fatal("the session was revoked by a refused call")
			}
			signedOut(t, r, r.post("/signout", url.Values{}))
			if o.signedIn(signOutTok) {
				t.Fatal("the session is still live after the retry")
			}
		})
	}
}

// With no socket at all, the sign-out is incomplete too.
func TestSignOutWithNoOwnerIsIncomplete(t *testing.T) {
	r := newRig(t)
	u, _ := url.Parse("http://10.42.0.1/")
	r.jar.SetCookies(u, []*http.Cookie{{Name: cookieName, Value: signOutTok, Path: "/"}})
	w := r.post("/signout", url.Values{})
	incomplete(t, r, w.Body.String(), w.Code)
}

// A token agentosd refuses as unauthorized is already signed out (never
// minted, or revoked earlier), so the sign-out ends.
func TestSignOutOfUnknownTokenEnds(t *testing.T) {
	o := &signOutOwner{live: map[string]bool{}}
	r := signOutRig(t, o)
	signedOut(t, r, r.post("/signout", url.Values{}))
}

// A response lost after agentosd revoked the session shows incomplete; the
// retry is refused as unauthorized, which ends the sign-out, so a retry is
// safe to repeat.
func TestSignOutLostResponseThenRetryEnds(t *testing.T) {
	o := &signOutOwner{live: map[string]bool{signOutTok: true}, dropped: true}
	o.fail = func(call int) error {
		if call == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}
	r := signOutRig(t, o)
	w := r.post("/signout", url.Values{})
	incomplete(t, r, w.Body.String(), w.Code)
	if o.signedIn(signOutTok) {
		t.Fatal("the first call did not revoke")
	}
	signedOut(t, r, r.post("/signout", url.Values{}))
	if o.calls != 2 {
		t.Fatalf("agentosd asked %d times, want 2", o.calls)
	}
}

// A confirmed sign-out ends at once.
func TestSignOutConfirmedEnds(t *testing.T) {
	o := &signOutOwner{live: map[string]bool{signOutTok: true}}
	r := signOutRig(t, o)
	signedOut(t, r, r.post("/signout", url.Values{}))
	if o.signedIn(signOutTok) {
		t.Fatal("the session is still live")
	}
}

// The retry is a same-origin POST like the first sign-out: a cross-site
// post is refused before agentosd is asked.
func TestSignOutRetryIsSameOriginOnly(t *testing.T) {
	o := &signOutOwner{live: map[string]bool{signOutTok: true}}
	r := signOutRig(t, o)
	w := r.do("POST", "/signout", url.Values{}, func(q *http.Request) { q.Header.Set("Origin", "http://evil.example") })
	if w.Code == http.StatusSeeOther || o.calls != 0 {
		t.Fatalf("cross-site sign-out answered %d after %d calls", w.Code, o.calls)
	}
}
