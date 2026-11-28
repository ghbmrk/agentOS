package localui

// REQ: HW-10

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// CTRL-card-sock l2 (#1274): the busy answer is not the owner's mistake,
// so it carries the typed code back, capped at 32 as on GET.
func TestABusyClaimKeepsTheTypedCode(t *testing.T) {
	r, _ := newFloodRig(t)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	busy := func(code string) string {
		w := r.do("POST", "/claim", url.Values{"code": {code}}, func(q *http.Request) { *q = *q.WithContext(gone) })
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "busy") {
			t.Fatalf("busy answer: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if b := busy(claimCode); !strings.Contains(b, `value="`+claimCode+`"`) {
		t.Fatalf("busy answer lost the typed code: %s", b)
	}
	long := strings.Repeat("A", 33)
	if b := busy(long); strings.Contains(b, long) {
		t.Fatal("busy answer echoed a code over 32 characters")
	}
}

// lostPost posts form to /claim and loses the answer: the phone keeps
// the cookies it had before the post and none the answer set.
func (cr *claimRig) lostPost(form url.Values) int {
	cr.t.Helper()
	var u *url.URL
	var before []*http.Cookie
	w := cr.do("POST", "/claim", form, func(q *http.Request) { u = q.URL; before = cr.jar.Cookies(q.URL) })
	cr.jar, _ = cookiejar.New(nil)
	cr.jar.SetCookies(u, before)
	return w.Code
}

// CTRL-card-sock s3 (#1273): the phone whose claim answer was lost finds
// the form again and claims with the same code; no other phone is offered
// the form or can claim, and once the claimant phone is back the code is
// dead.
func TestALostClaimAnswerClaimsAgain(t *testing.T) {
	r := newClaimRig(t)
	r.get("/claim") // the page load gives this phone its nonce
	if code := r.lostPost(url.Values{"code": {claimCode}}); code != 303 {
		t.Fatalf("claim: %d", code)
	}
	for _, p := range []string{"/claim", "/setup"} {
		b := r.do("GET", p, nil).Body.String()
		if !strings.Contains(b, "type my sticker's code again") || !strings.Contains(b, `action="/claim"`) {
			t.Fatalf("GET %s does not offer the claim again: %s", p, b)
		}
	}
	w := r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "did not match my sticker") || len(w.Result().Cookies()) != 0 {
		t.Fatalf("wrong code in the window: %d %s", w.Code, w.Body.String())
	}

	// Another phone, even one that loaded the page, is offered no form and
	// cannot claim with the right code.
	owner := r.jar
	r.otherPhone()
	r.get("/claim")
	b := r.do("GET", "/claim", nil).Body.String()
	if strings.Contains(b, `action="/claim"`) || !strings.Contains(b, "already claimed") {
		t.Fatalf("other phone is offered the claim: %s", b)
	}
	if w := r.post("/claim", url.Values{"code": {claimCode}}); w.Code != 409 {
		t.Fatalf("other phone, right code: %d", w.Code)
	}
	r.jar = owner

	var u *url.URL
	var nonceOnly []*http.Cookie
	w = r.do("POST", "/claim", url.Values{"code": {claimCode}}, func(q *http.Request) { u = q.URL; nonceOnly = r.jar.Cookies(q.URL) })
	if w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatalf("same code again: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := r.do("GET", "/setup", nil); w.Code != 200 {
		t.Fatalf("re-claimed phone's setup page: %d", w.Code)
	}
	// The claimant phone came back: its nonce alone is offered no claim.
	r.jar, _ = cookiejar.New(nil)
	r.jar.SetCookies(u, nonceOnly)
	b = r.do("GET", "/claim", nil).Body.String()
	if strings.Contains(b, `action="/claim"`) || !strings.Contains(b, "already claimed") {
		t.Fatalf("claim page offers a claim after the claimant came back: %s", b)
	}
}
