// Package csrf is the enforcer page's anti-forgery pair (CH-9, #4387).
//
// A screen sets a cookie, SameSite=Strict, HttpOnly, Secure and host-only
// (the __Host- prefix), and carries in its markup a token that is that
// cookie's MAC under a key Tokens draws at start and never shows. Check
// refuses a request without both, matching.
//
// The cookie is a random nonce, the time it was drawn, and a tag over both
// under the same key with another label (#4428, #4479). A screen reached
// by a navigation the browser calls same-origin, same-site or its own
// (none) that sends a cookie drawn at most ReuseFor ago keeps it, so a
// second tab or a reload leaves the first screen's pair working; any other
// screen mints a new one. Check refuses a pair whose cookie was drawn more
// than PairLife ago or in the future (#4427).
//
// The key, the tags and the tokens never leave this package as values
// (#4685, re-plan of #4731): no exported name takes or returns one, the
// only token that leaves is the one Screen writes, in a place Screen fixes,
// into the response it is handed, and Tokens holds the key only inside a
// closure, so fmt of a Tokens, or of anything holding one, prints at most
// a code address. The page imports this package as internal, so no other
// package can. TestAPI pins that surface through go/types.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"time"
)

// Cookie and Header name the pair on the wire.
const (
	Cookie = "__Host-enforcer"
	Header = "X-Enforcer-Token"
)

// PairLife is how long after its cookie was drawn a pair still passes
// Check; past it a tap fails with ErrToken's "reload it", as after a
// restart. ReuseFor is how long a new screen may keep a cookie: half of
// PairLife, so a screen that keeps one still has at least half a day.
const (
	PairLife = 24 * time.Hour
	ReuseFor = PairLife / 2
)

// ErrToken is Check's refusal.
var ErrToken = errors.New("this screen is out of date; reload it and try again")

const (
	tokenLabel  = "agentOS enforcer page token\x00"
	cookieLabel = "agentOS enforcer page cookie\x00"
	nonceLen    = 16
	bodyLen     = nonceLen + 8
	cookieLen   = bodyLen + sha256.Size
)

// prefix opens every screen, up to the token's value: the token sits in
// one place, which the page's markup cannot move.
const prefix = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"enforcer-token\" content=\""

// Tokens draws and checks the page's pairs. Its fields are funcs only, so
// fmt prints no key.
type Tokens struct {
	now func() time.Time
	mac func(label string, body []byte) []byte // keyed by the closure alone
}

// New draws a key and returns the pairs under it, on now's clock.
func New(now func() time.Time) (*Tokens, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &Tokens{now: now, mac: func(label string, body []byte) []byte {
		m := hmac.New(sha256.New, k)
		m.Write([]byte(label))
		m.Write(body)
		return m.Sum(nil)
	}}, nil
}

// Screen writes markup to w as a screen for r: it keeps the cookie r sent
// when keep allows it and otherwise sets a new one, then writes the
// screen's opening with the token, then markup. It fails, having written
// nothing, only when it cannot draw a nonce.
func (t *Tokens) Screen(w http.ResponseWriter, r *http.Request, markup []byte) error {
	body, ok := t.keep(r)
	if !ok {
		body = make([]byte, bodyLen)
		if _, err := rand.Read(body[:nonceLen]); err != nil {
			return err
		}
		binary.BigEndian.PutUint64(body[nonceLen:], uint64(t.now().UnixMilli()))
		http.SetCookie(w, &http.Cookie{
			Name:     Cookie,
			Value:    base64.RawURLEncoding.EncodeToString(append(body[:bodyLen:bodyLen], t.mac(cookieLabel, body)...)),
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	out := append([]byte(prefix), base64.RawURLEncoding.EncodeToString(t.mac(tokenLabel, body))...)
	w.Write(append(append(out, "\">\n"...), markup...))
	return nil
}

// Check passes r when it carries a cookie this page drew at most PairLife
// ago and, in Header, the token a screen drawn with it carries.
func (t *Tokens) Check(r *http.Request) error {
	c, ok := t.cookie(r)
	if !ok {
		return ErrToken
	}
	if a, ok := t.age(c); !ok || a > PairLife {
		return ErrToken
	}
	tok, err := base64.RawURLEncoding.DecodeString(r.Header.Get(Header))
	if err != nil || !hmac.Equal(t.mac(tokenLabel, c[:bodyLen]), tok) {
		return ErrToken
	}
	return nil
}

// keep returns the body of the cookie r sent when a new screen may keep
// it: the browser calls the navigation same-origin, same-site or its own
// (none), and the cookie is one this page drew at most ReuseFor ago. A
// cross-site request, one with no Sec-Fetch-Site, or a cookie the page
// cannot vouch for or that is older is not kept.
func (t *Tokens) keep(r *http.Request) ([]byte, bool) {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site", "none":
	default:
		return nil, false
	}
	c, ok := t.cookie(r)
	if !ok {
		return nil, false
	}
	if a, ok := t.age(c); !ok || a > ReuseFor {
		return nil, false
	}
	return c[:bodyLen], true
}

// cookie returns the raw cookie r sent.
func (t *Tokens) cookie(r *http.Request) ([]byte, bool) {
	ck, err := r.Cookie(Cookie)
	if err != nil {
		return nil, false
	}
	c, err := base64.RawURLEncoding.DecodeString(ck.Value)
	return c, err == nil
}

// age is how long ago this page drew cookie c. It is false when the page
// cannot vouch for c (the wrong length, another key, a restart, tampered)
// or c was drawn after now (the clock went back).
func (t *Tokens) age(c []byte) (time.Duration, bool) {
	if len(c) != cookieLen || !hmac.Equal(t.mac(cookieLabel, c[:bodyLen]), c[bodyLen:]) {
		return 0, false
	}
	a := t.now().Sub(time.UnixMilli(int64(binary.BigEndian.Uint64(c[nonceLen:bodyLen]))))
	return a, a >= 0
}
