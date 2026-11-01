package page

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

// The page's anti-forgery token (CH-9, #4387). A screen the page draws sets
// a cookie, SameSite=Strict, HttpOnly, Secure and host-only (the __Host-
// prefix), and carries in its markup a token that is that cookie's MAC
// under a key the page draws at start and never shows. ServeHTTP refuses
// every request other than GET before it looks up a route unless it
// carries both and they match (guard), so no handler can skip the check,
// and a route added later starts refused.
//
// A page the owner merely visits cannot pass it: the browser does not send
// a SameSite=Strict cookie on a request another site starts, HttpOnly keeps
// the cookie from script, __Host- keeps another host on the same site from
// planting one, and the token comes only from a screen of this origin,
// which the page's other headers keep from being read or framed elsewhere.
//
// The cookie is a random nonce, the time it was drawn, and a tag over both
// under the same key (#4428). A screen reached by a same-site navigation
// that sends a cookie this page drew less than reuseFor ago keeps it, so a
// second tab or a reload leaves the first screen's pair working; any other
// screen mints a new one. A link opened from a text is a cross-site
// navigation, on which the browser withholds the cookie, so it mints.
const (
	tokenCookie = "__Host-enforcer"
	tokenHeader = "X-Enforcer-Token"
	tokenLabel  = "agentOS enforcer page token\x00"
	cookieLabel = "agentOS enforcer page cookie\x00"
	nonceLen    = 16
	cookieLen   = nonceLen + 8 + sha256.Size
)

// reuseFor is how long after it was drawn a cookie may still be kept by a
// new screen. Past it the next screen mints, and older screens' taps fail
// with "reload it", as they do after the enforcer restarts.
const reuseFor = 12 * time.Hour

var errToken = errors.New("this screen is out of date; reload it and try again")

// newTokenKey draws the page's token key.
func newTokenKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// token returns the token a screen drawn for r carries, keeping the
// cookie r sent when keep allows it and otherwise setting a new one on w.
func (s *Server) token(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, ok := s.keep(r); ok {
		return base64.RawURLEncoding.EncodeToString(s.mac(c)), nil
	}
	return s.mint(w)
}

// keep returns the cookie r sent when a new screen may keep it: the
// browser calls the navigation same-origin, same-site or its own (none),
// and the cookie is one this page drew, at most reuseFor ago and not in
// the future. A cross-site request, one with no Sec-Fetch-Site, or a
// cookie the page cannot vouch for (another key, a restart, tampered,
// expired) is not kept.
func (s *Server) keep(r *http.Request) ([]byte, bool) {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site", "none":
	default:
		return nil, false
	}
	ck, err := r.Cookie(tokenCookie)
	if err != nil {
		return nil, false
	}
	c, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(c) != cookieLen || !hmac.Equal(c[nonceLen+8:], s.tag(c[:nonceLen+8])) {
		return nil, false
	}
	drawn := time.UnixMilli(int64(binary.BigEndian.Uint64(c[nonceLen : nonceLen+8])))
	if now := s.cfg.Now(); drawn.After(now) || now.Sub(drawn) > reuseFor {
		return nil, false
	}
	return c, true
}

// mint sets a new cookie on w and returns the token a screen drawn with it
// carries.
func (s *Server) mint(w http.ResponseWriter) (string, error) {
	c := make([]byte, nonceLen+8, cookieLen)
	if _, err := rand.Read(c[:nonceLen]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(c[nonceLen:], uint64(s.cfg.Now().UnixMilli()))
	c = append(c, s.tag(c)...)
	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookie,
		Value:    base64.RawURLEncoding.EncodeToString(c),
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return base64.RawURLEncoding.EncodeToString(s.mac(c)), nil
}

// tag vouches for a cookie's nonce and time as this page's.
func (s *Server) tag(body []byte) []byte {
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(cookieLabel))
	m.Write(body)
	return m.Sum(nil)
}

func (s *Server) mac(cookie []byte) []byte {
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(tokenLabel))
	m.Write(cookie)
	return m.Sum(nil)
}

// guard is the one check every state-changing request passes before any
// route sees it: sent by the page itself (sameOrigin), with the cookie a
// screen of this page set and the token that screen carried.
func (s *Server) guard(r *http.Request) error {
	if !s.sameOrigin(r) {
		return errCrossOrigin
	}
	ck, err := r.Cookie(tokenCookie)
	if err != nil {
		return errToken
	}
	c, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(c) != cookieLen {
		return errToken
	}
	t, err := base64.RawURLEncoding.DecodeString(r.Header.Get(tokenHeader))
	if err != nil || !hmac.Equal(t, s.mac(c)) {
		return errToken
	}
	return nil
}
