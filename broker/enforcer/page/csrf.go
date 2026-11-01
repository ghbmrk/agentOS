package page

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
)

// The page's anti-forgery token (CH-9, #4387). Every screen the page draws
// sets a fresh random cookie, SameSite=Strict, HttpOnly, Secure and
// host-only (the __Host- prefix), and carries in its markup a token that is
// that cookie's MAC under a key the page draws at start and never shows.
// ServeHTTP refuses every request other than GET before it looks up a
// route unless it carries both and they match (guard), so no handler can
// skip the check, and a route added later starts refused.
//
// A page the owner merely visits cannot pass it: the browser does not send
// a SameSite=Strict cookie on a request another site starts, HttpOnly keeps
// the cookie from script, __Host- keeps another host on the same site from
// planting one, and the token comes only from a screen of this origin,
// which the page's other headers keep from being read or framed elsewhere.
const (
	tokenCookie = "__Host-enforcer"
	tokenHeader = "X-Enforcer-Token"
	tokenLabel  = "agentOS enforcer page token\x00"
)

var errToken = errors.New("this screen is out of date; reload it and try again")

// newTokenKey draws the page's token key.
func newTokenKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// mint sets a fresh cookie on w and returns the token a screen drawn with
// it carries. A screen opened from a text is a cross-site navigation, which
// the browser sends without the cookie, so every screen mints its own
// rather than reuse one it may not be shown.
func (s *Server) mint(w http.ResponseWriter) (string, error) {
	c := make([]byte, 32)
	if _, err := rand.Read(c); err != nil {
		return "", err
	}
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
	if err != nil || len(c) != 32 {
		return errToken
	}
	t, err := base64.RawURLEncoding.DecodeString(r.Header.Get(tokenHeader))
	if err != nil || !hmac.Equal(t, s.mac(c)) {
		return errToken
	}
	return nil
}
