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
// under the same key (#4428). A screen reached by a navigation the browser
// calls same-origin, same-site or its own (none) that sends a cookie this
// page drew at most reuseFor ago keeps it, so a second tab or a reload
// leaves the first screen's pair working; any other screen mints a new
// one, including one another site opens, on which the browser withholds
// the Strict cookie. guard refuses a pair whose cookie was drawn more than
// pairLife ago (#4427), so no pair outlives a day even while the enforcer
// runs, and every screen's pair lasts at least pairLife-reuseFor.
//
// A tag and a token are each a secret, which leaves only by its exits
// (#4427, #4685). Its one field is a func, so == on a secret does not
// compile and fmt prints at most a code address for it in any holder, at
// any depth, under any verb (fmt never calls a func value). Its methods are
// equal, which runs hmac.Equal in constant time; setCookie, which writes
// the cookie onto the response (only ever a writer net/http called a
// handler with) and is called only by mint; and IssueToken,
// which only the embedded templates call, as {{.Token.IssueToken}}, into
// the one buffer render writes to the response. TestSecretsLeaveOnlyByTheirExits
// pins that structure, and TestExitCheckCatchesEachRoute shows it refusing
// each route it closes.
const (
	tokenCookie = "__Host-enforcer"
	tokenHeader = "X-Enforcer-Token"
	tokenLabel  = "agentOS enforcer page token\x00"
	cookieLabel = "agentOS enforcer page cookie\x00"
	nonceLen    = 16
	bodyLen     = nonceLen + 8
	cookieLen   = bodyLen + sha256.Size
)

// pairLife is how long after its cookie was drawn a pair still passes
// guard; past it a tap fails with "reload it", as after a restart. reuseFor
// is how long a new screen may keep a cookie: half of pairLife, so a screen
// that keeps one still has at least half a day to be tapped.
const (
	pairLife = 24 * time.Hour
	reuseFor = pairLife / 2
)

var errToken = errors.New("this screen is out of date; reload it and try again")

// secret is a MAC the page derives under its token key.
type secret struct{ secretSum func() []byte }

// newSecret is sum as a secret.
func newSecret(sum []byte) secret { return secret{func() []byte { return sum }} }

// equal reports, in constant time, whether b is x; a zero secret equals nothing.
func (x secret) equal(b []byte) bool {
	return x.secretSum != nil && len(x.secretSum()) == sha256.Size && hmac.Equal(x.secretSum(), b)
}

// IssueToken is x as a screen carries it; only templates call it.
func (x secret) IssueToken() string { return base64.RawURLEncoding.EncodeToString(x.secretSum()) }

// setCookie sets on w the anti-forgery cookie for body tagged with x.
func (x secret) setCookie(w http.ResponseWriter, body []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     tokenCookie,
		Value:    base64.RawURLEncoding.EncodeToString(append(body[:len(body):len(body)], x.secretSum()...)),
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

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
func (s *Server) token(w http.ResponseWriter, r *http.Request) (secret, error) {
	if c, ok := s.keep(r); ok {
		return s.mac(c[:bodyLen]), nil
	}
	return s.mint(w)
}

// keep returns the cookie r sent when a new screen may keep it: the
// browser calls the navigation same-origin, same-site or its own (none),
// and the cookie is one this page drew at most reuseFor ago (age). A
// cross-site request, one with no Sec-Fetch-Site, or a cookie the page
// cannot vouch for or that is older is not kept.
func (s *Server) keep(r *http.Request) ([]byte, bool) {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site", "none":
	default:
		return nil, false
	}
	c, ok := s.cookie(r)
	if !ok {
		return nil, false
	}
	if a, ok := s.age(c); !ok || a > reuseFor {
		return nil, false
	}
	return c, true
}

// cookie returns the raw anti-forgery cookie r sent.
func (s *Server) cookie(r *http.Request) ([]byte, bool) {
	ck, err := r.Cookie(tokenCookie)
	if err != nil {
		return nil, false
	}
	c, err := base64.RawURLEncoding.DecodeString(ck.Value)
	return c, err == nil
}

// age is how long ago this page drew cookie c. It is false when the page
// cannot vouch for c (the wrong length, another key, a restart, tampered)
// or c was drawn after now (the clock went back).
func (s *Server) age(c []byte) (time.Duration, bool) {
	if len(c) != cookieLen || !s.tag(c[:bodyLen]).equal(c[bodyLen:]) {
		return 0, false
	}
	a := s.cfg.Now().Sub(time.UnixMilli(int64(binary.BigEndian.Uint64(c[nonceLen:bodyLen]))))
	return a, a >= 0
}

// mint sets a new cookie on w and returns the token a screen drawn with it
// carries.
func (s *Server) mint(w http.ResponseWriter) (secret, error) {
	body := make([]byte, bodyLen)
	if _, err := rand.Read(body[:nonceLen]); err != nil {
		return secret{}, err
	}
	binary.BigEndian.PutUint64(body[nonceLen:], uint64(s.cfg.Now().UnixMilli()))
	s.tag(body).setCookie(w, body)
	return s.mac(body), nil
}

// tag vouches for a cookie's nonce and time as this page's.
func (s *Server) tag(body []byte) secret {
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(cookieLabel))
	m.Write(body)
	return newSecret(m.Sum(nil))
}

// mac is the token a screen carries for the cookie with this body. It
// MACs the same bytes as tag under the same key, so only its label, which
// differs from tag's, keeps either from standing in for the other.
func (s *Server) mac(body []byte) secret {
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(tokenLabel))
	m.Write(body)
	return newSecret(m.Sum(nil))
}

// guard is the one check every state-changing request passes before any
// route sees it: sent by the page itself (sameOrigin), with the cookie a
// screen of this page set at most pairLife ago and the token that screen
// carried.
func (s *Server) guard(r *http.Request) error {
	if !s.sameOrigin(r) {
		return errCrossOrigin
	}
	c, ok := s.cookie(r)
	if !ok {
		return errToken
	}
	if a, ok := s.age(c); !ok || a > pairLife {
		return errToken
	}
	t, err := base64.RawURLEncoding.DecodeString(r.Header.Get(tokenHeader))
	if err != nil || !s.mac(c[:bodyLen]).equal(t) {
		return errToken
	}
	return nil
}
