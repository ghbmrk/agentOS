package page

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/ghbmrk/agentos/broker/enforcer/page/internal/csrf"
)

// The page's anti-forgery pair (CH-9, #4387) is package csrf's: a screen
// sets its cookie and carries its token, and ServeHTTP refuses every
// request other than GET, before it looks up a route, unless guard passes
// it, so no handler can skip the check and a route added later starts
// refused. The page never holds a key, a tag or a token as a value: csrf
// writes the token into each screen itself (render), so neither page code
// nor the templates can reach one (#4685, re-plan of #4731).
const (
	tokenCookie = csrf.Cookie
	tokenHeader = csrf.Header
)

var errToken = errors.New("this screen is out of date; reload it and try again")

// guard is the one check every state-changing request passes before any
// route sees it: sent by the page itself (sameOrigin), with the cookie a
// screen of this page set at most csrf.PairLife ago and the token that
// screen carried.
func (s *Server) guard(r *http.Request) error {
	if !s.sameOrigin(r) {
		return errCrossOrigin
	}
	if !s.tokens.Check(r) {
		return errToken
	}
	return nil
}

// render draws a screen for r; csrf writes its opening with the token.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	var b bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&b, name, data); err != nil {
		http.Error(w, "page error", http.StatusInternalServerError)
		return
	}
	if !s.tokens.Screen(w, r, b.Bytes()) {
		http.Error(w, "page error", http.StatusInternalServerError)
	}
}
