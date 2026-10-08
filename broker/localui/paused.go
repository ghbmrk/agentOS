package localui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Paused page (W5a-resume, Security R2 on #169) lists the paused
// grants, what resuming each lets run again and who paused it, and asks
// to resume one. Asking needs only the sign-in: agentosd turns it into a
// request the owner approves under Approvals with a fresh code, bound to
// that grant and to the pause shown here (grants.Gate.AskResume).

type pausedView struct {
	Grants []pausedGrantView
	// Msg is agentosd's reply to the last ask; Err is the page's refusal.
	Msg, Err string
}

type pausedGrantView struct {
	ID, What, By, Pause, Tok string
	Odd                      bool
}

const pausedUnreachable = "The box isn't answering right now. Nothing was asked. Reload to try again."

// paused serves the Paused page behind sign-in (CH-7).
func (s *Server) paused(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if s.getOwner() == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	tok := cookieToken(r)
	sess := tokenKey(tok)
	v := pausedView{}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		v.Msg, v.Err = s.askResume(r.Context(), tok, sess, r.PostForm)
	}
	var p localapi.Paused
	if err := s.call(r.Context(), localapi.OpPaused, localapi.Auth{Token: tok}, &p); err != nil {
		if refused(err, localapi.ErrUnauthorized) {
			http.Redirect(w, r, "/unlock?next=/paused/", http.StatusSeeOther)
			return
		}
		v.Err = pausedUnreachable
	}
	for _, g := range p.Grants {
		// The ID and pause are the gate's own; What carries a grant's
		// fields, shown as Approvals shows them.
		what, odd := showField(g.What)
		v.Grants = append(v.Grants, pausedGrantView{ID: g.ID, What: what, By: g.By, Pause: g.Pause, Tok: s.resumeToken(sess, g.ID, g.Pause), Odd: odd})
	}
	s.render(w, "paused", v)
}

// askResume asks agentosd to resume the grant the form names, from the
// pause it showed, and returns agentosd's reply or the page's refusal.
func (s *Server) askResume(ctx context.Context, tok, sess string, f map[string][]string) (msg, refusal string) {
	get := func(k string) string {
		if v := f[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	id, pause := get("grant"), get("pause")
	// The form is bound to this phone's sign-in, the grant and the pause
	// as shown, so another phone cannot replay it and a changed field is
	// stale; agentosd refuses a pause that has since ended or been
	// replaced.
	if id == "" || !hmac.Equal([]byte(get("tok")), []byte(s.resumeToken(sess, id, pause))) {
		return "", stalePage
	}
	var out localapi.Text
	if err := s.call(ctx, localapi.OpAskResume, localapi.AskResume{Token: tok, Grant: id, Pause: pause}, &out); err != nil {
		if refused(err, localapi.ErrBadArgs) {
			return "", stalePage
		}
		return "", pausedUnreachable
	}
	return out.Text, ""
}

// resumeToken binds a resume form to the signed-in phone, the grant and
// the pause as shown. Its input is kept apart from formToken's.
func (s *Server) resumeToken(sess, id, pause string) string {
	m := hmac.New(sha256.New, s.formKey)
	fmt.Fprintf(m, "resume\x00%s\x00%s\x00%s", sess, id, pause)
	return hex.EncodeToString(m.Sum(nil))
}
