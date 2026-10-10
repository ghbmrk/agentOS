package localui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Forget page (W3-forget-b3r, potency R2) lists the owner's recent
// tasks by the labels FORGET shows by text and asks to forget one. The
// ask is FORGET's own (CAP-3): agentosd submits it to the gate, the owner
// approves the request with a code, and only then is anything deleted, so
// the page says it asked, never that a task is forgotten. The form posts
// the task's goal ID alone.

type forgetView struct {
	Tasks  []forgetTaskView
	Locked bool
	// Msg is agentosd's reply to the last ask; Err is the page's refusal.
	Msg, Err string
}

type forgetTaskView struct {
	ID, Label, Tok string
}

const forgetStaleText = "This page is out of date. Reload it and choose the task again."

func init() {
	template.Must(tmpl.Parse(`{{define "forget"}}{{template "head" ""}}
<h1>Forget a task</h1>
{{with .Msg}}<p class="ok">{{.}}</p>{{end}}{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{if .Locked}}<p>Your session is locked, so no tasks are shown. Unlock it with a code first.</p>
{{else}}{{range .Tasks}}<section class="card"><p><bdi>{{.Label}}</bdi></p>
<form method="post" action="/forget/ask"><input type="hidden" name="task" value="{{.ID}}"><input type="hidden" name="tok" value="{{.Tok}}">
<button>Ask to forget</button></form></section>
{{else}}<p>No recent tasks to forget.</p>{{end}}{{end}}
<p class="muted">Asking sends you a request by text. Nothing is deleted until you approve it with a code, and you get a text when it is done.</p>
<p><a href="/approvals/">Approvals</a> · <a href="/home">More</a> · <a href="/status">Status</a></p>
{{template "foot"}}{{end}}`))
}

// forgetPage serves the Forget page behind sign-in (CH-7, CH-8): the list
// on GET, the ask on POST to /forget/ask only, so a GET never asks.
func (s *Server) forgetPage(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.forgetList(w, r, forgetView{})
	case "/ask":
		s.post(s.forgetAsk)(w, r)
	default:
		http.NotFound(w, r)
	}
}

// forgetAsk asks agentosd to forget the task the form names, then shows
// the list with agentosd's reply or the page's refusal.
func (s *Server) forgetAsk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	tok := cookieToken(r)
	v := forgetView{}
	var unauthorized bool
	v.Msg, v.Err, unauthorized = s.askForget(r.Context(), tok, tokenKey(tok), r.PostForm)
	if unauthorized {
		http.Redirect(w, r, "/unlock?next=/forget/", http.StatusSeeOther)
		return
	}
	s.forgetList(w, r, v)
}

func (s *Server) forgetList(w http.ResponseWriter, r *http.Request, v forgetView) {
	if s.getOwner() == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	tok := cookieToken(r)
	sess := tokenKey(tok)
	var l localapi.ForgetTasks
	if err := s.call(r.Context(), localapi.OpForgetTasks, localapi.Auth{Token: tok}, &l); err != nil {
		if refused(err, localapi.ErrUnauthorized) {
			http.Redirect(w, r, "/unlock?next=/forget/", http.StatusSeeOther)
			return
		}
		v.Err = pausedUnreachable
	}
	v.Locked = l.Locked
	for _, t := range l.Tasks {
		// The label is FORGET's own: a texted task's clipped words, else
		// only when it came. It is the owner's text, escaped and
		// isolated so it cannot reorder the page around it.
		v.Tasks = append(v.Tasks, forgetTaskView{ID: t.ID, Label: t.Label, Tok: s.forgetToken(sess, t.ID)})
	}
	s.render(w, "forget", v)
}

// askForget asks agentosd to forget the form's task and returns its reply
// or the page's refusal.
func (s *Server) askForget(ctx context.Context, tok, sess string, f map[string][]string) (msg, refusal string, unauthorized bool) {
	get := func(k string) string {
		if v := f[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	id := get("task")
	// The form is bound to this phone's sign-in and the task as shown, so
	// another phone cannot replay it and a changed task is stale;
	// agentosd asks only for a task it still lists.
	if id == "" || !hmac.Equal([]byte(get("tok")), []byte(s.forgetToken(sess, id))) {
		return "", forgetStaleText, false
	}
	var out localapi.Text
	if err := s.call(ctx, localapi.OpForget, localapi.Forget{Token: tok, ID: id}, &out); err != nil {
		switch {
		case refused(err, localapi.ErrUnauthorized):
			return "", "", true
		case refused(err, localapi.ErrBadArgs):
			return "", forgetStaleText, false
		}
		return "", pausedUnreachable, false
	}
	return out.Text, "", false
}

// forgetToken binds a forget form to the signed-in phone and the task.
// Its input is kept apart from formToken's and resumeToken's.
func (s *Server) forgetToken(sess, id string) string {
	m := hmac.New(sha256.New, s.formKey)
	fmt.Fprintf(m, "forget\x00%s\x00%s", sess, id)
	return hex.EncodeToString(m.Sum(nil))
}
