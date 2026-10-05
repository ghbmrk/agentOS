package localui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
)

// The Approvals page (P2-2a, CH-10, UX-144-2) lists the owner channel's
// open requests with every field in full, and answers them: approving
// takes a fresh code each time, even on a signed-in phone, and denying
// needs only the sign-in. Each answer is texted to the owner by the
// channel (owner.LocalAnswer).

// approvalsView is the Approvals page.
type approvalsView struct {
	Requests []requestView
	// Msg is the channel's reply to the last answer; Err is a refusal.
	Msg, Err string
}

type requestView struct {
	ID, Sum, Tok string
	Expires      string
	// Local: the request can be answered here only.
	Local bool
	Items []itemView
}

type itemView struct {
	Verb, Object, Detail, Amount, Undo string
	Unverified                         bool
	Recipients                         []string
	// Odd: a field holds a character outside plain ASCII, shown as its
	// code point.
	Odd bool
}

// approvals serves the Approvals page behind sign-in (CH-7).
func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	o := s.getOwner()
	if o == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	sess := ""
	if c, err := r.Cookie(cookieName); err == nil {
		sess = tokenKey(c.Value)
	}
	v := approvalsView{}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		v.Msg, v.Err = s.answer(o, sess, r.PostForm)
	}
	for _, rq := range o.LocalRequests() {
		v.Requests = append(v.Requests, s.requestView(rq, sess))
	}
	s.render(w, "approvals", v)
}

// answer settles one request from the page's form and returns the
// channel's reply, or the owner-facing refusal.
func (s *Server) answer(o Owner, sess string, f map[string][]string) (msg, refusal string) {
	get := func(k string) string {
		if v := f[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	id, sum := get("id"), get("sum")
	// The form is bound to this phone's sign-in and to the request as it
	// was shown (owner.LocalRequest.Sum: every field, and the expiry), so
	// another phone cannot replay it, and the channel refuses it if the
	// request changed or closed since, or its ID was reused (Security D1).
	if !hmac.Equal([]byte(get("tok")), []byte(s.formToken(sess, id, sum))) {
		return "", stalePage
	}
	approve := false
	switch get("answer") {
	case "approve":
		approve = true
	case "deny":
	default:
		return "", "Choose Approve or Deny."
	}
	code := strings.TrimSpace(get("code"))
	if approve && code == "" {
		return "", "Enter a code from your code generator to approve."
	}
	if approve {
		// One approval at a time, so two posts cannot both pass mayTry
		// before either records a wrong code (L3 on #165).
		s.approveMu.Lock()
		defer s.approveMu.Unlock()
	}
	if approve && !s.mayTry(sess) {
		return "", "Too many wrong codes from this phone. Wait a minute, then try again."
	}
	if strings.HasPrefix(code, owner.UnlockProofPrefix) {
		return "", "That code did not work. Each code works once; wait for the next one."
	}
	out, err := o.LocalAnswer(id, sum, approve, code)
	switch {
	case err == nil:
		return out, ""
	case errors.Is(err, owner.ErrTooMany):
		return "", "Too many tries on the box's Wi-Fi in the last day, so approving here is paused for up to 24 hours. Deny still works here, and NO by text."
	case errors.Is(err, owner.ErrWrongCode):
		s.wrongTry(sess)
		if out != "" {
			return "", out // tries left, or void (UX A4)
		}
		return "", "That code did not work. Each code works once; wait for the next one."
	case errors.Is(err, owner.ErrNoRequest), errors.Is(err, owner.ErrChanged):
		return "", stalePage
	}
	// The channel's own reply when nothing was settled.
	return "", err.Error()
}

const stalePage = "This page is out of date. Check the request below and answer again."

// PageWrongPerMinute bounds wrong approval codes from one signed-in phone
// (Security D5), on top of the channel's per-request and daily bounds.
const PageWrongPerMinute = 5

func (s *Server) mayTry(sess string) bool {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, ts := range s.pageWrong {
		if ts = since(ts, now.Add(-time.Minute)); len(ts) == 0 {
			delete(s.pageWrong, k)
		} else {
			s.pageWrong[k] = ts
		}
	}
	if _, ok := s.pageWrong[sess]; !ok && len(s.pageWrong) >= MaxSessions*2 {
		return false // full: fail closed (Security R2 on #165)
	}
	return len(s.pageWrong[sess]) < PageWrongPerMinute
}

func (s *Server) wrongTry(sess string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pageWrong == nil {
		s.pageWrong = map[string][]time.Time{}
	}
	if len(s.pageWrong) < MaxSessions*2 {
		s.pageWrong[sess] = append(s.pageWrong[sess], s.cfg.Now())
	}
}

// since keeps the times after cut.
func since(ts []time.Time, cut time.Time) []time.Time {
	var out []time.Time
	for _, t := range ts {
		if t.After(cut) {
			out = append(out, t)
		}
	}
	return out
}

// formToken binds a request's form to the signed-in phone and to the
// request as shown.
func (s *Server) formToken(sess, id, sum string) string {
	m := hmac.New(sha256.New, s.formKey)
	fmt.Fprintf(m, "%s\x00%s\x00%s", sess, id, sum)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) requestView(rq owner.LocalRequest, sess string) requestView {
	v := requestView{ID: rq.ID, Sum: rq.Sum, Tok: s.formToken(sess, rq.ID, rq.Sum), Local: rq.Local, Expires: rq.By}
	for i, it := range rq.Items {
		if i < len(rq.Done) && rq.Done[i] {
			continue
		}
		iv := itemView{Unverified: it.Unverified}
		show := func(f string) string {
			shown, odd := showField(f)
			iv.Odd = iv.Odd || odd
			return shown
		}
		iv.Verb, iv.Object, iv.Detail, iv.Amount = show(it.Facts.Verb), show(it.Object), show(it.Detail), show(it.Amount)
		if it.Recipient != "" {
			// Split as the text counts them; only the separator's one
			// space is dropped.
			for _, rc := range strings.Split(it.Recipient, ",") {
				iv.Recipients = append(iv.Recipients, show(strings.TrimPrefix(rc, " ")))
			}
		}
		switch {
		case it.UndoWindow > 0:
			iv.Undo = "Undo within " + owner.DurText(it.UndoWindow) + "."
		case it.UndoBy != "":
			iv.Undo = show(it.UndoBy)
		default:
			iv.Undo = "Cannot be undone."
		}
		v.Items = append(v.Items, iv)
	}
	return v
}

// showField returns s as the page shows it: printable ASCII as is, and
// every other character, and "[", as its code point in brackets, so a
// look-alike letter, an invisible character or a direction override is
// seen rather than rendered, and a literal "[U+...]" cannot pass for one.
// Nothing is folded or normalized. odd reports a replaced character.
func showField(s string) (shown string, odd bool) {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e && r != '[' {
			b.WriteRune(r)
			continue
		}
		odd = true
		fmt.Fprintf(&b, "[U+%04X]", r)
	}
	return b.String(), odd
}
