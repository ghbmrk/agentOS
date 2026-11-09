package localui

import (
	"context"
	"crypto/hmac"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"unicode"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Inbox page (CH-14, D-311) is where a session's held messages wait:
// what the owner's number sent while the session was locked. Only this
// page opens a session (the sign-in in front of it), so it shows each
// message in full, as plain escaped text, and the owner's tap sends the
// ones marked and discards the rest of those shown. One that arrived after
// the page was drawn stays for the next visit. The form is bound to this
// phone's sign-in and to the list as shown, so another phone cannot
// replay it and a changed list is refused (stalePage).

type inboxView struct {
	Msgs        []inboxMsgView
	Shown, Tok  string
	Dropped     int
	Expired     int
	Msg, Err    string
	Unreachable bool
}

type inboxMsgView struct {
	ID, Date, Text string
	// Odd marks a message with characters outside printable ASCII, each
	// shown as [U+XXXX] (showField), so nothing the agent would get is
	// hidden from the owner (CH-14: they run only what they have read).
	Odd bool
}

// showHeld returns a held message as the page shows it (CH-14: the owner
// runs only text they have read). Visible characters show as they are:
// letters, numbers, punctuation, symbols, U+0020, line breaks, and marks
// on a visible character. Every invisible or reordering character shows
// as [U+XXXX] and flags the message: other controls, format characters
// (bidi controls, zero-width characters, the tag block), private-use and
// unassigned code points, line and paragraph separators, spaces other
// than U+0020, and characters drawn blank (Hangul fillers, U+2800). A
// variation selector shows only on a symbol, as an emoji's style. "[" is
// escaped too, unflagged, so text cannot fake a marker (#5185 Security,
// UX).
func showHeld(s string) (shown string, odd bool) {
	var b strings.Builder
	prev := rune(-1) // the last character shown as itself, -1 if none
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteRune(r)
			prev = -1
			continue
		case r == '[':
			b.WriteString("[U+005B]")
			prev = r
			continue
		case heldVisible(r, prev):
			b.WriteRune(r)
			prev = r
			continue
		}
		odd = true
		prev = -1
		fmt.Fprintf(&b, "[U+%04X]", r)
	}
	return b.String(), odd
}

// heldBlank are characters in visible categories that draw as nothing.
var heldBlank = map[rune]bool{0x115F: true, 0x1160: true, 0x3164: true, 0xFFA0: true, 0x2800: true, 0x180E: true}

// heldVisible reports whether r, after prev, shows as itself.
func heldVisible(r, prev rune) bool {
	switch {
	case heldBlank[r]:
		return false
	case r == ' ':
		return true
	case unicode.In(r, unicode.Variation_Selector):
		return prev >= 0 && unicode.Is(unicode.S, prev)
	case unicode.Is(unicode.M, r):
		return prev >= 0 // on a character shown as itself
	}
	return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)
}

const inboxUnreachable = "I can't show the messages you sent right now. Reload to try again."

// inbox serves the Inbox page behind sign-in (CH-7, CH-8, CH-14).
func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
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
	v := inboxView{}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		v.Msg, v.Err = s.runInbox(r.Context(), tok, sess, r.PostForm)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in localapi.Inbox
	if err := s.call(r.Context(), localapi.OpInbox, localapi.Auth{Token: tok}, &in); err != nil {
		if refused(err, localapi.ErrUnauthorized) {
			http.Redirect(w, r, "/unlock?next=/inbox/", http.StatusSeeOther)
			return
		}
		if v.Msg == "" && v.Err == "" {
			v.Err = inboxUnreachable
		}
	}
	var ids []string
	for _, m := range in.Msgs {
		ids = append(ids, m.ID)
		text, odd := showHeld(m.Text)
		v.Msgs = append(v.Msgs, inboxMsgView{ID: m.ID, Date: m.At.Local().Format("2 Jan 2006, 15:04"), Text: text, Odd: odd})
	}
	v.Shown = strings.Join(ids, ",")
	v.Tok = s.formToken(sess, "inbox", v.Shown)
	v.Dropped, v.Expired = in.Dropped, in.Expired
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "inbox", v)
}

// runInbox sends the owner's tap and returns the reply or the refusal.
func (s *Server) runInbox(ctx context.Context, tok, sess string, f map[string][]string) (msg, refusal string) {
	get := func(k string) string {
		if v := f[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	shown := get("shown")
	if shown == "" || !hmac.Equal([]byte(get("tok")), []byte(s.formToken(sess, "inbox", shown))) {
		return "", stalePage
	}
	ids := strings.Split(shown, ",")
	in := map[string]bool{}
	for _, id := range ids {
		in[id] = true
	}
	var run []string
	for _, id := range f["run"] {
		if !in[id] {
			return "", stalePage
		}
		run = append(run, id)
	}
	if len(ids) > localapi.MaxInbox {
		return "", stalePage
	}
	var a localapi.Answered
	err := s.call(ctx, localapi.OpRunInbox, localapi.RunInbox{Token: tok, Shown: ids, Run: run}, &a)
	switch {
	case err != nil:
		return "", inboxUnreachable
	case a.Refusal == localapi.RefusedChanged:
		return "", stalePage
	case a.Refusal != "":
		return "", inboxUnreachable
	}
	return a.Text, ""
}

func init() {
	template.Must(tmpl.Parse(`{{define "inbox"}}{{template "head" ""}}
<h1>Messages you sent</h1>
<p class="muted">These came from your number while the session was locked. Read each one: send only those you wrote.</p>
{{with .Msg}}<p>{{.}}</p>{{end}}{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{if .Msgs}}<form method="post" action="/inbox/">
<input type="hidden" name="shown" value="{{.Shown}}"><input type="hidden" name="tok" value="{{.Tok}}">
{{range .Msgs}}<section class="card"><label><input type="checkbox" name="run" value="{{.ID}}"> Send</label>
<p class="muted">{{.Date}}</p>{{if .Odd}}<p class="err">This message has hidden or unusual characters, shown as [U+…]. Send it only if you wrote all of it.</p>{{end}}<pre style="white-space:pre-wrap;overflow-wrap:anywhere">{{.Text}}</pre></section>
{{end}}<p><button type="submit">Send the marked ones, discard the rest</button></p></form>
{{else}}{{if not .Err}}<p>Nothing is waiting.</p>{{end}}{{end}}
{{with .Dropped}}<p class="muted">{{.}} more were dropped unread: the hold was full, or a deletion removed them because they quoted what it deleted.</p>{{end}}
{{with .Expired}}<p class="muted">{{.}} expired before you read them.</p>{{end}}
<p><a href="/home">More</a> · <a href="/status">Status</a></p>
{{template "foot"}}{{end}}`))
}
