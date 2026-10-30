package localui

import (
	"html/template"
	"net/http"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Held page (#993; CH-8, CH-19, CH-21) shows what the box kept in
// place of a text: what the owner channel held back, and agent replies
// too long to text or that did not go. Each is shown as plain text,
// escaped and with no link made live, and reading it removes nothing; an
// expired one says so in one line, and one whose code has expired says so
// beside its kind (CH-19, #906).

type heldView struct {
	Items, Expired []heldItemView
	Err            string
}

type heldItemView struct {
	Date, Kind, Text string
}

const heldUnreachable = "I can't show held messages right now. Reload to try again."

// heldKinds names each kind on the page; a reply kept before kinds were
// recorded has none.
var heldKinds = map[string]string{
	localapi.HeldSecret:  "Held back: it may contain a code or key",
	localapi.HeldOneTime: "Held back: it had a code in it",
	localapi.HeldCode:    "Held back: it mentioned a code",
	localapi.HeldLong:    "Too long to text",
	localapi.HeldUnsent:  "Did not send",
}

// held serves the Held page behind sign-in (CH-7, CH-8).
func (s *Server) held(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.getOwner() == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	var l localapi.HeldList
	v := heldView{}
	if err := s.call(r.Context(), localapi.OpHeld, localapi.Auth{Token: cookieToken(r)}, &l); err != nil {
		if refused(err, localapi.ErrUnauthorized) {
			http.Redirect(w, r, "/unlock?next=/held/", http.StatusSeeOther)
			return
		}
		v.Err = heldUnreachable
	}
	for _, it := range l.Items {
		if it.Expired {
			v.Expired = append(v.Expired, heldItemView{Date: it.At.Local().Format("2 Jan")})
			continue
		}
		kind, ok := heldKinds[it.Kind]
		if !ok {
			kind = "Agent reply"
		}
		if it.CodeExpired {
			kind += "; the code has expired"
		}
		v.Items = append(v.Items, heldItemView{Date: it.At.Local().Format("2 Jan 2006, 15:04"), Kind: kind, Text: it.Text})
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "held", v)
}

func init() {
	template.Must(tmpl.Parse(`{{define "held"}}{{template "head" ""}}
<h1>Held messages</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{range .Items}}<section class="card"><p class="muted">{{.Date}} · {{.Kind}}</p>
<pre style="white-space:pre-wrap;overflow-wrap:anywhere">{{.Text}}</pre></section>
{{else}}{{if not .Err}}<p>Nothing is held.</p>{{end}}{{end}}
{{range .Expired}}<p class="muted">A held message from {{.Date}} has expired.</p>
{{end}}<p class="muted">Each stays here until it expires; reading it removes nothing.</p>
<p><a href="/home">More</a> · <a href="/status">Status</a></p>
{{template "foot"}}{{end}}`))
}
