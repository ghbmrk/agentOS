package localui

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// Accounts is the account clerks' installed-app sign-in (clerk.SignIn,
// #2852; D-150), as the Connect page uses it. The page relays one frame
// each way (D-154): the consent address comes out, the pasted address goes
// in, and the verifier, the code's answer, the tokens and the client
// secret stay in the clerk. Both answer a typed detail, "" for none,
// carrying no value (CLK-4). session is the phone's session token, which
// agentosd checks before the frame goes on (AgentosdAccounts, #3006).
type Accounts interface {
	// Begin starts account's sign-in for one declared use and returns the
	// consent address. reg is the household's client, given at its first
	// sign-in; nil signs in again with the client the clerk sealed.
	Begin(ctx context.Context, session, account, use string, reg *AccountRegistration) (consent, detail string)
	// Finish hands the clerk the address the owner pasted and the use the
	// confirm screen named, and returns its detail: "signedin <use>" when
	// the grant is sealed, "use" when the clerk's waiting sign-in is for
	// another use (it refuses before redeeming anything).
	Finish(ctx context.Context, session, account, use, pasted string) string
}

// AccountRegistration is the household's own client (clerk.Registration).
type AccountRegistration struct {
	ID, Secret string
}

// ConnectDeclaration is the owner page's Connect step for one declared API
// account (#2853, SPEC §12.1 step 7): the registration steps, the names
// the provider's consent warning shows, each use and what it gets, and
// what the box never gets. Its ID and use IDs are the clerk's.
type ConnectDeclaration struct {
	ID, Name, Provider string
	// AppName is the name the steps tell the owner to give the client,
	// which the provider's "unverified app" warning then shows.
	AppName string
	// ConsentHost is the only host the page links consent to, over https.
	ConsentHost string
	Steps       []ConnectStep
	Uses        []ConnectUse
	Never       []string
}

// ConnectStep is one registration step, done by hand once on the owner's
// own device. Link opens the provider's console; Check makes it a box the
// owner ticks before the first sign-in.
type ConnectStep struct {
	Text, Link string
	Check      bool
}

// ConnectUse is one declared use (CLK-9): its name, what it is for, what
// the box gets with it, and a warning shown beside it.
type ConnectUse struct {
	ID, Name, Text string
	Gets           []string
	Warn           string
}

// GmailConnect is the Connect step for Gmail (D-150). The steps follow
// Google's console as of 2026-10; the uses are inbox.GmailUses.
var GmailConnect = ConnectDeclaration{
	ID: "gmail", Name: "Gmail", Provider: "Google", AppName: "agentOS at home", ConsentHost: "accounts.google.com",
	Steps: []ConnectStep{
		{Text: "Create a Google Cloud project, signed in as you. Any name works.", Link: "https://console.cloud.google.com/projectcreate"},
		{Text: "Turn on the Gmail API for that project.", Link: "https://console.cloud.google.com/apis/library/gmail.googleapis.com"},
		{Text: "Under Branding, name the app agentOS at home and give your own email as the support and developer contact. Leave the logo empty: a logo starts Google's review.", Link: "https://console.cloud.google.com/auth/branding"},
		{Text: "Under Audience, choose External, then Publish app, so Publishing status reads In production. In Testing, Google ends every sign-in after 7 days.", Link: "https://console.cloud.google.com/auth/audience", Check: true},
		{Text: "Under Clients, create a client of type Desktop app, then copy its client ID and secret below.", Link: "https://console.cloud.google.com/auth/clients"},
	},
	Uses: []ConnectUse{
		{ID: "watch", Name: "Watch", Text: "see who wrote and what about, never the message itself",
			Gets: []string{"the sender, recipients, subject and date of each message", "your labels"}},
		{ID: "archive", Name: "Archive", Text: "read your mail and keep copies",
			Gets: []string{"read every message and attachment"}},
		{ID: "sort", Name: "Sort", Text: "read, label and trash your mail",
			Gets: []string{"read every message and attachment", "sort messages into labels", "move messages to the trash", "send mail as you"},
			Warn: "This also lets me send mail as you."},
	},
	Never: []string{"delete mail forever", "change your Gmail settings or filters", "your Google password or sign-in", "your account recovery"},
}

func (d ConnectDeclaration) validate() error {
	if !plainID(d.ID) || d.Name == "" || d.AppName == "" || d.ConsentHost == "" || len(d.Uses) == 0 {
		return errors.New("localui: an account's Connect step needs an ID, names, a consent host and its uses")
	}
	for _, s := range d.Steps {
		if u, err := url.Parse(s.Link); s.Text == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("localui: a registration step needs text and an https link")
		}
	}
	seen := map[string]bool{}
	for _, u := range d.Uses {
		if !plainID(u.ID) || seen[u.ID] || u.Name == "" || len(u.Gets) == 0 {
			return errors.New("localui: each use needs its own ID, a name and what it gets")
		}
		seen[u.ID] = true
	}
	return nil
}

func plainID(s string) bool {
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func (d *ConnectDeclaration) use(id string) *ConnectUse {
	for i := range d.Uses {
		if d.Uses[i].ID == id {
			return &d.Uses[i]
		}
	}
	return nil
}

// consentLink is the consent address as a link, only when it is https on
// the declared host.
func (d *ConnectDeclaration) consentLink(a string) string {
	u, err := url.Parse(a)
	if err != nil || u.Scheme != "https" || u.Host != d.ConsentHost || u.User != nil {
		return ""
	}
	return a
}

// Bounds on what the Connect forms take, agentosd's own (localapi).
const (
	maxClientField = localapi.MaxClientField
	maxPasted      = localapi.MaxPasted
)

// connectView is the Connect page in one of its steps: the registration
// form, the consent link with its paste field, the confirm screen, or the
// result.
type connectView struct {
	Account *ConnectDeclaration
	// Step is "", "consent", "confirm" or "done".
	Step string
	Use  *ConnectUse
	// Consent is the checked consent address; Email the developer contact
	// typed with this registration, "" on signing in again.
	Consent, Email, Pasted string
	Err, Done              string
}

// accountsPage serves /accounts/ behind sign-in (CH-7): the list of
// declared accounts, and each account's Connect step. GET only shows;
// every step that reaches the clerk is a form post (CH-9).
func (s *Server) accountsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		s.render(w, "accounts", s.cfg.Connect)
		return
	}
	var d *ConnectDeclaration
	for i := range s.cfg.Connect {
		if "/"+s.cfg.Connect[i].ID == r.URL.Path {
			d = &s.cfg.Connect[i]
		}
	}
	if d == nil {
		http.NotFound(w, r)
		return
	}
	v := connectView{Account: d}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.render(w, "connect", v)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	switch f.Get("step") {
	case "begin":
		if v.Use = d.use(f.Get("use")); v.Use == nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		var reg *AccountRegistration
		if f.Get("again") != "1" {
			reg = &AccountRegistration{ID: strings.TrimSpace(f.Get("id")), Secret: strings.TrimSpace(f.Get("secret"))}
			v.Email = strings.TrimSpace(f.Get("email"))
			switch {
			case reg.ID == "" || reg.Secret == "" || len(reg.ID) > maxClientField || len(reg.Secret) > maxClientField:
				v.Err = "Copy the client ID and secret from Google's Clients page, then try again."
			case len(v.Email) > 254 || strings.ContainsAny(v.Email, " \t\r\n") || v.Email != "" && !strings.Contains(v.Email, "@"):
				v.Err = "That email doesn't look right. Type the one you gave as the developer contact."
			case !hasChecks(d, f):
				v.Err = "Tick each step once it is done. A client left in Testing loses its sign-in after 7 days."
			}
			if v.Err != "" {
				s.render(w, "connect", v)
				return
			}
		}
		consent, detail := s.cfg.Accounts.Begin(ctx, cookieToken(r), d.ID, v.Use.ID, reg)
		if detail == "" {
			if v.Consent = d.consentLink(consent); v.Consent == "" {
				detail = "badlink"
			}
		}
		if detail != "" {
			v.Err, v.Email = beginText(detail), ""
			s.render(w, "connect", v)
			return
		}
		v.Step = "consent"
	case "paste":
		v.Use = d.use(f.Get("use"))
		v.Pasted = strings.TrimSpace(f.Get("pasted"))
		if v.Use == nil || v.Pasted == "" || len(v.Pasted) > maxPasted {
			v.Pasted, v.Err = "", "Paste the whole address your phone landed on, then try again. If the sign-in ran out, start again."
			break
		}
		v.Step = "confirm"
	case "connect":
		// The form carries the use its confirm screen showed; the clerk
		// finishes only that use.
		confirmed := d.use(f.Get("use"))
		if confirmed == nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		pasted := strings.TrimSpace(f.Get("pasted"))
		if pasted == "" || len(pasted) > maxPasted {
			v.Err = connectText(dNotOurs)
			break
		}
		detail := s.cfg.Accounts.Finish(ctx, cookieToken(r), d.ID, confirmed.ID, pasted)
		if use, ok := strings.CutPrefix(detail, dSignedIn+" "); ok {
			// A use the declaration lacks is still a sealed grant: say it
			// connected rather than that nothing did.
			v.Step, v.Use, v.Done = "done", d.use(use), d.Name+" is connected."
			break
		}
		v.Err = connectText(detail)
	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	s.render(w, "connect", v)
}

// hasChecks says the owner ticked every checked registration step; the
// form names each "check-<index>".
func hasChecks(d *ConnectDeclaration, f url.Values) bool {
	for i, st := range d.Steps {
		if st.Check && f.Get("check-"+strconv.Itoa(i)) != "1" {
			return false
		}
	}
	return true
}

// The clerk's sign-in details (clerk.D*), pinned by
// TestConnectTextsForEachDetail.
const (
	dSignedIn   = "signedin"
	dNoSignIn   = "nosignin"
	dNotOurs    = "notours"
	dState      = "state"
	dUse        = "use"
	dRefused    = "refused"
	dScope      = "scope"
	dNoGrant    = "nogrant"
	dExchange   = "exchange"
	dNoAccount  = "noaccount"
	dRegistered = "registered"
)

// connectText is the owner's wording for Finish's detail. Each names a
// step that works (CH-12) and none carries a value.
func connectText(detail string) string {
	first, _, _ := strings.Cut(detail, " ")
	switch first {
	case dNotOurs:
		return "That isn't the address your phone landed on. Copy the whole address from the page that didn't load (it starts with http://127.0.0.1), then start again."
	case dNoSignIn:
		return "That sign-in ran out or was replaced by a newer one. Start again below."
	case dState:
		return "That address is from a different sign-in. Start again below, and paste the address from that one."
	case dUse:
		return "That address is from a sign-in for a different use than the one you confirmed, so nothing is connected. Start again below, and use one tab."
	case dRefused:
		return "You said no on Google's page, so nothing is connected. Start again below if you change your mind."
	case dScope:
		return "Google gave a different permission than I asked for, so I gave it back. Start again and leave every box on Google's page ticked."
	case dNoGrant:
		return "Google didn't give me a lasting sign-in. Start again below."
	case dExchange:
		return "Google didn't accept the sign-in. Check the client ID and secret on Google's Clients page, then start again."
	}
	return "That didn't go through. Start again below."
}

// beginText is the owner's wording for Begin's detail.
func beginText(detail string) string {
	switch detail {
	case dRegistered:
		return "The client ID or secret has a character I can't use. Copy them again from Google's Clients page."
	case dNoAccount:
		return "I don't have your Google client yet. Fill in the steps below first."
	}
	return "Could not start the sign-in. Try again."
}

func init() {
	template.Must(tmpl.Parse(`{{define "accounts"}}{{template "head" ""}}
<h1>Accounts</h1>
{{range .}}<p><a href="/accounts/{{.ID}}">Connect {{.Name}}</a></p>{{end}}
{{template "foot"}}{{end}}`))
	template.Must(tmpl.Parse(`{{define "connect"}}{{template "head" ""}}{{$a := .Account}}
<h1>Connect {{$a.Name}}</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{if eq .Step "consent"}}
<p>Open this link on your phone and sign in to {{$a.Provider}} there:</p>
<p><a class="button" href="{{.Consent}}" target="_blank" rel="noopener noreferrer">Open {{$a.Provider}}'s page</a></p>
<p>{{$a.Provider}} warns that it hasn't verified this app. That is expected: the app is yours. Before you go past the warning, check it names the app <strong>{{$a.AppName}}</strong> and, as the developer, {{with .Email}}<strong>{{.}}</strong>{{else}}the email you gave as the developer contact{{end}}. If it names anything else, stop.</p>
<p>After you allow it, your phone shows a page that doesn't load. That is expected too. Copy that page's whole address and paste it here.</p>
<form method="post" action="/accounts/{{$a.ID}}"><input type="hidden" name="step" value="paste"><input type="hidden" name="use" value="{{.Use.ID}}">
<label>The address your phone landed on<input type="text" name="pasted" autocomplete="off" autocapitalize="off" spellcheck="false" required></label>
<button>Paste</button></form>
{{else if eq .Step "confirm"}}
<p>Connecting {{$a.Name}} to {{.Use.Name}} gives me:</p>
<ul>{{range .Use.Gets}}<li>{{.}}</li>{{end}}</ul>
<p>It never gives me:</p>
<ul>{{range $a.Never}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="/accounts/{{$a.ID}}"><input type="hidden" name="step" value="connect"><input type="hidden" name="use" value="{{.Use.ID}}"><input type="hidden" name="pasted" value="{{.Pasted}}"><button>Connect</button></form>
<p><a href="/accounts/{{$a.ID}}">Cancel</a></p>
{{else if eq .Step "done"}}
<p class="ok">{{.Done}}{{with .Use}} {{.Name}}: I can {{.Text}}.{{with .Warn}} {{.}}{{end}}{{end}}</p>
<p><a href="/home">Done</a></p>
{{else}}
<p>You register your own {{$a.Provider}} client once, by hand, on your phone or computer. Each link opens {{$a.Provider}}'s console there.</p>
<form method="post" action="/accounts/{{$a.ID}}"><input type="hidden" name="step" value="begin">
<ol>{{range $i, $s := $a.Steps}}<li>{{$s.Text}} <a href="{{$s.Link}}" target="_blank" rel="noopener noreferrer">Open</a>{{if $s.Check}}<br><label><input type="checkbox" name="check-{{$i}}" value="1" required> Done</label>{{end}}</li>{{end}}</ol>
<label>Client ID<input type="text" name="id" maxlength="512" autocomplete="off" autocapitalize="off" spellcheck="false" required></label>
<label>Client secret<input type="password" name="secret" maxlength="512" autocomplete="off" required></label>
<label>The email you gave as the developer contact<input type="text" name="email" inputmode="email" maxlength="254" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
{{template "connectuses" $a}}
<button>Next</button></form>
<h2>Already registered?</h2>
<form method="post" action="/accounts/{{$a.ID}}"><input type="hidden" name="step" value="begin"><input type="hidden" name="again" value="1">
{{template "connectuses" $a}}
<button>Sign in again</button></form>
{{end}}
<p class="muted">agentOS never asks you to sign in to {{$a.Provider}} inside it.</p>
{{template "foot"}}{{end}}`))
	template.Must(tmpl.Parse(`{{define "connectuses"}}<p>What may I do with {{.Name}}?</p>
{{range $i, $u := .Uses}}<label><input type="radio" name="use" value="{{$u.ID}}"{{if eq $i 0}} checked{{end}}> {{$u.Name}}: {{$u.Text}}.{{with $u.Warn}} <strong>{{.}}</strong>{{end}}</label><br>{{end}}{{end}}`))
}
