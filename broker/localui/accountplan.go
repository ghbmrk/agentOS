package localui

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk/accounts"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// AccountPlan is setup's account plan as the page reads it (TN-account-plan
// slice b, SPEC §12.1 step 7): agentosd checks the session and relays the
// mail clerk's items, every string the known-services table's or a fixed
// constant. ok is false when agentosd or the clerk did not answer. An
// Accounts that is also an AccountPlan serves the plan's one screen at
// /account-plan/ (AgentosdAccounts is).
type AccountPlan interface {
	Plan(ctx context.Context, session string) (p localapi.AccountPlanned, ok bool)
}

// The screen's fixed lines (DEV-8: no line carries mail's text).
const (
	// planListed is an item set up whose route the box does not have yet:
	// it is listed, and no step that cannot work is named.
	planListed = "Listed: I'll ask to connect it when a task first needs it."
	planLater  = "Later: not connected."
	// planRefused is Set up on an item whose sign-in page the table does
	// not declare: nothing is opened or recorded.
	planRefused = "I can't connect that one from here: its sign-in page isn't one I know for it."
	planFailed  = "I couldn't get the plan just now. I may still be reading who writes to you: open this page again in a minute."
)

// planReason is the owner's wording for the clerk's typed reason (clerk/run
// DReconnect, DSignInRefused, DNoSignIn); each names the step that exists
// and where, as STATUS does (clerk/run seen.go). Only reconnect is fixed
// on the Accounts page; an IMAP account is set up again on the Wi-Fi page,
// which this page cannot link to (#3226).
func planReason(reason string) string {
	switch reason {
	case "reconnect":
		return "Your mail sign-in ended, so I can't read who writes to you. Sign in again on the Accounts page, then open this page again."
	case "sign-in-refused":
		return "Your mail server refused my sign-in, so I can't read who writes to you. Set up the mail account again on my Wi-Fi page, then open this page again. If your provider uses two-step sign-in, use an app password it gives for mail apps."
	case "no-sign-in":
		return "Your mail server doesn't accept a password sign-in with these settings, so I can't read who writes to you. On my Wi-Fi page, set up the mail account again with the server settings your provider gives for mail apps, then open this page again."
	}
	return planFailed
}

// planChoices is the owner's Set up and Later per item, held by this page
// for its own lifetime, as the plan is by the clerk (nothing persisted).
type planChoices struct {
	mu sync.Mutex
	m  map[string]string // item ID: "later" or "listed"
}

func (c *planChoices) get(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[id]
}

func (c *planChoices) set(id, choice string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]string{}
	}
	c.m[id] = choice
}

// planRow is one item as the screen shows it. A card, wallet or mailbox
// item (source always) shows no power label: it is not an account the
// owner signs in to here (#3197 item 3).
type planRow struct {
	localapi.AccountPlanItem
	ShowLabel bool
	State     string // "", "later" or "listed"
}

type planView struct {
	Rows        []planRow
	Err, Reason string
	Reconnect   bool // the Accounts button: only reconnect is fixed there
	Listed      string
	Later       string
}

// accountPlanPage serves /account-plan/ behind sign-in (CH-7): GET shows
// the plan, and Set up and Later are form posts (CH-9). Set up on an item
// the box has a route for (a Connect declaration of the same ID, today
// Gmail's oauth) goes to that sign-in only if the table declares its
// consent host for the item (accounts.Entry.SignInAllowed); the Connect
// page then links consent to that host alone. Set up on an item with no
// route lists it; Later leaves it unconnected.
func (s *Server) accountPlanPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	planner := s.cfg.Accounts.(AccountPlan)
	ctx := r.Context()
	p, ok := planner.Plan(ctx, cookieToken(r))
	v := planView{Listed: planListed, Later: planLater}
	switch {
	case !ok:
		v.Err = planFailed
	case p.Reason != "":
		v.Reason, v.Reconnect = planReason(p.Reason), p.Reason == "reconnect"
	}
	if r.Method == http.MethodPost && ok && p.Reason == "" {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		var it *localapi.AccountPlanItem
		for i := range p.Items {
			if p.Items[i].ID == r.PostForm.Get("id") {
				it = &p.Items[i]
			}
		}
		choice := r.PostForm.Get("choice")
		if it == nil || choice != "setup" && choice != "later" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		switch {
		case it.Connected:
		case choice == "later":
			s.plan.set(it.ID, "later")
		default:
			link, route := s.planSetUpLink(it.ID)
			switch {
			case link != "":
				http.Redirect(w, r, link, http.StatusSeeOther)
				return
			case route:
				v.Err = planRefused
			default:
				s.plan.set(it.ID, "listed")
			}
		}
	}
	if v.Reason == "" && ok {
		for _, it := range p.Items {
			v.Rows = append(v.Rows, planRow{AccountPlanItem: it, ShowLabel: it.Source != string(accounts.Always), State: s.plan.get(it.ID)})
		}
	}
	s.render(w, "accountplan", v)
}

// planSetUpLink is the page Set up on item id goes to: its Connect step, when
// the box declares one for id and the known-services table allows a
// sign-in at its consent host over https. route reports whether the table
// gives id a route the box has a Connect step for, so a refused link is
// told apart from an item with no route yet.
func (s *Server) planSetUpLink(id string) (link string, route bool) {
	t, err := accounts.Known()
	if err != nil {
		return "", false
	}
	e, ok := t.Entry(id)
	if !ok || e.Route != "oauth" {
		return "", false
	}
	for _, d := range s.cfg.Connect {
		if d.ID != id {
			continue
		}
		if !e.SignInAllowed(&url.URL{Scheme: "https", Host: d.ConsentHost}) {
			return "", true
		}
		return "/accounts/" + d.ID, true
	}
	return "", false
}

func init() {
	template.Must(tmpl.Parse(`{{define "accountplan"}}{{template "head" ""}}{{$v := .}}
<h1>Your accounts</h1>
<p>Payments first, then a mailbox of my own, then the accounts your mail shows you use. Set up each one now, or later.</p>
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{with .Reason}}<p class="err">{{.}}</p>{{if $v.Reconnect}}<p><a class="button" href="/accounts/">Accounts</a></p>{{end}}{{end}}
{{range .Rows}}<div class="card">
<p><b>{{.Name}}</b>{{if .Preselected}} <span class="muted">Suggested</span>{{end}}</p>
{{if .ShowLabel}}<p class="muted">{{.Label}}</p>{{end}}{{with .Advice}}<p>{{.}}</p>{{end}}
{{if .Connected}}<p class="ok">Connected.</p>
{{else if eq .State "listed"}}<p>{{$v.Listed}}</p>
{{else}}{{if eq .State "later"}}<p class="muted">{{$v.Later}}</p>{{end}}
<form method="post" action="/account-plan/"><input type="hidden" name="id" value="{{.ID}}"><button name="choice" value="setup">Set up</button> <button class="plain" name="choice" value="later">Later</button></form>
{{end}}</div>
{{end}}
<p><a href="/home">Done</a></p>
{{template "foot"}}{{end}}`))
}
