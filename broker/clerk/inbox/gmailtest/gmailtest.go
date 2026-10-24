// Package gmailtest is a local fake of the Gmail API and Google's token
// endpoint for the mail clerk's tests and the inbox slice (A21, A22): one
// account with messages, system and user labels, a trash, history and the
// settings the clerk reads. Under the box's grant it refuses what the real
// API refuses there (A22 Fences): permanent deletion (messages.delete,
// batchDelete) and every settings change answer 403, as a gmail.modify token
// gets, and every request it refuses is recorded. The contract test runs the
// same cases against a real test account. Synthetic data only; it listens on
// loopback and holds no real account.
package gmailtest

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// Canary values: a refresh grant and the access tokens the fake issues.
const (
	Refresh = "canary-gmailtest-refresh"
	Client  = "canary-gmailtest-client"
	Secret  = "canary-gmailtest-client-secret"
	User    = "owner@gmail.test"
)

// Grant is the sealed refresh grant the fake's token endpoint accepts.
func Grant() []byte {
	b, _ := json.Marshal(map[string]string{"refresh_token": Refresh, "client_id": Client, "client_secret": Secret})
	return b
}

// Server is a running fake.
type Server struct {
	srv *httptest.Server

	mu       sync.Mutex
	msgs     map[string]*Message
	order    []string // message ids, oldest first
	labels   []Label
	next     int
	history  int
	changes  []int // history ids of inbox changes
	tokens   int
	token    string
	refused  []string
	calls    []string
	lie      bool
	echo     bool
	fail     map[string]int
	filters  int
	forwards []string
	autoFwd  string
	grantOK  bool
	endless  int    // read listings left that name a next page, whatever the last
	otherID  bool   // metadata answers name another message's id
	user     string // the address the profile names; "" is User
	// Sign-in (D-150): the codes consent issued, each with its PKCE
	// challenge, redirect and scope; the scope the next consent grants
	// beyond the asked one; and the tokens revoked.
	codes   map[string]consent
	wider   string
	revoked []string
	revokes int // revocation requests, whatever their answer
}

type consent struct{ challenge, redirect, scope string }

// Message is one stored message.
type Message struct {
	ID     string
	Raw    []byte
	Labels []string
	// Arrived is the internalDate, in milliseconds: a second apart from
	// 2026-10-01, in the order delivered.
	Arrived int64
}

// arrivedBase is the first delivered message's internalDate.
const arrivedBase = int64(1790812800000) // 2026-10-01T00:00:00Z

// Label is one label of the account.
type Label struct {
	ID, Name, Type string
}

var system = []string{"INBOX", "SPAM", "TRASH", "UNREAD", "STARRED", "IMPORTANT", "SENT", "DRAFT", "CATEGORY_PROMOTIONS"}

// New starts a fake; Close stops it.
func New() *Server {
	s := &Server{msgs: map[string]*Message{}, history: 1000, fail: map[string]int{}, grantOK: true, codes: map[string]consent{}}
	for _, id := range system {
		s.labels = append(s.labels, Label{ID: id, Name: id, Type: "system"})
	}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// Close stops the fake.
func (s *Server) Close() { s.srv.Close() }

// Host is the name the fake answers to under its certificate.
const Host = "example.com"

func (s *Server) origin() string {
	return "https://" + Host + ":" + s.srv.URL[strings.LastIndex(s.srv.URL, ":")+1:]
}

// Base is the fake's Gmail root, in GmailBase's place.
func (s *Server) Base() string { return s.origin() + "/gmail/v1/users/me" }

// Token is the fake's token endpoint, in GmailToken's place.
func (s *Server) Token() string { return s.origin() + "/token" }

// Consent is the fake's consent page and Revoke its revocation endpoint.
func (s *Server) Consent() string { return s.origin() + "/consent" }
func (s *Server) Revoke() string  { return s.origin() + "/revoke" }

// Approve is the owner approving the consent address the clerk gave, on
// their phone: it checks the request is Google's installed-app shape with
// PKCE S256 and returns the loopback address the browser lands on, with a
// code and the state. ok false is a consent the fake would refuse to show.
func (s *Server) Approve(address string) (landing string, ok bool) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != s.Consent() {
		return "", false
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != Client || q.Get("code_challenge_method") != "S256" ||
		len(q.Get("code_challenge")) != 43 || q.Get("state") == "" || q.Get("access_type") != "offline" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	scope := q.Get("scope")
	if s.wider != "" {
		scope += " " + s.wider
	}
	code := "canary-gmailtest-code-" + strconv.Itoa(len(s.codes)+1)
	s.codes[code] = consent{q.Get("code_challenge"), q.Get("redirect_uri"), scope}
	return q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {code}, "scope": {scope}}.Encode(), true
}

// Deny is the owner pressing Cancel on the consent page.
func Deny(address string) string {
	u, _ := url.Parse(address)
	q := u.Query()
	return q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "error": {"access_denied"}}.Encode()
}

// Wider makes every later consent grant scope too, as Google's
// include_granted_scopes does with an earlier grant.
func (s *Server) Wider(scope string) { s.mu.Lock(); s.wider = scope; s.mu.Unlock() }

// Revoked lists the tokens revoked, in order.
func (s *Server) Revoked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.revoked)
}

// Revokes counts the revocation requests, including those answered 400:
// every grant the fake issues shares Refresh, so a second grant's
// revocation shows here and not in Revoked.
func (s *Server) Revokes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokes
}

// Roots trusts the fake's certificate.
func (s *Server) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.srv.Certificate())
	return p
}

type resolver netip.Addr

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(r)}, nil
}

// Guard is a home-network policy under which Host stands for a public
// address and every dial reaches the fake.
func (s *Server) Guard() *netguard.Policy {
	addr := s.srv.Listener.Addr().String()
	return netguard.New(netguard.Config{Resolver: resolver(netip.MustParseAddr("8.8.8.8")),
		Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}})
}

// Deliver adds a message to the inbox, unread, and returns its id.
func (s *Server) Deliver(raw []byte, labels ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := fmt.Sprintf("%016x", 0x18f0000000000000+s.next)
	if len(labels) == 0 {
		labels = []string{"INBOX", "UNREAD"}
	}
	s.msgs[id] = &Message{ID: id, Raw: slices.Clone(raw), Labels: slices.Clone(labels), Arrived: arrivedBase + int64(s.next)*1000}
	s.order = append(s.order, id)
	s.change()
	return id
}

// Open is the owner reading a message in their own mail app: its UNREAD
// label goes.
func (s *Server) Open(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.msgs[id]; m != nil {
		m.Labels = slices.DeleteFunc(m.Labels, func(l string) bool { return l == "UNREAD" })
		s.change()
	}
}

// Erase is the owner deleting a message for good in their own mail app.
func (s *Server) Erase(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.msgs, id)
	s.change()
}

// Get is a stored message, as it is now.
func (s *Server) Get(id string) (Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.msgs[id]
	if !ok {
		return Message{}, false
	}
	return Message{ID: m.ID, Raw: slices.Clone(m.Raw), Labels: slices.Clone(m.Labels)}, true
}

// LabelName is the name of label id, "" when there is none.
func (s *Server) LabelName(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.labels {
		if l.ID == id {
			return l.Name
		}
	}
	return ""
}

// Refused lists every request the fake refused, as "METHOD path".
func (s *Server) Refused() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.refused)
}

// Calls lists every Gmail request the fake answered, as "METHOD path".
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// Tokens is how many access tokens the token endpoint issued.
func (s *Server) Tokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens
}

// Endless makes the next n listings of read mail name a next page of the
// same ids, as an API that never ends its listing would.
func (s *Server) Endless(n int) { s.mu.Lock(); s.endless = n; s.mu.Unlock() }

// As makes the profile name address, as another Google account signed in
// on the consent page would.
func (s *Server) As(address string) { s.mu.Lock(); s.user = address; s.mu.Unlock() }

// OtherID makes each metadata answer name an id other than the one asked.
func (s *Server) OtherID(on bool) { s.mu.Lock(); s.otherID = on; s.mu.Unlock() }

// Lie makes a modify or trash answer 200 and change nothing, as a lost
// write would.
func (s *Server) Lie(on bool) { s.mu.Lock(); s.lie = on; s.mu.Unlock() }

// Echo makes every answer, and every raw message, carry the bearer token the
// request came with, as a hostile or broken API might.
func (s *Server) Echo(on bool) { s.mu.Lock(); s.echo = on; s.mu.Unlock() }

// Fail makes requests whose path ends in suffix answer status.
func (s *Server) Fail(suffix string, status int) { s.mu.Lock(); s.fail[suffix] = status; s.mu.Unlock() }

// RefuseGrant makes the token endpoint answer invalid_grant.
func (s *Server) RefuseGrant() { s.mu.Lock(); s.grantOK = false; s.mu.Unlock() }

// SetDoors sets what the settings reads show.
func (s *Server) SetDoors(filters int, forwards []string, autoFwd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filters, s.forwards, s.autoFwd = filters, slices.Clone(forwards), autoFwd
}

// AddLabel adds a label to the account, whatever its id.
func (s *Server) AddLabel(l Label) { s.mu.Lock(); s.labels = append(s.labels, l); s.mu.Unlock() }

// Attempt makes a request outside the clerk's declaration under the access
// token the fake last issued, as the box's own grant, and returns its status
// (0 when nothing answered).
func (s *Server) Attempt(method, path, body string) int {
	s.mu.Lock()
	tok := s.token
	s.mu.Unlock()
	req, err := http.NewRequest(method, s.srv.URL+"/gmail/v1/users/me"+path, strings.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.srv.Client().Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Expire makes the next request with the current access token answer 401.
func (s *Server) Expire() { s.mu.Lock(); s.token = ""; s.mu.Unlock() }

func (s *Server) change() {
	s.history++
	s.changes = append(s.changes, s.history)
}

var (
	msgPath    = regexp.MustCompile(`^/gmail/v1/users/me/messages/([0-9A-Za-z_-]+)$`)
	actionPath = regexp.MustCompile(`^/gmail/v1/users/me/messages/([0-9A-Za-z_-]+)/(modify|trash|untrash)$`)
)

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/token" {
		s.serveToken(w, r)
		return
	}
	if r.URL.Path == "/revoke" {
		s.serveRevoke(w, r)
		return
	}
	line := r.Method + " " + r.URL.Path
	auth := r.Header.Get("Authorization")
	if s.token == "" || auth != "Bearer "+s.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	for suffix, status := range s.fail {
		if strings.HasSuffix(r.URL.Path, suffix) {
			w.WriteHeader(status)
			return
		}
	}
	reply := func(v any) {
		b, _ := json.Marshal(v)
		if s.echo {
			b = []byte(strings.Replace(string(b), `{`, `{"echo":"`+s.token+`",`, 1))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
	refuse := func(status int) {
		s.refused = append(s.refused, line)
		w.WriteHeader(status)
		w.Write([]byte(`{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Request had insufficient authentication scopes."}}`))
	}
	p := r.URL.Path
	q := r.URL.Query()
	// Permanent deletion and every settings change: the box's grant
	// (gmail.modify) does not reach them.
	if r.Method == "DELETE" || strings.HasSuffix(p, "/batchDelete") ||
		strings.Contains(p, "/settings") && r.Method != "GET" {
		refuse(http.StatusForbidden)
		return
	}
	s.calls = append(s.calls, line)
	switch {
	case r.Method == "GET" && p == "/gmail/v1/users/me/messages":
		if q.Has("q") && q.Get("q") != "-is:unread" {
			w.WriteHeader(http.StatusBadRequest) // a query the fake does not know
			return
		}
		s.list(q, reply)
	case r.Method == "GET" && msgPath.MatchString(p):
		m := s.msgs[msgPath.FindStringSubmatch(p)[1]]
		if m == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		out := map[string]any{"id": m.ID, "threadId": m.ID, "labelIds": m.Labels, "historyId": strconv.Itoa(s.history),
			"internalDate": strconv.FormatInt(m.Arrived, 10)}
		switch q.Get("format") {
		case "raw":
			raw := m.Raw
			if s.echo {
				raw = append(slices.Clone(raw), []byte("\r\nX-Echo: "+s.token+"\r\n")...)
			}
			out["raw"] = base64.URLEncoding.EncodeToString(raw)
		case "metadata", "full":
			out["payload"] = map[string]any{"headers": headers(m.Raw, q["metadataHeaders"])}
			if s.otherID {
				out["id"] = m.ID + "0"
			}
		}
		reply(out)
	case r.Method == "POST" && actionPath.MatchString(p):
		sub := actionPath.FindStringSubmatch(p)
		m := s.msgs[sub[1]]
		if m == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !s.lie {
			switch sub[2] {
			case "modify":
				var body struct {
					Add    []string `json:"addLabelIds"`
					Remove []string `json:"removeLabelIds"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				for _, l := range body.Add {
					if !s.hasLabel(l) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
				}
				for _, l := range body.Add {
					if !slices.Contains(m.Labels, l) {
						m.Labels = append(m.Labels, l)
					}
				}
				m.Labels = slices.DeleteFunc(m.Labels, func(l string) bool { return slices.Contains(body.Remove, l) })
			case "trash":
				m.Labels = slices.DeleteFunc(m.Labels, func(l string) bool { return l == "INBOX" || l == "SPAM" })
				if !slices.Contains(m.Labels, "TRASH") {
					m.Labels = append(m.Labels, "TRASH")
				}
			case "untrash":
				m.Labels = slices.DeleteFunc(m.Labels, func(l string) bool { return l == "TRASH" })
				if !slices.Contains(m.Labels, "INBOX") {
					m.Labels = append(m.Labels, "INBOX")
				}
			}
			s.change()
		}
		reply(map[string]any{"id": m.ID, "labelIds": m.Labels})
	case r.Method == "GET" && p == "/gmail/v1/users/me/labels":
		var ls []map[string]string
		for _, l := range s.labels {
			ls = append(ls, map[string]string{"id": l.ID, "name": l.Name, "type": l.Type})
		}
		reply(map[string]any{"labels": ls})
	case r.Method == "POST" && p == "/gmail/v1/users/me/labels":
		var body struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, l := range s.labels {
			if strings.EqualFold(l.Name, body.Name) {
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
		l := Label{ID: "Label_" + strconv.Itoa(len(s.labels)+1), Name: body.Name, Type: "user"}
		s.labels = append(s.labels, l)
		reply(map[string]string{"id": l.ID, "name": l.Name, "type": l.Type})
	case r.Method == "POST" && p == "/gmail/v1/users/me/messages/send":
		var body struct {
			Raw string `json:"raw"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err := base64.URLEncoding.DecodeString(body.Raw)
		if err != nil {
			if raw, err = base64.RawURLEncoding.DecodeString(body.Raw); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		s.next++
		id := fmt.Sprintf("%016x", 0x18f0000000000000+s.next)
		s.msgs[id] = &Message{ID: id, Raw: raw, Labels: []string{"SENT"}}
		s.order = append(s.order, id)
		reply(map[string]any{"id": id, "labelIds": []string{"SENT"}})
	case r.Method == "GET" && p == "/gmail/v1/users/me/history":
		start, err := strconv.Atoi(q.Get("startHistoryId"))
		if err != nil || start < 1000 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var hs []map[string]string
		for _, h := range s.changes {
			if h > start {
				hs = append(hs, map[string]string{"id": strconv.Itoa(h)})
			}
		}
		reply(map[string]any{"history": hs, "historyId": strconv.Itoa(s.history)})
	case r.Method == "GET" && p == "/gmail/v1/users/me/settings/filters":
		fs := []map[string]string{}
		for i := range s.filters {
			fs = append(fs, map[string]string{"id": "filter-" + strconv.Itoa(i)})
		}
		reply(map[string]any{"filter": fs})
	case r.Method == "GET" && p == "/gmail/v1/users/me/settings/forwardingAddresses":
		var as []map[string]string
		for _, a := range s.forwards {
			as = append(as, map[string]string{"forwardingEmail": a, "verificationStatus": "accepted"})
		}
		reply(map[string]any{"forwardingAddresses": as})
	case r.Method == "GET" && p == "/gmail/v1/users/me/settings/autoForwarding":
		reply(map[string]any{"enabled": s.autoFwd != "", "emailAddress": s.autoFwd, "disposition": "leaveInInbox"})
	case r.Method == "GET" && p == "/gmail/v1/users/me/profile":
		reply(map[string]any{"emailAddress": cmp.Or(s.user, User), "messagesTotal": len(s.msgs), "historyId": strconv.Itoa(s.history)})
	default:
		s.calls = s.calls[:len(s.calls)-1]
		refuse(http.StatusNotFound)
	}
}

func (s *Server) hasLabel(id string) bool {
	for _, l := range s.labels {
		if l.ID == id {
			return true
		}
	}
	return false
}

// list answers messages.list for labelIds, newest first, in pages. The one
// query it knows is read mail (-is:unread); spam and trash are listed only
// with includeSpamTrash, as Gmail lists them.
func (s *Server) list(q url.Values, reply func(any)) {
	label := q.Get("labelIds")
	read := q.Get("q") == "-is:unread"
	all := q.Get("includeSpamTrash") == "true"
	max, _ := strconv.Atoi(q.Get("maxResults"))
	if max <= 0 || max > 500 {
		max = 100
	}
	start, _ := strconv.Atoi(q.Get("pageToken"))
	var ids []string
	for i := len(s.order) - 1; i >= 0; i-- {
		m := s.msgs[s.order[i]]
		switch {
		case m == nil, label != "" && !slices.Contains(m.Labels, label):
			continue
		case !all && (slices.Contains(m.Labels, "SPAM") || slices.Contains(m.Labels, "TRASH")):
			continue
		case read && slices.Contains(m.Labels, "UNREAD"):
			continue
		}
		ids = append(ids, m.ID)
	}
	var page []map[string]string
	for i := start; i < len(ids) && i < start+max; i++ {
		page = append(page, map[string]string{"id": ids[i], "threadId": ids[i]})
	}
	out := map[string]any{"messages": page, "resultSizeEstimate": len(ids)}
	if start+max < len(ids) {
		out["nextPageToken"] = strconv.Itoa(start + max)
	}
	if read && s.endless > 0 {
		s.endless--
		out["nextPageToken"] = strconv.Itoa(start)
	}
	reply(out)
}

// headers is a message's header fields, those named in only when given.
func headers(raw []byte, only []string) []map[string]string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	head, _, _ := strings.Cut(text, "\n\n")
	var out []map[string]string
	for _, line := range strings.Split(head, "\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(out) > 0 {
			out[len(out)-1]["value"] += " " + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if len(only) > 0 && !slices.ContainsFunc(only, func(o string) bool { return strings.EqualFold(o, k) }) {
			continue
		}
		out = append(out, map[string]string{"name": k, "value": strings.TrimSpace(v)})
	}
	return out
}

// serveCode redeems a consent's code once (RFC 6749 section 4.1.3), checking
// the PKCE verifier against its challenge (RFC 7636 section 4.6), the
// redirect and the client.
func (s *Server) serveCode(w http.ResponseWriter, r *http.Request) {
	c, ok := s.codes[r.Form.Get("code")]
	delete(s.codes, r.Form.Get("code"))
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.Form.Get("redirect_uri") != c.redirect ||
		r.Form.Get("client_id") != Client || r.Form.Get("client_secret") != Secret {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	s.tokens++
	s.token = "canary-gmailtest-access-" + strconv.Itoa(s.tokens)
	s.grantOK = true
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"access_token": s.token, "expires_in": 3599, "token_type": "Bearer",
		"refresh_token": Refresh, "scope": c.scope})
}

// serveRevoke revokes a token (RFC 7009): the refresh token kills the grant
// and its access token; an unknown token answers 400, as Google's does.
func (s *Server) serveRevoke(w http.ResponseWriter, r *http.Request) {
	s.revokes++
	t := ""
	if r.ParseForm() == nil {
		t = r.Form.Get("token")
	}
	switch {
	case t == Refresh && s.grantOK:
		s.grantOK, s.token = false, ""
	case t != "" && t == s.token:
		s.token = ""
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_token"}`))
		return
	}
	s.revoked = append(s.revoked, t)
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() == nil && r.Form.Get("grant_type") == "authorization_code" {
		s.serveCode(w, r)
		return
	}
	if r.ParseForm() != nil || r.Form.Get("grant_type") != "refresh_token" || !s.grantOK ||
		r.Form.Get("refresh_token") != Refresh || r.Form.Get("client_id") != Client || r.Form.Get("client_secret") != Secret {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	s.tokens++
	s.token = "canary-gmailtest-access-" + strconv.Itoa(s.tokens)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"access_token": s.token, "expires_in": 3599, "token_type": "Bearer"})
}
