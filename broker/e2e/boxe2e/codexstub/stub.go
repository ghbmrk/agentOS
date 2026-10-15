// Package codexstub stands in for the Codex plan's provider in the
// in-image end-to-end run (#1701): the device-code sign-in on the auth host
// and the model endpoints on the run host, as egress.Codex declares them.
//
// It is test-only. The shipped agentos-egress never imports it: only a
// build with the agentos_e2e tag does, and that build dials the stub's
// unix socket for the Codex hosts in place of the provider (Transport).
// Every token it issues is a synthetic canary minted at random.
package codexstub

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/egress"
)

// Socket is where the box-e2e driver serves the stub inside the image and
// where the agentos_e2e egress build dials it.
const Socket = "/run/agentos-e2e-stub/codex.sock"

// Answer is the text every responses call answers with: the guest-task
// step looks for it on the owner's page.
const Answer = "agentos-e2e-canary-answer"

// Canary is the prefix of every token the stub mints, so a log or page
// that shows one can be found by grep.
const Canary = "agentos-e2e-canary-"

// Stub is one in-memory provider: one pending device code at a time, one
// signed-in token set.
type Stub struct {
	route    egress.PlanRoute
	redirect string // the auth host's own callback, as the route rewrites it
	mu       sync.Mutex
	device   string // device_auth_id
	user     string // user_code
	ok       bool   // the owner approved user
	code     string // authorization_code
	verify   string // code_verifier
	access   string
	refresh  string
	account  string
	hits     map[string]int
	refused  int
}

// New returns a stub that serves every endpoint egress.Codex declares. A
// declared endpoint the stub cannot answer panics here, so a change to the
// route shows up in the stub's own tests.
func New() *Stub {
	s := &Stub{route: egress.Codex(), hits: map[string]int{}, account: Canary + "acct-" + rnd()}
	for _, ep := range s.route.Endpoints {
		if _, ok := handlers[ep.Name]; !ok {
			panic("codexstub: no handler for endpoint " + ep.Name)
		}
		if ep.Kind == egress.KindCode {
			s.redirect = "https://" + ep.Host + s.route.RedirectPath
		}
	}
	return s
}

// Hosts are the provider hosts the stub answers for.
func (s *Stub) Hosts() []string {
	return hosts(s.route)
}

func hosts(r egress.PlanRoute) []string {
	seen := map[string]bool{}
	var out []string
	for _, ep := range r.Endpoints {
		if !seen[ep.Host] {
			seen[ep.Host] = true
			out = append(out, ep.Host)
		}
	}
	return out
}

// Approve is the owner entering code on the provider's page.
func (s *Stub) Approve(code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == "" || code != s.user {
		return false
	}
	s.ok = true
	return true
}

// Hits counts the calls each endpoint answered.
func (s *Stub) Hits() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for k, v := range s.hits {
		out[k] = v
	}
	return out
}

// Refused counts calls the stub turned away: an unknown path, a wrong
// token (a placeholder that reached the provider), or a bad exchange.
func (s *Stub) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

// Tokens returns the token set the stub issued, so a test can look for it
// where it must not be.
func (s *Stub) Tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, v := range []string{s.access, s.refresh, s.code, s.verify} {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

type handler func(s *Stub, w http.ResponseWriter, r *http.Request, body []byte) bool

var handlers = map[string]handler{
	"usercode":    (*Stub).usercode,
	"devicetoken": (*Stub).devicetoken,
	"code":        (*Stub).exchange,
	"refresh":     (*Stub).refreshToken,
	"models":      (*Stub).models,
	"responses":   (*Stub).responses,
}

// ServeHTTP answers a request for a declared endpoint by host, method and
// path; refresh and code share a path and are told apart by their body.
func (s *Stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	form := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	for _, ep := range s.route.Endpoints {
		if ep.Host != r.Host || ep.Method != r.Method || ep.Path != r.URL.Path {
			continue
		}
		if ep.Kind == egress.KindCode && !form || ep.Kind == egress.KindRefresh && form {
			continue
		}
		if !handlers[ep.Name](s, w, r, body) {
			s.refuse(w, http.StatusUnauthorized)
			return
		}
		s.mu.Lock()
		s.hits[ep.Name]++
		s.mu.Unlock()
		return
	}
	s.refuse(w, http.StatusNotFound)
}

func (s *Stub) refuse(w http.ResponseWriter, code int) {
	s.mu.Lock()
	s.refused++
	s.mu.Unlock()
	http.Error(w, http.StatusText(code), code)
}

func writeJSON(w http.ResponseWriter, v any) bool {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
	return true
}

func (s *Stub) usercode(w http.ResponseWriter, _ *http.Request, body []byte) bool {
	var in struct {
		ClientID string `json:"client_id"`
	}
	if json.Unmarshal(body, &in) != nil || in.ClientID == "" {
		return false
	}
	s.mu.Lock()
	s.device, s.user, s.ok = Canary+"device-"+rnd(), userCode(), false
	out := map[string]string{"device_auth_id": s.device, "user_code": s.user, "interval": "1"}
	s.mu.Unlock()
	return writeJSON(w, out)
}

// devicetoken answers 403 until the owner approves, as the provider does;
// the CLI keeps polling on 403.
func (s *Stub) devicetoken(w http.ResponseWriter, _ *http.Request, body []byte) bool {
	var in struct {
		Device string `json:"device_auth_id"`
		User   string `json:"user_code"`
	}
	json.Unmarshal(body, &in)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.device == "" || in.Device != s.device || in.User != s.user {
		return false
	}
	if !s.ok {
		w.WriteHeader(http.StatusForbidden)
		return true
	}
	s.code, s.verify = Canary+"code-"+rnd(), Canary+"verifier-"+rnd()
	s.device, s.user, s.ok = "", "", false
	return writeJSON(w, map[string]string{
		"authorization_code": s.code, "code_challenge": "challenge-" + rnd(), "code_verifier": s.verify,
	})
}

// exchange is the code exchange; redirect_uri must be the auth host's own
// callback, which the egress route rewrites the forwarder's into.
func (s *Stub) exchange(w http.ResponseWriter, _ *http.Request, body []byte) bool {
	f, err := url.ParseQuery(string(body))
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || s.code == "" || f.Get("grant_type") != "authorization_code" ||
		f.Get("code") != s.code || f.Get("code_verifier") != s.verify || f.Get("redirect_uri") != s.redirect {
		return false
	}
	s.code, s.verify = "", ""
	return writeJSON(w, s.mint())
}

func (s *Stub) refreshToken(w http.ResponseWriter, _ *http.Request, body []byte) bool {
	var in struct {
		Grant   string `json:"grant_type"`
		Refresh string `json:"refresh_token"`
	}
	json.Unmarshal(body, &in)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refresh == "" || in.Grant != "refresh_token" || in.Refresh != s.refresh {
		return false
	}
	return writeJSON(w, s.mint())
}

// mint issues a new token set and returns it; s.mu is held.
func (s *Stub) mint() map[string]any {
	s.access, s.refresh = Canary+"access-"+rnd(), Canary+"refresh-"+rnd()
	return map[string]any{
		"access_token": s.access, "refresh_token": s.refresh, "id_token": s.idToken(),
		"expires_in": 3600, "token_type": "Bearer",
	}
}

// idToken carries the account claim the route reads, unsigned like the
// placeholder the worker holds.
func (s *Stub) idToken() string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
		enc(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": s.account}}) +
		"." + rnd()
}

// bearer reports whether r carries the access token the stub issued last.
func (s *Stub) bearer(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.access != "" && r.Header.Get("Authorization") == "Bearer "+s.access
}

func (s *Stub) models(w http.ResponseWriter, r *http.Request, _ []byte) bool {
	if !s.bearer(r) {
		return false
	}
	return writeJSON(w, map[string]any{"models": []any{}})
}

// responses streams one assistant message whose text is Answer.
func (s *Stub) responses(w http.ResponseWriter, r *http.Request, body []byte) bool {
	var in struct {
		Stream bool `json:"stream"`
	}
	if !s.bearer(r) || json.Unmarshal(body, &in) != nil || !in.Stream {
		return false
	}
	id := "resp_" + rnd()
	w.Header().Set("Content-Type", "text/event-stream")
	for _, ev := range []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": id}},
		{"type": "response.output_item.done", "item": map[string]any{
			"type": "message", "role": "assistant", "id": "msg_" + rnd(),
			"content": []any{map[string]string{"type": "output_text", "text": Answer}},
		}},
		{"type": "response.completed", "response": map[string]any{"id": id}},
	} {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev["type"], b)
	}
	return true
}

func rnd() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("codexstub: no randomness")
	}
	return hex.EncodeToString(b)
}

// userCode is a code in the shape the route accepts ([A-Z0-9-]{4,16}).
func userCode() string {
	const abc = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = abc[int(b[i])%len(abc)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}
