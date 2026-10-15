package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// A plan worker's route (#1014, CRED-5, A14): the one listener a guest
// agent CLI signed in to an owner's plan reaches, through the in-image
// forwarder, at a loopback origin it was configured with. The route
// carries the CLI's declared endpoints only, puts the real login in at
// the broker, and hands the worker placeholders. Everything else fails by
// absence and is journaled without payload.

// EndpointKind is what a declared plan endpoint carries.
type EndpointKind string

const (
	// KindResponses is the model call: a bearer-authenticated JSON body
	// whose tools are held to the route's client-side types.
	KindResponses EndpointKind = "responses"
	// KindRead is a bearer-authenticated GET with no body.
	KindRead EndpointKind = "read"
	// KindRefresh is the token refresh: the refresh token travels in the
	// JSON body, and the response is a credential exchange.
	KindRefresh EndpointKind = "refresh"
	// KindDevice is a device-auth step of sign-in: no credential either way
	// the broker holds.
	KindDevice EndpointKind = "device"
	// KindCode is sign-in's code exchange: a form body whose redirect_uri
	// the route rewrites, and whose response is the first login.
	KindCode EndpointKind = "code"
)

// PlanEndpoint is one declared request. SignIn endpoints are reachable by
// a sign-in worker only; the rest by a run worker only.
type PlanEndpoint struct {
	Name   string
	Host   string
	Method string
	Path   string
	Kind   EndpointKind
	// Query names the query keys the endpoint takes, each at most once.
	Query  []string
	SignIn bool
}

// PlanRoute declares one provider's plan route.
type PlanRoute struct {
	Provider string
	// Origin is the loopback origin the CLI is configured with (the
	// forwarder in the image); it names the issuer the CLI signs in at.
	Origin string
	// AuthHost is the provider's own sign-in host.
	AuthHost string
	// RedirectPath is the device-flow callback the CLI derives from its
	// issuer; the route rewrites Origin+RedirectPath to the auth host's.
	RedirectPath string
	// DevicePage is the verification page the CLI prints under its issuer.
	DevicePage string
	Endpoints  []PlanEndpoint
	// ToolTypes are the tool types a model call may declare: client-side
	// ones only, so the provider never runs a tool for the worker.
	ToolTypes []string
	// BodyKeys, InputTypes and ContentTypes are the shape a model call may
	// take: its top-level keys, its input items' types, and the types of a
	// message's content parts. Anything else is refused, not forwarded.
	BodyKeys     []string
	InputTypes   []string
	ContentTypes []string
	// Token is the shape of a refresh's or code exchange's response.
	Token ResponseRule
	// RequestHeaders a run worker may send; SignInHeaders a sign-in
	// worker. Authorization is never on either: the route writes it.
	RequestHeaders []string
	SignInHeaders  []string
	// ResponseHeaders and ResponsePrefixes are returned to the worker,
	// redacted.
	ResponseHeaders  []string
	ResponsePrefixes []string
}

// clientToolTypes are the only tool types any plan route may allow: the
// CLI runs these itself. A hosted type has the provider act for the worker.
var clientToolTypes = map[string]bool{"namespace": true, "function": true, "custom": true}

// relayDeniedKeys are body keys no plan route may allow, as on every relay
// (E10): background runs, provider-held prompts and conversations, and
// server-side tool sources.
var relayDeniedKeys = map[string]bool{
	"background": true, "prompt": true, "conversation": true, "previous_response_id": true,
	"web_search_options": true, "mcp_servers": true, "container": true,
}

// Codex is the Codex CLI's plan route, as measured on CLI 0.162.1 (#809).
func Codex() PlanRoute {
	const run, auth = "chatgpt.com", "auth.openai.com"
	return PlanRoute{
		Provider:     "codex",
		Origin:       "http://127.0.0.1:18432",
		AuthHost:     auth,
		RedirectPath: "/deviceauth/callback",
		DevicePage:   "/codex/device",
		Endpoints: []PlanEndpoint{
			{Name: "responses", Host: run, Method: "POST", Path: "/backend-api/codex/responses", Kind: KindResponses},
			{Name: "models", Host: run, Method: "GET", Path: "/backend-api/codex/models", Kind: KindRead, Query: []string{"client_version"}},
			{Name: "refresh", Host: auth, Method: "POST", Path: "/oauth/token", Kind: KindRefresh},
			{Name: "usercode", Host: auth, Method: "POST", Path: "/api/accounts/deviceauth/usercode", Kind: KindDevice, SignIn: true},
			{Name: "devicetoken", Host: auth, Method: "POST", Path: "/api/accounts/deviceauth/token", Kind: KindDevice, SignIn: true},
			{Name: "code", Host: auth, Method: "POST", Path: "/oauth/token", Kind: KindCode, SignIn: true},
		},
		ToolTypes: []string{"namespace", "function", "custom"},
		// The CLI's request: #809 saw model, input, tool_choice, include
		// and stream; the rest are the fields the CLI's request type sets.
		BodyKeys: []string{
			"model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
			"reasoning", "store", "stream", "include", "prompt_cache_key", "text",
		},
		InputTypes: []string{
			"message", "reasoning", "function_call", "function_call_output",
			"custom_tool_call", "custom_tool_call_output", "additional_tools",
		},
		ContentTypes: []string{"input_text", "output_text", "input_image"},
		Token: ResponseRule{Fields: []Field{
			{Name: "access_token", Kind: FieldCredential},
			{Name: "refresh_token", Kind: FieldCredential, Optional: true},
			{Name: "id_token", Kind: FieldCredential, Optional: true},
			{Name: "expires_in", Kind: FieldNumber, Optional: true},
			{Name: "token_type", Kind: FieldText, Pattern: `[Bb]earer`, Optional: true},
			{Name: "scope", Kind: FieldText, Pattern: `[a-z_.: ]{1,200}`, Optional: true},
		}},
		RequestHeaders: []string{
			"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
			"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
		},
		SignInHeaders:    []string{"Accept", "Content-Type", "User-Agent", "Originator"},
		ResponseHeaders:  []string{"Content-Type", "Retry-After", "X-Request-Id", "Openai-Model"},
		ResponsePrefixes: []string{"X-Codex-"},
	}
}

// PlanLoginStore is the vault's plan logins (#1015) as the route uses
// them: Resolve turns a worker's placeholder into the real value, and the
// swappers store a refreshed or first login and issue that worker's new
// placeholders.
type PlanLoginStore interface {
	ForWorker(provider, worker string) Swapper
	ForSignIn(provider, worker string) Swapper
	Resolve(provider, worker, placeholder string) (string, bool)
}

// QuotaReading is one quota pool's state, read from the provider's
// response headers on the broker's own connection (#809).
type QuotaReading struct {
	At            time.Time
	Provider      string
	Worker        string
	Pool          string
	UsedPercent   float64
	WindowMinutes int
	ResetAt       int64
	// Exhausted is set when the provider signals credits or a reached
	// limit; until those are measured, any such signal reads as used up.
	Exhausted bool
}

// PlanUse is one forwarded request, for the OP-8 meter.
type PlanUse struct {
	At            time.Time
	Provider      string
	Worker        string
	Endpoint      string
	Status        int
	RequestBytes  int64
	ResponseBytes int64
	Duration      time.Duration
}

// WorkerRouteConfig configures one worker's route.
type WorkerRouteConfig struct {
	Route  PlanRoute
	Worker string
	// SignIn selects the sign-in endpoints instead of the run endpoints.
	SignIn bool
	Logins PlanLoginStore
	// Transport reaches the provider; when nil, Guard's DefaultTransport.
	Transport http.RoundTripper
	Guard     *netguard.Policy
	Audit     Auditor
	Quota     func(QuotaReading)
	Meter     func(PlanUse)
	Now       func() time.Time
	// MaxBody caps a request body; zero means DefaultMaxBody.
	MaxBody int64
}

// maxExchangeRequest caps a sign-in or refresh request body.
const maxExchangeRequest = 16 << 10

var (
	queryValue = regexp.MustCompile(`\A[A-Za-z0-9._-]{1,64}\z`)
	signInCode = regexp.MustCompile(`\A[A-Z0-9-]{4,16}\z`)
	safeWord   = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,40}\z`)
)

func (r PlanRoute) validate() error {
	if r.Provider == "" || strings.ContainsAny(r.Provider, "/?#%. ") {
		return fmt.Errorf("plan route provider %q", r.Provider)
	}
	o, err := url.Parse(r.Origin)
	if err != nil || o.Scheme != "http" || o.Path != "" || o.User != nil || o.RawQuery != "" || o.Fragment != "" {
		return fmt.Errorf("plan route %s: origin %q", r.Provider, r.Origin)
	}
	if r.AuthHost == "" || strings.ContainsAny(r.AuthHost, "/:@?#% ") {
		return fmt.Errorf("plan route %s: auth host %q", r.Provider, r.AuthHost)
	}
	for _, p := range []string{r.RedirectPath, r.DevicePage} {
		if _, err := splitPath(p); err != nil || strings.ContainsAny(p, "{}") {
			return fmt.Errorf("plan route %s: path %q", r.Provider, p)
		}
	}
	if len(r.ToolTypes) == 0 {
		return fmt.Errorf("plan route %s: no tool types", r.Provider)
	}
	for _, t := range r.ToolTypes {
		if !clientToolTypes[t] {
			return fmt.Errorf("plan route %s: tool type %q is not client-side", r.Provider, t)
		}
	}
	if len(r.BodyKeys) == 0 || len(r.InputTypes) == 0 || len(r.ContentTypes) == 0 {
		return fmt.Errorf("plan route %s: no body shape", r.Provider)
	}
	for _, k := range r.BodyKeys {
		if relayDeniedKeys[k] {
			return fmt.Errorf("plan route %s: body key %q is denied on every relay (E10)", r.Provider, k)
		}
	}
	seen := map[string]bool{}
	for _, e := range r.Endpoints {
		if e.Name == "" || seen[e.Name] {
			return fmt.Errorf("plan route %s: endpoint %q unnamed or repeated", r.Provider, e.Name)
		}
		seen[e.Name] = true
		if e.Host == "" || strings.ContainsAny(e.Host, "/:@?#% ") {
			return fmt.Errorf("plan route %s: endpoint %s: host %q", r.Provider, e.Name, e.Host)
		}
		if _, err := splitPath(e.Path); err != nil || strings.ContainsAny(e.Path, "{}") {
			return fmt.Errorf("plan route %s: endpoint %s: path %q", r.Provider, e.Name, e.Path)
		}
		switch e.Kind {
		case KindRead:
			if e.Method != "GET" {
				return fmt.Errorf("plan route %s: endpoint %s: a read is a GET", r.Provider, e.Name)
			}
		case KindResponses, KindRefresh, KindDevice, KindCode:
			if e.Method != "POST" {
				return fmt.Errorf("plan route %s: endpoint %s: %s is a POST", r.Provider, e.Name, e.Kind)
			}
		default:
			return fmt.Errorf("plan route %s: endpoint %s: kind %q", r.Provider, e.Name, e.Kind)
		}
		if (e.Kind == KindDevice || e.Kind == KindCode) != e.SignIn {
			return fmt.Errorf("plan route %s: endpoint %s: only device and code endpoints are sign-in", r.Provider, e.Name)
		}
		if (e.Kind == KindRefresh || e.Kind == KindCode) && e.Host != r.AuthHost {
			return fmt.Errorf("plan route %s: endpoint %s: a token exchange goes to the auth host", r.Provider, e.Name)
		}
		for _, q := range e.Query {
			if !safeWord.MatchString(q) {
				return fmt.Errorf("plan route %s: endpoint %s: query key %q", r.Provider, e.Name, q)
			}
		}
	}
	for _, h := range append(append(append([]string(nil), r.RequestHeaders...), r.SignInHeaders...), r.ResponseHeaders...) {
		if planForbiddenHeader(http.CanonicalHeaderKey(h)) {
			return fmt.Errorf("plan route %s: may not forward header %s", r.Provider, h)
		}
	}
	for _, p := range r.ResponsePrefixes {
		if p == "" || planForbiddenHeader(http.CanonicalHeaderKey(p)) {
			return fmt.Errorf("plan route %s: response prefix %q", r.Provider, p)
		}
	}
	return nil
}

// planForbiddenHeader names headers no plan route forwards: credentials,
// cookies, encodings the redactor cannot read, hop-by-hop and framing
// headers, redirects, and the broker's own signals. It is narrower than
// forbiddenHeader because the CLI's own session_id names a conversation,
// not a login.
func planForbiddenHeader(c string) bool {
	switch c {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Location",
		"Accept-Encoding", "Content-Encoding", "Transfer-Encoding", "Content-Length",
		"Host", "Connection", "Upgrade", "Te", "Trailer", "Keep-Alive":
		return true
	}
	l := strings.ToLower(c)
	for _, w := range []string{"agentos", "auth", "token", "key", "cookie", "secret", "password"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// SignInLink checks the verification link and code the CLI printed before
// either reaches the owner's page. The CLI prints its issuer's page, the
// forwarder's origin; the owner must open the auth host's own page. Only
// those two exact links are accepted, and the auth host's is returned:
// anything else stops sign-in, so a look-alike link is never shown.
func (r PlanRoute) SignInLink(printed, code string) (link, userCode string, err error) {
	own := "https://" + r.AuthHost + r.DevicePage
	if printed != r.Origin+r.DevicePage && printed != own {
		return "", "", errors.New("sign-in link is not the provider's verification page")
	}
	if !signInCode.MatchString(code) {
		return "", "", errors.New("sign-in code out of shape")
	}
	return own, code, nil
}

type workerRoute struct {
	c         WorkerRouteConfig
	rt        http.RoundTripper
	token     ResponseRule
	endpoints []PlanEndpoint
	headers   []string
	tools     map[string]bool
	keys      map[string]bool
	inputs    map[string]bool
	parts     map[string]bool
}

// NewWorkerRoute returns the handler a worker's forwarder reaches.
func NewWorkerRoute(c WorkerRouteConfig) (http.Handler, error) {
	if err := c.Route.validate(); err != nil {
		return nil, err
	}
	if c.Worker == "" || c.Logins == nil || c.Audit == nil {
		return nil, errors.New("worker route: worker, logins and auditor are required")
	}
	w := &workerRoute{c: c, rt: c.Transport}
	if w.rt == nil {
		if c.Guard == nil {
			return nil, errors.New("worker route: a transport or a guard is required")
		}
		w.rt = DefaultTransport(c.Guard)
	}
	w.token = ResponseRule{Fields: append([]Field(nil), c.Route.Token.Fields...)}
	if err := w.token.compile(); err != nil {
		return nil, fmt.Errorf("worker route: token rule: %v", err)
	}
	if w.c.Now == nil {
		w.c.Now = time.Now
	}
	if w.c.MaxBody <= 0 {
		w.c.MaxBody = DefaultMaxBody
	}
	for _, e := range c.Route.Endpoints {
		if e.SignIn == c.SignIn {
			w.endpoints = append(w.endpoints, e)
		}
	}
	w.headers = c.Route.RequestHeaders
	if c.SignIn {
		w.headers = c.Route.SignInHeaders
	}
	w.tools, w.keys = set(c.Route.ToolTypes), set(c.Route.BodyKeys)
	w.inputs, w.parts = set(c.Route.InputTypes), set(c.Route.ContentTypes)
	return w, nil
}

func (w *workerRoute) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := w.c.Now()
	ev := Event{At: start, Machine: w.c.Worker, Adapter: w.c.Route.Provider, Method: r.Method}
	deny := func(status int, reason string) {
		ev.Reason, ev.Status = reason, status
		w.c.Audit.Egress(ev)
		rw.Header().Set(DeniedHeader, "1")
		http.Error(rw, "egress denied: "+reason, status)
	}
	if r.Method == http.MethodConnect {
		deny(http.StatusForbidden, "CONNECT not supported")
		return
	}
	ev.Path = r.URL.Path
	if len(ev.Path) > 256 {
		ev.Path = ev.Path[:256]
	}
	// N1: an upgraded connection's frames would pass no body check.
	if r.Header.Get("Upgrade") != "" || headerHasToken(r.Header, "Connection", "upgrade") {
		deny(http.StatusForbidden, "protocol upgrade not supported")
		return
	}
	if r.URL.RawPath != "" || r.URL.Fragment != "" {
		deny(http.StatusForbidden, "undeclared request shape")
		return
	}
	ep, ok := w.match(r.Method, r.URL.Path)
	if !ok {
		deny(http.StatusForbidden, "no declared endpoint matches")
		return
	}
	ev.Operation, ev.Path = ep.Name, ep.Host+ep.Path
	query, ok := declaredQuery(ep, r.URL.RawQuery)
	if !ok {
		deny(http.StatusForbidden, "undeclared query")
		return
	}
	if encoded(r.Header) {
		deny(http.StatusForbidden, "encoded request body refused")
		return
	}
	limit := w.c.MaxBody
	if ep.Kind == KindRefresh || ep.Kind == KindCode || ep.Kind == KindDevice {
		limit = maxExchangeRequest
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		deny(http.StatusForbidden, "request body unreadable or too large")
		return
	}

	up, err := http.NewRequestWithContext(r.Context(), ep.Method, "https://"+ep.Host+ep.Path, nil)
	if err != nil {
		deny(http.StatusForbidden, "undeclared request shape")
		return
	}
	up.URL.RawQuery = query
	for _, h := range w.headers {
		for _, v := range r.Header.Values(h) {
			up.Header.Add(h, v)
		}
	}
	up.Header.Set("Accept-Encoding", "identity")

	// injected holds the real values this request carries; the response
	// is redacted of them.
	var injected [][]byte
	switch ep.Kind {
	case KindResponses, KindRead:
		real, ok := w.bearer(r.Header)
		if !ok {
			deny(http.StatusForbidden, "no login placeholder of this worker")
			return
		}
		injected = append(injected, []byte(real))
		up.Header.Set("Authorization", "Bearer "+real)
		if ep.Kind == KindRead {
			if len(body) != 0 {
				deny(http.StatusForbidden, "a read carries no body")
				return
			}
			break
		}
		out, reason := w.checkResponses(body)
		if reason != "" {
			deny(http.StatusForbidden, reason)
			return
		}
		body = out
	case KindRefresh:
		out, real, reason := w.checkRefresh(body)
		if reason != "" {
			deny(http.StatusForbidden, reason)
			return
		}
		injected = append(injected, []byte(real))
		body = out
		up.Header.Set("Content-Type", "application/json")
	case KindCode:
		out, reason := w.checkCode(r.Header, body)
		if reason != "" {
			deny(http.StatusForbidden, reason)
			return
		}
		body = out
		up.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case KindDevice:
		out, reason := strictStringObject(body)
		if reason != "" {
			deny(http.StatusForbidden, reason)
			return
		}
		body = out
		up.Header.Set("Content-Type", "application/json")
	}
	if len(body) > 0 {
		up.Body = io.NopCloser(bytes.NewReader(body))
		up.ContentLength = int64(len(body))
		up.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}

	use := PlanUse{At: start, Provider: w.c.Route.Provider, Worker: w.c.Worker, Endpoint: ep.Name, RequestBytes: int64(len(body))}
	resp, err := w.rt.RoundTrip(up)
	if errors.Is(err, netguard.ErrDenied) {
		deny(http.StatusForbidden, "destination refused by the home-network address policy")
		return
	}
	if err != nil {
		ev.Allowed, ev.Status, ev.Reason = true, http.StatusBadGateway, "upstream unreachable"
		w.c.Audit.Egress(ev)
		http.Error(rw, "egress: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	defer func() {
		use.Duration = w.c.Now().Sub(start)
		if w.c.Meter != nil {
			w.c.Meter(use)
		}
	}()
	use.Status = resp.StatusCode
	w.readQuota(resp.Header)

	if encoded(resp.Header) {
		ev.Allowed, ev.Status, ev.Reason = true, http.StatusBadGateway, "encoded response refused"
		w.c.Audit.Egress(ev)
		http.Error(rw, "egress: encoded response refused", http.StatusBadGateway)
		return
	}

	// CRED-5: a token response reaches the worker only swapped, and only
	// after the vault holds the login it replaces.
	if ep.Kind == KindRefresh || ep.Kind == KindCode {
		sw := w.c.Logins.ForWorker(w.c.Route.Provider, w.c.Worker)
		if ep.Kind == KindCode {
			sw = w.c.Logins.ForSignIn(w.c.Route.Provider, w.c.Worker)
		}
		out, commit, err := w.token.swap(resp, w.c.Route.Provider, sw)
		if err == nil {
			err = commit()
		}
		if err != nil {
			ev.Status = resp.StatusCode
			ev.Reason = ReasonUnswappable
			if resp.StatusCode >= 400 {
				ev.Reason = "credential exchange answered with an error; dropped"
			}
			w.c.Audit.Egress(ev)
			rw.Header().Set(DeniedHeader, "1")
			http.Error(rw, "egress denied: "+ev.Reason, http.StatusBadGateway)
			return
		}
		use.ResponseBytes = int64(len(out))
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		ev.Allowed, ev.Status = true, http.StatusOK
		w.c.Audit.Egress(ev)
		rw.Write(out)
		return
	}

	red := vault.NewRedactor(injected)
	for _, h := range w.responseHeaders(resp.Header) {
		for _, v := range resp.Header.Values(h) {
			rw.Header().Add(h, string(red.Redact([]byte(v))))
		}
	}
	rw.WriteHeader(resp.StatusCode)
	ev.Allowed, ev.Status = true, resp.StatusCode
	w.c.Audit.Egress(ev)

	out := red.Writer(rw)
	fl, _ := rw.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			use.ResponseBytes += int64(n)
			if _, err := out.Write(buf[:n]); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if rerr != nil {
			break
		}
	}
	out.Close()
	if fl != nil {
		fl.Flush()
	}
}

func (w *workerRoute) match(method, path string) (PlanEndpoint, bool) {
	if _, err := splitPath(path); err != nil {
		return PlanEndpoint{}, false
	}
	for _, e := range w.endpoints {
		if e.Method == method && e.Path == path {
			return e, true
		}
	}
	return PlanEndpoint{}, false
}

// declaredQuery accepts only the endpoint's declared keys, each at most
// once with a plain value, and returns the route's own encoding.
func declaredQuery(ep PlanEndpoint, raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	allowed := map[string]bool{}
	for _, k := range ep.Query {
		allowed[k] = true
	}
	for k, vs := range q {
		if !allowed[k] || len(vs) != 1 || !queryValue.MatchString(vs[0]) {
			return "", false
		}
	}
	return q.Encode(), true
}

// bearer resolves the worker's own placeholder from Authorization.
func (w *workerRoute) bearer(h http.Header) (string, bool) {
	vs := h.Values("Authorization")
	if len(vs) != 1 {
		return "", false
	}
	ph, ok := strings.CutPrefix(vs[0], "Bearer ")
	if !ok || ph == "" || strings.ContainsAny(ph, " \t") {
		return "", false
	}
	return w.c.Logins.Resolve(w.c.Route.Provider, w.c.Worker, ph)
}

// checkResponses holds a model call to the route's declared shape: only
// its top-level keys, input item types and content part types, with tools
// only where the CLI declares them (a top-level tools array, an
// additional_tools input item (#809), a namespace's nested tools) and only
// of client-side types. As on every relay (E10), store is forced off and
// remote content sources are refused. It returns the route's own encoding
// of what it checked, or the reason it refused.
func (w *workerRoute) checkResponses(body []byte) ([]byte, string) {
	obj, err := strictObject(body)
	if err != nil {
		return nil, "body is not a single JSON object"
	}
	for k, v := range obj {
		if !w.keys[k] {
			return nil, "body key " + sanitized(k) + " refused"
		}
		if k != "tools" && k != "input" {
			if r := noTools(v, 0); r != "" {
				return nil, r
			}
		}
	}
	if s, ok := obj["store"]; ok && s != false {
		return nil, "store must be false"
	}
	obj["store"] = false
	if t, ok := obj["tools"]; ok {
		if r := w.checkTools(t, 0); r != "" {
			return nil, r
		}
	}
	if in, ok := obj["input"]; ok {
		if r := w.checkInput(in); r != "" {
			return nil, r
		}
	}
	if tc, ok := obj["tool_choice"]; ok {
		switch v := tc.(type) {
		case string:
			if v != "auto" && v != "none" && v != "required" {
				return nil, "tool_choice " + sanitized(v) + " refused"
			}
		case map[string]any:
			if t, _ := v["type"].(string); !w.tools[t] {
				return nil, "tool_choice type " + sanitized(t) + " refused"
			}
		default:
			return nil, "tool_choice out of shape"
		}
	}
	if err := remoteSource(obj, ""); err != nil {
		return nil, err.Error()
	}
	out, err := encodeJSON(obj)
	if err != nil {
		return nil, "body could not be re-encoded"
	}
	return out, ""
}

// checkInput holds each input item to a declared type. Only an
// additional_tools item carries tools, and a message's content parts (and
// a tool output's, when it is a list) are of declared types.
func (w *workerRoute) checkInput(v any) string {
	in, ok := v.([]any)
	if !ok {
		return "input is not a list"
	}
	for _, it := range in {
		item, ok := it.(map[string]any)
		if !ok {
			return "input item is not an object"
		}
		t, _ := item["type"].(string)
		if !w.inputs[t] {
			return "input item type " + sanitized(t) + " refused"
		}
		for k, f := range item {
			switch {
			case k == "tools" && t == "additional_tools":
				if r := w.checkTools(f, 0); r != "" {
					return r
				}
			case k == "tools":
				return "tools outside a declared position"
			case k == "content" || k == "output":
				if r := w.checkParts(f); r != "" {
					return r
				}
			default:
				if r := noTools(f, 0); r != "" {
					return r
				}
			}
		}
		if _, has := item["tools"]; t == "additional_tools" && !has {
			return "additional_tools item without a tools list"
		}
	}
	return ""
}

// checkParts allows text, or a list of parts of declared types.
func (w *workerRoute) checkParts(v any) string {
	list, ok := v.([]any)
	if !ok {
		if _, text := v.(string); text {
			return ""
		}
		return "content out of shape"
	}
	for _, it := range list {
		part, ok := it.(map[string]any)
		if !ok {
			return "content part is not an object"
		}
		if t, _ := part["type"].(string); !w.parts[t] {
			return "content part type " + sanitized(t) + " refused"
		}
		if r := noTools(part, 0); r != "" {
			return r
		}
	}
	return ""
}

// noTools refuses a tools key anywhere in v: tools are checked only where
// the CLI declares them.
func noTools(v any, depth int) string {
	if depth > 32 {
		return "body nested too deep"
	}
	switch x := v.(type) {
	case map[string]any:
		for k, f := range x {
			if k == "tools" {
				return "tools outside a declared position"
			}
			if r := noTools(f, depth+1); r != "" {
				return r
			}
		}
	case []any:
		for _, f := range x {
			if r := noTools(f, depth+1); r != "" {
				return r
			}
		}
	}
	return ""
}

func (w *workerRoute) checkTools(v any, depth int) string {
	list, ok := v.([]any)
	if !ok {
		return "tools is not a list"
	}
	if depth > 4 {
		return "tools nested too deep"
	}
	for _, it := range list {
		tool, ok := it.(map[string]any)
		if !ok {
			return "tool is not an object"
		}
		t, _ := tool["type"].(string)
		if !w.tools[t] {
			return "tool type " + sanitized(t) + " refused"
		}
		nested, has := tool["tools"]
		if t == "namespace" && !has {
			return "namespace without a tools list"
		}
		if has {
			if r := w.checkTools(nested, depth+1); r != "" {
				return r
			}
		}
	}
	return ""
}

var refreshKeys = map[string]bool{"client_id": true, "grant_type": true, "refresh_token": true, "scope": true}

// checkRefresh puts the real refresh token at its declared field. The
// body may carry only the refresh's declared keys.
func (w *workerRoute) checkRefresh(body []byte) ([]byte, string, string) {
	obj, err := strictObject(body)
	if err != nil {
		return nil, "", "refresh body is not a single JSON object"
	}
	for k, v := range obj {
		if _, ok := v.(string); !refreshKeys[k] || !ok {
			return nil, "", "undeclared refresh field"
		}
	}
	if obj["grant_type"] != "refresh_token" {
		return nil, "", "refresh grant out of shape"
	}
	ph, _ := obj["refresh_token"].(string)
	real, ok := w.c.Logins.Resolve(w.c.Route.Provider, w.c.Worker, ph)
	if ph == "" || !ok {
		return nil, "", "no login placeholder of this worker"
	}
	obj["refresh_token"] = real
	out, err := encodeJSON(obj)
	if err != nil {
		return nil, "", "body could not be re-encoded"
	}
	return out, real, ""
}

var codeKeys = []string{"client_id", "code", "code_verifier", "grant_type", "redirect_uri"}

// checkCode admits sign-in's code exchange in its exact form and rewrites
// the forwarder's callback to the auth host's: the provider binds the code
// to its own (#809). Any other redirect_uri is refused, not passed on.
func (w *workerRoute) checkCode(h http.Header, body []byte) ([]byte, string) {
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return nil, "code exchange is not a form"
	}
	f, err := url.ParseQuery(string(body))
	if err != nil || len(f) != len(codeKeys) {
		return nil, "code exchange out of shape"
	}
	for _, k := range codeKeys {
		if vs := f[k]; len(vs) != 1 || vs[0] == "" {
			return nil, "code exchange out of shape"
		}
	}
	if f.Get("grant_type") != "authorization_code" {
		return nil, "code exchange grant out of shape"
	}
	if f.Get("redirect_uri") != w.c.Route.Origin+w.c.Route.RedirectPath {
		return nil, "redirect_uri is not the forwarder's callback"
	}
	f.Set("redirect_uri", "https://"+w.c.Route.AuthHost+w.c.Route.RedirectPath)
	return []byte(f.Encode()), ""
}

// strictStringObject admits a JSON object of string values only.
func strictStringObject(body []byte) ([]byte, string) {
	obj, err := strictObject(body)
	if err != nil {
		return nil, "body is not a single JSON object"
	}
	for _, v := range obj {
		if s, ok := v.(string); !ok || len(s) > 512 {
			return nil, "body field out of shape"
		}
	}
	out, err := encodeJSON(obj)
	if err != nil {
		return nil, "body could not be re-encoded"
	}
	return out, ""
}

func strictObject(body []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return obj, nil
}

func encodeJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// sanitized names a refused value in the journal only when it is a plain
// word; the journal never carries request payload.
func sanitized(s string) string {
	if safeWord.MatchString(s) {
		return s
	}
	return "(unnamed)"
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, line := range h.Values(name) {
		for _, v := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(v), token) {
				return true
			}
		}
	}
	return false
}

func (w *workerRoute) responseHeaders(h http.Header) []string {
	var names []string
	for _, n := range w.c.Route.ResponseHeaders {
		names = append(names, http.CanonicalHeaderKey(n))
	}
	for k := range h {
		if planForbiddenHeader(k) {
			continue
		}
		for _, p := range w.c.Route.ResponsePrefixes {
			if strings.HasPrefix(k, http.CanonicalHeaderKey(p)) {
				names = append(names, k)
				break
			}
		}
	}
	return names
}

// readQuota turns the provider's quota headers into one reading per pool.
// A credits or reached-limit signal is not yet measured (#809), so any
// such header reads as used up.
func (w *workerRoute) readQuota(h http.Header) {
	if w.c.Quota == nil {
		return
	}
	exhausted := h.Get("X-Codex-Rate-Limit-Reached-Type") != ""
	for k := range h {
		if strings.HasPrefix(k, "X-Codex-Credits-") {
			exhausted = true
		}
	}
	now := w.c.Now()
	emitted := false
	for _, pool := range []string{"primary", "secondary"} {
		pre := "X-Codex-" + strings.ToUpper(pool[:1]) + pool[1:] + "-"
		used, window, reset := h.Get(pre+"Used-Percent"), h.Get(pre+"Window-Minutes"), h.Get(pre+"Reset-At")
		if used == "" && window == "" && reset == "" {
			continue
		}
		q := QuotaReading{At: now, Provider: w.c.Route.Provider, Worker: w.c.Worker, Pool: pool, Exhausted: exhausted}
		q.UsedPercent, _ = strconv.ParseFloat(used, 64)
		q.WindowMinutes, _ = strconv.Atoi(window)
		q.ResetAt, _ = strconv.ParseInt(reset, 10, 64)
		if q.UsedPercent >= 100 {
			q.Exhausted = true
		}
		w.c.Quota(q)
		emitted = true
	}
	if exhausted && !emitted {
		w.c.Quota(QuotaReading{At: now, Provider: w.c.Route.Provider, Worker: w.c.Worker, Pool: "plan", Exhausted: true})
	}
}

func set(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, v := range list {
		m[v] = true
	}
	return m
}

// RouteControl is the broker's client of the vault process's provider
// control socket (agentos-egress). It is a vm.Services: opening a provider
// worker's services opens its route socket and returns the directory that
// holds only that socket, which the machine mounts at /run/agentos; closing
// removes it. An open that is refused (vault locked, not a provider worker)
// is an error, so the worker does not start without its route.
type RouteControl struct{ Socket string }

func (c RouteControl) do(verb, id string) (*http.Response, error) {
	cl := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.Socket)
		}},
	}
	return cl.Post("http://egress/"+verb+"?machine="+url.QueryEscape(id), "text/plain", nil)
}

// Open opens id's route and returns its directory.
func (c RouteControl) Open(id string) (string, error) {
	resp, err := c.do("open", id)
	if err != nil {
		return "", fmt.Errorf("worker route for %s: %w", id, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("worker route for %s: %s", id, strings.TrimSpace(string(body)))
	}
	var out struct{ Dir string }
	if err := json.Unmarshal(body, &out); err != nil || out.Dir == "" {
		return "", fmt.Errorf("worker route for %s: unreadable reply", id)
	}
	return out.Dir, nil
}

// Close closes id's route; a failure leaves the route to the vault
// process's own shutdown.
func (c RouteControl) Close(id string) {
	if resp, err := c.do("close", id); err == nil {
		resp.Body.Close()
	}
}
