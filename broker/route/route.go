// Package route is the broker's model router (CAP-9, ADP-3, ADP-4; PLAN
// P2-7).
//
// A guest asks for a model through the one interface it is qualified on,
// OpenAI chat completions (ARC-6 (a)). The model name it sends is a task
// class. The router looks the class up in the active Rule, an ordered list
// of routes (provider and provider model), and serves the call from the
// first route that is granted to the calling machine, allowed for its data
// label, not exhausted, and able to express the request. Each provider
// translates the call into its own API and sends it through the egress
// proxy, which alone holds and injects credentials (CRED-5, ADP-10). When
// a route answers that it is exhausted or broken (rate limit, quota,
// overload, server error, rejected credential), the call fails over to the
// next route; any other answer is the guest's answer.
//
// Routing never adds a provider: grants are checked here and again by the
// proxy. Data labels are checked before anything is sent, and no Rule can
// override them (CAP-9, REV-5). The router measures every route (success,
// latency, failover, bytes) but never reorders a Rule on its own: a better
// order is a Loop 1 candidate (Candidate) adopted through §11 (SetRule),
// per ADP-4.
//
// The router holds no credential and opens no connection: everything it
// sends goes to the proxy handler it is given.
package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Provider translates the guest interface to one provider's API, sent
// through the egress adapter it names. The set is closed: providers are
// declared in this package and reviewed with it.
type Provider interface {
	// Name is the egress adapter the provider's requests go through.
	Name() string
	// Path is the upstream path of its inference operation.
	Path() string
	// Headers are sent with every request (the proxy forwards only
	// those its adapter declares).
	Headers() map[string]string
	Request(req *chatRequest, model string) ([]byte, error)
	Response(body []byte, class string) ([]byte, error)
	Stream(dst io.Writer, flush func(), src io.Reader, class string, includeUsage bool) error
	// Error translates a provider error body into the guest's shape.
	Error(status int, body []byte) []byte
}

// errUnsupported marks a request a provider cannot express; the router
// moves to the next route (ADP-3: the first route that covers the call).
type errUnsupported struct{ what string }

func (e errUnsupported) Error() string { return "route cannot express " + e.what }

func unsupported(what string) error { return errUnsupported{what} }

// errBadRequest marks a request no route could serve.
type errBadRequest struct{ msg string }

func (e errBadRequest) Error() string { return e.msg }

func badRequest(msg string) error { return errBadRequest{msg} }

// Route is one way to serve a class: a provider and its model.
type Route struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

func (r Route) String() string { return r.Provider + "/" + r.Model }

// Rule maps each task class to its routes in preference order. ADP-3's
// default order puts API routes first; the order within a class is what
// Loop 1 improves (ADP-4).
type Rule map[string][]Route

// Decision is one routing outcome. It carries no request or response
// content.
type Decision struct {
	At      time.Time `json:"at"`
	Machine string    `json:"machine"`
	Class   string    `json:"class,omitempty"`
	Route   string    `json:"route,omitempty"`
	Outcome string    `json:"outcome"`
	Status  int       `json:"status,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

// Outcomes.
const (
	Served   = "served"
	Failover = "failover"
	Denied   = "denied"
)

// LabelPublic is the REV-5 label under which a machine may use any granted
// provider. Every other label, including none, is private.
const LabelPublic = "public"

// Defaults.
const (
	DefaultMaxBody     = 8 << 20
	DefaultMaxResponse = 32 << 20
	DefaultCooldown    = time.Minute
	MaxCooldown        = time.Hour
)

// Config configures New.
type Config struct {
	Providers []Provider
	Rule      Rule
	// Granted reports whether the owner granted provider to machine. It is
	// the same grant the egress proxy enforces; the router checks it so it
	// never even tries an ungranted route.
	Granted func(machine, provider string) bool
	// PrivateOK names the providers the owner allowed for private data
	// when connecting them (CAP-9). None by default.
	PrivateOK map[string]bool
	// Label returns a machine's REV-5 data label; nil means every machine
	// is private.
	Label func(machine string) string
	// Upstream returns the egress proxy's handler for a machine.
	Upstream func(machine string) http.Handler
	// Audit receives every decision; required.
	Audit func(Decision)
	// Cooldown is how long an exhausted route is skipped when the provider
	// gives no Retry-After; zero means DefaultCooldown.
	Cooldown    time.Duration
	MaxBody     int64
	MaxResponse int64
	Now         func() time.Time
}

// Stats are a route's measurements since the router started.
type Stats struct {
	Calls     int64         `json:"calls"`
	OK        int64         `json:"ok"`
	Failovers int64         `json:"failovers"`
	Latency   time.Duration `json:"latency"` // total time to response headers
	Bytes     int64         `json:"bytes"`
}

// Router is safe for concurrent use.
type Router struct {
	cfg       Config
	providers map[string]Provider

	mu    sync.Mutex
	rule  Rule
	until map[string]time.Time // route -> exhausted until
	stats map[string]*Stats
}

// New validates the configuration and returns a router.
func New(cfg Config) (*Router, error) {
	if cfg.Granted == nil || cfg.Upstream == nil || cfg.Audit == nil {
		return nil, errors.New("route: Granted, Upstream, and Audit are required")
	}
	r := &Router{cfg: cfg, providers: map[string]Provider{}, until: map[string]time.Time{}, stats: map[string]*Stats{}}
	for _, p := range cfg.Providers {
		if _, dup := r.providers[p.Name()]; dup {
			return nil, fmt.Errorf("route: provider %s declared twice", p.Name())
		}
		r.providers[p.Name()] = p
	}
	if r.cfg.Cooldown <= 0 {
		r.cfg.Cooldown = DefaultCooldown
	}
	if r.cfg.MaxBody <= 0 {
		r.cfg.MaxBody = DefaultMaxBody
	}
	if r.cfg.MaxResponse <= 0 {
		r.cfg.MaxResponse = DefaultMaxResponse
	}
	if r.cfg.Now == nil {
		r.cfg.Now = time.Now
	}
	if err := r.SetRule(cfg.Rule); err != nil {
		return nil, err
	}
	return r, nil
}

// SetRule replaces the active rule. It is how an adopted Loop 1 routing
// candidate takes effect (ADP-4); adoption itself is §11's. A rule may only
// name declared providers, and grants and labels still decide each call.
func (r *Router) SetRule(rule Rule) error {
	if len(rule) == 0 {
		return errors.New("route: empty rule")
	}
	cp := Rule{}
	for class, routes := range rule {
		if class == "" || len(routes) == 0 {
			return fmt.Errorf("route: class %q has no routes", class)
		}
		seen := map[Route]bool{}
		for _, rt := range routes {
			if _, ok := r.providers[rt.Provider]; !ok {
				return fmt.Errorf("route: class %s names undeclared provider %q", class, rt.Provider)
			}
			if rt.Model == "" || seen[rt] {
				return fmt.Errorf("route: class %s: bad or repeated route %s", class, rt)
			}
			seen[rt] = true
		}
		cp[class] = append([]Route(nil), routes...)
	}
	r.mu.Lock()
	r.rule = cp
	r.mu.Unlock()
	return nil
}

// Rule returns a copy of the active rule.
func (r *Router) Rule() Rule {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := Rule{}
	for c, rs := range r.rule {
		cp[c] = append([]Route(nil), rs...)
	}
	return cp
}

// Stats returns a copy of every route's measurements, keyed by route.
func (r *Router) Stats() map[string]Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]Stats{}
	for k, s := range r.stats {
		out[k] = *s
	}
	return out
}

// Candidate proposes a rule from the measurements: within each class,
// measured routes are ordered by success rate, then mean latency; routes
// with no calls keep their place after them. It only proposes. The
// proposal is a Loop 1 candidate and takes effect only if §11 adopts it
// (ADP-4); it never adds a route the active rule lacks.
func (r *Router) Candidate() Rule {
	rule, stats := r.Rule(), r.Stats()
	for _, routes := range rule {
		sort.SliceStable(routes, func(i, j int) bool {
			a, b := stats[routes[i].String()], stats[routes[j].String()]
			if (a.Calls > 0) != (b.Calls > 0) {
				return a.Calls > 0
			}
			if a.Calls == 0 {
				return false
			}
			ra, rb := float64(a.OK)/float64(a.Calls), float64(b.OK)/float64(b.Calls)
			if ra != rb {
				return ra > rb
			}
			return a.Latency/time.Duration(a.Calls) < b.Latency/time.Duration(b.Calls)
		})
	}
	return rule
}

func (r *Router) stat(route string) *Stats {
	s := r.stats[route]
	if s == nil {
		s = &Stats{}
		r.stats[route] = s
	}
	return s
}

// Handler serves one agent machine's model calls. Identity comes from
// which handler the request arrived on, never from the request.
func (r *Router) Handler(machine string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.serve(machine, w, req) })
}

// failover reports whether a provider status means the route is exhausted
// or broken rather than that the request is wrong: rate limit or quota
// (429), rejected credential (401), overload (529), and server or gateway
// errors. The proxy's own denials (403, 413) are not failovers.
func failover(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusUnauthorized, 529,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func (r *Router) serve(machine string, w http.ResponseWriter, req *http.Request) {
	d := Decision{At: r.cfg.Now(), Machine: machine}
	fail := func(status int, typ, code, reason string) {
		d.Outcome, d.Status, d.Reason = Denied, status, reason
		r.cfg.Audit(d)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(apiError(reason, typ, code))
	}
	if req.Method != http.MethodPost || req.URL.Path != "/v1/chat/completions" || req.URL.RawQuery != "" {
		fail(http.StatusNotFound, "invalid_request_error", "not_found", "only POST /v1/chat/completions is served")
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, r.cfg.MaxBody+1))
	if err != nil || int64(len(body)) > r.cfg.MaxBody {
		fail(http.StatusRequestEntityTooLarge, "invalid_request_error", "", "request body unreadable or too large")
		return
	}
	chat, err := parseChat(body)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_request_error", "", err.Error())
		return
	}
	d.Class = chat.Model
	r.mu.Lock()
	routes := append([]Route(nil), r.rule[chat.Model]...)
	r.mu.Unlock()
	if len(routes) == 0 {
		fail(http.StatusNotFound, "invalid_request_error", "model_not_found", "no such model class")
		return
	}
	private := r.cfg.Label == nil || r.cfg.Label(machine) != LabelPublic

	var (
		eligible, exhausted int
		lastStatus          int
		lastBody            []byte
		lastProvider        Provider
		unsupportedWhy      string
	)
	for _, rt := range routes {
		p := r.providers[rt.Provider]
		if !r.cfg.Granted(machine, rt.Provider) || (private && !r.cfg.PrivateOK[rt.Provider]) {
			continue
		}
		eligible++
		key := rt.String()
		r.mu.Lock()
		cooling := r.cfg.Now().Before(r.until[key])
		r.mu.Unlock()
		if cooling {
			exhausted++
			continue
		}
		out, err := p.Request(chat, rt.Model)
		var bad errBadRequest
		if errors.As(err, &bad) {
			fail(http.StatusBadRequest, "invalid_request_error", "", bad.msg)
			return
		}
		if err != nil {
			unsupportedWhy = err.Error()
			continue
		}

		ctx, cancel := context.WithCancel(req.Context())
		start := r.cfg.Now()
		resp := call(ctx, r.cfg.Upstream(machine), p, out)
		elapsed := r.cfg.Now().Sub(start)
		d.Route = key
		if failover(resp.StatusCode) {
			lastStatus, lastProvider = resp.StatusCode, p
			lastBody, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			cancel()
			wait := r.cfg.Cooldown
			if s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			if wait > MaxCooldown {
				wait = MaxCooldown
			}
			r.mu.Lock()
			r.until[key] = r.cfg.Now().Add(wait)
			st := r.stat(key)
			st.Calls++
			st.Failovers++
			st.Latency += elapsed
			r.mu.Unlock()
			d.Outcome, d.Status, d.Reason = Failover, resp.StatusCode, "route exhausted or unavailable"
			r.cfg.Audit(d)
			exhausted++
			continue
		}
		n := r.deliver(w, resp, p, chat)
		resp.Body.Close()
		cancel()
		r.mu.Lock()
		st := r.stat(key)
		st.Calls++
		if resp.StatusCode < 300 {
			st.OK++
		}
		st.Latency += elapsed
		st.Bytes += n
		r.mu.Unlock()
		d.Outcome, d.Status, d.Reason = Served, resp.StatusCode, ""
		r.cfg.Audit(d)
		return
	}
	d.Route = ""
	switch {
	case eligible == 0:
		fail(http.StatusForbidden, "permission_error", "no_route", "no route for this class is granted and allowed for this machine's data label")
	case exhausted > 0 && lastProvider != nil:
		d.Outcome, d.Status, d.Reason = Denied, lastStatus, "every permitted route is exhausted or unavailable"
		r.cfg.Audit(d)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(lastStatus)
		w.Write(lastProvider.Error(lastStatus, lastBody))
	case exhausted > 0:
		fail(http.StatusTooManyRequests, "rate_limit_error", "routes_exhausted", "every permitted route is exhausted; try again later")
	default:
		fail(http.StatusBadRequest, "invalid_request_error", "unsupported", unsupportedWhy)
	}
}

// deliver writes a provider response to the guest in the guest's shape and
// returns the bytes read from the provider.
func (r *Router) deliver(w http.ResponseWriter, resp *http.Response, p Provider, chat *chatRequest) int64 {
	cr := &countReader{r: resp.Body}
	if resp.StatusCode < 300 && chat.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(resp.StatusCode)
		fl, _ := w.(http.Flusher)
		flush := func() {
			if fl != nil {
				fl.Flush()
			}
		}
		// A broken stream cannot be retried once bytes reached the guest;
		// the guest sees it end without [DONE].
		_ = p.Stream(w, flush, cr, chat.Model, chat.StreamOptions != nil && chat.StreamOptions.IncludeUsage)
		return cr.n
	}
	body, err := io.ReadAll(io.LimitReader(cr, r.cfg.MaxResponse+1))
	w.Header().Set("Content-Type", "application/json")
	if err != nil || int64(len(body)) > r.cfg.MaxResponse {
		w.WriteHeader(http.StatusBadGateway)
		w.Write(apiError("provider response unreadable or too large", "server_error", ""))
		return cr.n
	}
	if resp.StatusCode >= 300 {
		w.WriteHeader(resp.StatusCode)
		w.Write(p.Error(resp.StatusCode, body))
		return cr.n
	}
	out, err := p.Response(body, chat.Model)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Write(apiError(err.Error(), "server_error", ""))
		return cr.n
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(out)
	return cr.n
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

// call sends one request to the proxy handler in process and returns its
// response as soon as the status is written, with the body streaming
// through a pipe. Closing the body stops the handler's writes.
func call(ctx context.Context, h http.Handler, p Provider, body []byte) *http.Response {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/"+p.Name()+p.Path(), strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.Headers() {
		req.Header.Set(k, v)
	}
	pr, pw := io.Pipe()
	w := &pipeWriter{header: http.Header{}, ready: make(chan struct{}), pw: pw}
	go func() {
		defer func() {
			w.WriteHeader(http.StatusOK)
			pw.Close()
		}()
		h.ServeHTTP(w, req)
	}()
	<-w.ready
	return &http.Response{StatusCode: w.status, Header: w.sent, Body: pr}
}

type pipeWriter struct {
	header http.Header
	sent   http.Header
	status int
	once   sync.Once
	ready  chan struct{}
	pw     *io.PipeWriter
}

func (p *pipeWriter) Header() http.Header { return p.header }

func (p *pipeWriter) WriteHeader(status int) {
	p.once.Do(func() {
		p.status, p.sent = status, p.header.Clone()
		close(p.ready)
	})
}

func (p *pipeWriter) Write(b []byte) (int, error) {
	p.WriteHeader(http.StatusOK)
	return p.pw.Write(b)
}

func (p *pipeWriter) Flush() {}
