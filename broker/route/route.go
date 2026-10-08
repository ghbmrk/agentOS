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
// a provider answers that a route is exhausted or broken (rate limit,
// quota, overload, server error, rejected credential), the call fails over
// to the next route; any other answer, and every denial by the proxy
// itself, is the guest's answer.
//
// Routing never adds a provider: grants are checked here and again by the
// proxy. Data labels are checked before anything is sent, and no Rule can
// override them (CAP-9, REV-5). Output tokens are capped at an owner
// ceiling so spend per call is bounded up front, and every served call's
// provider-reported usage is in its Decision. The router measures every
// route and task class (transport success, header latency, failover, bytes)
// but never reorders a Rule on its own: a better order is a Loop 1
// candidate (Candidate) adopted
// through §11 (SetRule), per ADP-4.
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

	"github.com/ghbmrk/agentos/broker/routerule"
)

// deniedHeader is egress.DeniedHeader: the proxy's mark on a response it
// produced itself. It is repeated here so the router does not import the
// proxy (and through it the vault); a test pins the two together.
const deniedHeader = "X-Agentos-Egress-Denied"

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
	Response(body []byte, class string) ([]byte, Usage, error)
	Stream(dst io.Writer, flush func(), src io.Reader, class string, includeUsage bool) (Usage, error)
	// Error translates a provider error body into the guest's shape.
	Error(status int, body []byte) []byte
}

// errUnsupported marks a valid request a provider cannot express; the
// router moves to the next route (ADP-3: the first route that covers the
// call).
type errUnsupported struct{ what string }

func (e errUnsupported) Error() string { return "route cannot express " + e.what }

func unsupported(what string) error { return errUnsupported{what} }

// errNotStarted is a stream that failed before writing anything to the
// guest, so another route may still serve the call.
var errNotStarted = errors.New("provider stream failed before it started")

// Route is one way to serve a class: a provider and its model.
type Route = routerule.Route

// Rule maps each task class to its routes in preference order. ADP-3's
// default order puts API routes first; the order within a class is what
// Loop 1 improves (ADP-4). The types live in routerule so code that only
// reads or changes a rule need not link the router.
type Rule = routerule.Rule

// Decision is one routing outcome. It carries no request or response
// content. Usage is what the provider reported for a served call; the
// OP-8 meter may charge the larger of it and its own byte estimate.
type Decision struct {
	At      time.Time `json:"at"`
	Machine string    `json:"machine"`
	Class   string    `json:"class,omitempty"`
	Route   string    `json:"route,omitempty"`
	Outcome string    `json:"outcome"`
	Status  int       `json:"status,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Usage   *Usage    `json:"usage,omitempty"`
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
	DefaultMaxBody         = 8 << 20
	DefaultMaxResponse     = 32 << 20
	DefaultMaxOutputTokens = 32000
	DefaultCooldown        = time.Minute
	MaxCooldown            = time.Hour
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
	// MaxOutputTokens is the owner's ceiling on one call's output tokens.
	// Every call is sent with a limit at or below it, so the meter can
	// reserve it up front. Zero means DefaultMaxOutputTokens.
	MaxOutputTokens int
	// CredentialRejected is told when a provider rejects the owner's
	// credential (401), at most once per provider a day, so the owner can
	// be texted once; the call itself fails over silently.
	CredentialRejected func(provider string)
	// Cooldown is how long an exhausted route is skipped when the provider
	// gives no Retry-After; zero means DefaultCooldown.
	Cooldown time.Duration
	// MaxBody caps the guest's request; MaxResponse caps what is read from
	// a provider for one call, streams included.
	MaxBody     int64
	MaxResponse int64
	Now         func() time.Time
}

// Stats are transport measurements since the router started, not completed-task
// acceptance or full task latency. They count only outcomes the provider is
// responsible for: served calls and
// failovers, not requests the provider or the proxy refused as invalid.
type Stats struct {
	Calls     int64         `json:"calls"`
	OK        int64         `json:"ok"`
	Failovers int64         `json:"failovers"`
	Latency   time.Duration `json:"latency"` // total time to response headers
	Bytes     int64         `json:"bytes"`
}

// evidenceKey keeps class, provider and model identity separate; display strings
// are not unique identity encodings. There is no reported model-version input.
type evidenceKey struct {
	class string
	route Route
}

// minCandidateCalls is a proposal noise guard, not a qualification or adoption
// threshold. Every route in a class needs this much evidence before reordering.
const minCandidateCalls = 10

// Router is safe for concurrent use.
type Router struct {
	cfg       Config
	providers map[string]Provider

	mu       sync.Mutex
	rule     Rule
	until    map[string]time.Time   // route -> exhausted until
	told     map[string]time.Time   // provider -> last CredentialRejected
	stats    map[string]*Stats      // aggregate diagnostics; not used for candidates
	evidence map[evidenceKey]*Stats // active class/routes only
}

// New validates the configuration and returns a router.
func New(cfg Config) (*Router, error) {
	if cfg.Granted == nil || cfg.Upstream == nil || cfg.Audit == nil {
		return nil, errors.New("route: Granted, Upstream, and Audit are required")
	}
	r := &Router{cfg: cfg, providers: map[string]Provider{}, until: map[string]time.Time{}, told: map[string]time.Time{}, stats: map[string]*Stats{}}
	for _, p := range cfg.Providers {
		if _, dup := r.providers[p.Name()]; dup {
			return nil, fmt.Errorf("route: provider %s declared twice", p.Name())
		}
		r.providers[p.Name()] = p
	}
	r.cfg.PrivateOK = map[string]bool{}
	for k, v := range cfg.PrivateOK {
		r.cfg.PrivateOK[k] = v
	}
	if r.cfg.MaxOutputTokens <= 0 {
		r.cfg.MaxOutputTokens = DefaultMaxOutputTokens
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

// MaxOutputTokens is the most output tokens any one call may produce, for
// the meter to reserve.
func (r *Router) MaxOutputTokens() int { return r.cfg.MaxOutputTokens }

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
	// Keep evidence across pure reorders, but discard removed class/routes. An
	// in-flight call retains its old pointer and cannot repopulate a new entry
	// if an identity is removed and later reintroduced.
	evidence := make(map[evidenceKey]*Stats)
	for class, routes := range cp {
		for _, rt := range routes {
			key := evidenceKey{class, rt}
			st := r.evidence[key]
			if st == nil {
				st = &Stats{}
			}
			evidence[key] = st
		}
	}
	r.rule, r.evidence = cp, evidence
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

// Candidate proposes a rule from class-specific transport measurements. A class
// keeps its full order until every active route has minCandidateCalls samples;
// then routes are ordered by transport success rate and mean header latency,
// preserving ties. These are not accepted-task or full-latency measurements.
// It only proposes: §11 adoption (ADP-4) is still required, and the candidate
// contains exactly the active routes. Grants, private-data filters, metering,
// price ceilings and adoption policy are unchanged.
func (r *Router) Candidate() Rule {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Rule and evidence must describe the same configuration snapshot.
	rule := Rule{}
	for class, active := range r.rule {
		routes := append([]Route(nil), active...)
		rule[class] = routes
		enough := true
		for _, rt := range routes {
			if r.evidence[evidenceKey{class, rt}].Calls < minCandidateCalls {
				enough = false
				break
			}
		}
		if !enough {
			continue
		}
		sort.SliceStable(routes, func(i, j int) bool {
			a, b := r.evidence[evidenceKey{class, routes[i]}], r.evidence[evidenceKey{class, routes[j]}]
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
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		private := r.cfg.Label == nil || r.cfg.Label(machine) != LabelPublic
		r.serve(caller{machine, private, r.cfg.Upstream(machine), nil}, w, req)
	})
}

// HandlerFor serves one call for a machine whose label and egress handler
// the caller supplies per request, as the vault process does for the
// broker that forwards to it (egress K9). audit, if not nil, receives
// this call's decisions after Config.Audit. Only exactly LabelPublic is
// public.
func (r *Router) HandlerFor(machine, label string, upstream http.Handler, audit func(Decision)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.serve(caller{machine, label != LabelPublic, upstream, audit}, w, req)
	})
}

// caller is who one call is served for.
type caller struct {
	machine  string
	private  bool
	upstream http.Handler
	audit    func(Decision)
}

func (r *Router) audit(c caller, d Decision) {
	r.cfg.Audit(d)
	if c.audit != nil {
		c.audit(d)
	}
}

type usageKey struct{}

// WithUsage returns ctx carrying f, which the router calls with the
// provider and its usage for each call it serves on ctx, whether or not
// the guest asked for usage. The guest plane uses it to settle the OP-8
// meter from what the provider reported.
func WithUsage(ctx context.Context, f func(provider string, u Usage)) context.Context {
	return context.WithValue(ctx, usageKey{}, f)
}

// paths the router serves: the OpenAI base URL at the root, or under the
// openai adapter's name, which is where a guest configured for the raw
// proxy already points.
var paths = map[string]bool{"/v1/chat/completions": true, "/openai/v1/chat/completions": true}

// failover reports whether a provider status means the route is exhausted
// or broken rather than that the request is wrong: rate limit or quota
// (429), rejected credential (401), overload (529), and server or gateway
// errors. It applies only to statuses the provider sent, never to the
// proxy's own denials.
func failover(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusUnauthorized, 529,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter reads Retry-After as seconds or an HTTP date.
func retryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if s, err := strconv.Atoi(v); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// clamp bounds the output tokens of a call at ceiling, setting a limit
// when the guest gave none.
func clamp(chat *chatRequest, ceiling int) *chatRequest {
	out := *chat
	limit := func(p *int) *int {
		if p == nil || *p > ceiling || *p <= 0 {
			return &ceiling
		}
		return p
	}
	switch {
	case out.MaxCompletionTokens != nil:
		out.MaxCompletionTokens = limit(out.MaxCompletionTokens)
		if out.MaxTokens != nil {
			out.MaxTokens = limit(out.MaxTokens)
		}
	case out.MaxTokens != nil:
		out.MaxTokens = limit(out.MaxTokens)
	default:
		out.MaxCompletionTokens = &ceiling
	}
	return &out
}

func (r *Router) serve(c caller, w http.ResponseWriter, req *http.Request) {
	machine := c.machine
	d := Decision{At: r.cfg.Now(), Machine: machine}
	fail := func(status int, typ, code, reason string) {
		d.Outcome, d.Status, d.Reason = Denied, status, reason
		r.audit(c, d)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(apiError(reason, typ, code))
	}
	if req.Method != http.MethodPost || !paths[req.URL.Path] || req.URL.RawPath != "" || req.URL.RawQuery != "" {
		fail(http.StatusNotFound, "invalid_request_error", "not_found", "only POST /v1/chat/completions is served")
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, r.cfg.MaxBody+1))
	if err != nil || int64(len(body)) > r.cfg.MaxBody {
		fail(http.StatusRequestEntityTooLarge, "invalid_request_error", "", "request body unreadable or too large")
		return
	}
	// A refusal's reason quotes anything the guest sent, so its class (the
	// text before the first quote) is fixed and the journal's coalescing
	// key cannot vary with the request (egress E6).
	chat, err := parseChat(body)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_request_error", "", fmt.Sprintf("request not accepted: %q", err.Error()))
		return
	}
	d.Class = chat.Model
	chat = clamp(chat, r.cfg.MaxOutputTokens)
	r.mu.Lock()
	routes := append([]Route(nil), r.rule[chat.Model]...)
	evidence := make([]*Stats, len(routes))
	for i, rt := range routes {
		evidence[i] = r.evidence[evidenceKey{chat.Model, rt}]
	}
	r.mu.Unlock()
	if len(routes) == 0 {
		fail(http.StatusNotFound, "invalid_request_error", "model_not_found", "no such model class")
		return
	}
	private := c.private

	var (
		eligible, exhausted int
		soonest             time.Time // earliest end of a cooldown met
		last                *attempt  // the last failover, if any
		unsupportedWhy      string
	)
	for i, rt := range routes {
		p := r.providers[rt.Provider]
		if !r.cfg.Granted(machine, rt.Provider) || (private && !r.cfg.PrivateOK[rt.Provider]) {
			continue
		}
		eligible++
		key := rt.String()
		r.mu.Lock()
		until := r.until[key]
		r.mu.Unlock()
		if r.cfg.Now().Before(until) {
			exhausted++
			if soonest.IsZero() || until.Before(soonest) {
				soonest = until
			}
			continue
		}
		out, err := p.Request(chat, rt.Model)
		if err != nil {
			unsupportedWhy = err.Error()
			continue
		}
		d.Route = key
		a := r.try(req.Context(), c.upstream, w, p, key, evidence[i], chat, out)
		switch {
		case a.denied:
			// The proxy's own answer (a grant, shape, body-rule, or
			// per-machine limit): this machine's, not the route's.
			d.Outcome, d.Status, d.Reason = Denied, a.status, "egress denied"
			r.audit(c, d)
			r.writeError(w, a.status, a.header, nil, a.body)
			return
		case a.failover:
			tell := false
			r.mu.Lock()
			r.until[key] = a.until
			if a.status == http.StatusUnauthorized && r.cfg.CredentialRejected != nil {
				if last, ok := r.told[rt.Provider]; !ok || r.cfg.Now().Sub(last) >= 24*time.Hour {
					r.told[rt.Provider], tell = r.cfg.Now(), true
				}
			}
			r.mu.Unlock()
			if tell {
				r.cfg.CredentialRejected(rt.Provider)
			}
			if soonest.IsZero() || a.until.Before(soonest) {
				soonest = a.until
			}
			d.Outcome, d.Status, d.Reason = Failover, a.status, "route exhausted or unavailable"
			r.audit(c, d)
			exhausted++
			last = a
			last.provider = p
			continue
		}
		d.Outcome, d.Status, d.Usage = Served, a.status, a.usage
		r.audit(c, d)
		if f, ok := req.Context().Value(usageKey{}).(func(string, Usage)); ok && a.usage != nil {
			f(rt.Provider, *a.usage)
		}
		return
	}
	d.Route = ""
	if !soonest.IsZero() && (last == nil || last.status == http.StatusTooManyRequests) {
		if s := int64(soonest.Sub(r.cfg.Now())/time.Second) + 1; s > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(s, 10))
		}
	}
	switch {
	case eligible == 0:
		fail(http.StatusForbidden, "permission_error", "no_route", "no route for this class is granted and allowed for this machine's data label")
	case exhausted > 0 && last != nil:
		d.Outcome, d.Status, d.Reason = Denied, last.status, "every permitted route is exhausted or unavailable"
		r.audit(c, d)
		r.writeError(w, last.status, nil, last.provider, last.body)
	case exhausted > 0:
		fail(http.StatusTooManyRequests, "rate_limit_error", "routes_exhausted", "every permitted route is exhausted; try again later")
	default:
		fail(http.StatusBadRequest, "invalid_request_error", "unsupported", fmt.Sprintf("no permitted route can serve this request: %q", unsupportedWhy))
	}
}

// attempt is the result of sending a call to one route.
type attempt struct {
	status   int
	header   http.Header
	body     []byte // the error body, when not served
	denied   bool   // the proxy refused it itself
	failover bool   // the route is exhausted or broken; nothing reached the guest
	until    time.Time
	usage    *Usage
	provider Provider
}

// try sends one call and, unless it fails over or the proxy denied it,
// delivers the answer to the guest.
func (r *Router) try(ctx context.Context, upstream http.Handler, w http.ResponseWriter, p Provider, key string, evidence *Stats, chat *chatRequest, out []byte) *attempt {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	start := r.cfg.Now()
	resp := call(ctx, upstream, p, out)
	defer resp.Body.Close()
	elapsed := r.cfg.Now().Sub(start)
	a := &attempt{status: resp.StatusCode, header: resp.Header}
	body := &countReader{r: io.LimitReader(resp.Body, r.cfg.MaxResponse)}

	// record counts an outcome the provider is responsible for.
	record := func(ok, failed bool) {
		r.mu.Lock()
		for _, st := range []*Stats{r.stat(key), evidence} {
			st.Calls++
			st.Latency += elapsed
			st.Bytes += body.n
			if ok {
				st.OK++
			}
			if failed {
				st.Failovers++
			}
		}
		r.mu.Unlock()
	}
	fail := func() *attempt {
		wait := retryAfter(resp.Header, r.cfg.Now())
		if wait <= 0 {
			wait = r.cfg.Cooldown
		}
		if wait > MaxCooldown {
			wait = MaxCooldown
		}
		a.failover, a.until = true, r.cfg.Now().Add(wait)
		record(false, true)
		return a
	}

	switch {
	case resp.Header.Get(deniedHeader) != "":
		a.denied = true
		a.body, _ = io.ReadAll(io.LimitReader(body, 64<<10))
		return a
	case failover(resp.StatusCode):
		a.body, _ = io.ReadAll(io.LimitReader(body, 64<<10))
		return fail()
	case resp.StatusCode >= 300:
		// The provider's answer to this request; not the route's fault.
		a.body, _ = io.ReadAll(io.LimitReader(body, 64<<10))
		r.writeError(w, resp.StatusCode, nil, p, a.body)
		return a
	}

	if chat.Stream {
		lw := &lazyWriter{w: w}
		fl, _ := w.(http.Flusher)
		flush := func() {
			if fl != nil && lw.started {
				fl.Flush()
			}
		}
		u, err := p.Stream(lw, flush, body, chat.Model, chat.StreamOptions != nil && chat.StreamOptions.IncludeUsage)
		if err != nil && !lw.started {
			// Nothing reached the guest: the route failed, not the call.
			a.status = http.StatusBadGateway
			if errors.Is(err, errNotStarted) {
				a.status = 529
			}
			a.body = apiError("provider stream failed", "server_error", "")
			return fail()
		}
		// A stream that breaks after it started cannot be retried; the
		// guest sees it end without [DONE].
		a.usage = &u
		record(err == nil, false)
		return a
	}
	raw, err := io.ReadAll(body)
	w.Header().Set("Content-Type", "application/json")
	// A provider answer the router cannot use may still be billed: its
	// size is reported as unverified output, the meter's floor (OP-8).
	unusable := func(msg string) *attempt {
		a.usage = &Usage{OutputChars: body.n}
		w.WriteHeader(http.StatusBadGateway)
		w.Write(apiError(msg, "server_error", ""))
		return a
	}
	if err != nil {
		return unusable("provider response unreadable")
	}
	if body.n >= r.cfg.MaxResponse {
		return unusable("provider response too large")
	}
	translated, u, err := p.Response(raw, chat.Model)
	if err != nil {
		return unusable(err.Error())
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(translated)
	a.usage = &u
	record(true, false)
	return a
}

// writeError gives the guest an error in the OpenAI shape. A provider's
// error is translated by p; the proxy's own plain-text denials (p nil) and
// anything else not already in that shape are wrapped.
func (r *Router) writeError(w http.ResponseWriter, status int, hdr http.Header, p Provider, body []byte) {
	var out []byte
	if p != nil {
		out = p.Error(status, body)
	}
	if !isAPIError(out) {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 || msg == "" || !strings.HasPrefix(msg, "egress denied:") {
			msg = fmt.Sprintf("upstream error (HTTP %d)", status)
		}
		typ := "server_error"
		switch {
		case status == http.StatusTooManyRequests:
			typ = "rate_limit_error"
		case status == http.StatusForbidden:
			typ = "permission_error"
		case status < 500:
			typ = "invalid_request_error"
		}
		out = apiError(msg, typ, "")
	}
	if v := hdr.Get("Retry-After"); v != "" {
		w.Header().Set("Retry-After", v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(out)
}

// lazyWriter writes the guest's stream headers on the first byte, so a
// stream that fails before producing anything can still fail over.
type lazyWriter struct {
	w       http.ResponseWriter
	started bool
}

func (l *lazyWriter) Write(b []byte) (int, error) {
	if !l.started {
		l.started = true
		l.w.Header().Set("Content-Type", "text/event-stream")
		l.w.Header().Set("Cache-Control", "no-cache")
		l.w.WriteHeader(http.StatusOK)
	}
	return l.w.Write(b)
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
			if v := recover(); v != nil {
				// Reported as a broken route, never as a guest answer.
				w.WriteHeader(http.StatusBadGateway)
				pw.CloseWithError(fmt.Errorf("proxy panic: %v", v))
				return
			}
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
