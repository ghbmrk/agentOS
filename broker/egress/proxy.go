// Package egress is the broker's credentialed egress proxy (CRED-5, ADP-10,
// PLAN P1-3).
//
// A guest reaches a provider as a standard HTTP endpoint and holds only a
// placeholder credential. Each request arrives on a handler bound to one
// agent machine, so identity comes from where the request arrived, never
// from anything the guest sends. The proxy forwards a request only if it
// matches a declared operation of an adapter that machine is granted, and
// its JSON body passes the operation's BodyRule. It then drops every header
// outside a fixed allowlist (including any credential the guest supplied),
// writes the vault credential into the adapter's injection header, and
// sends the request over HTTPS to the adapter's host. Redirects are
// returned, never followed; encoded responses are refused. The response
// comes back with only allowlisted headers, and its headers and body pass
// the vault redactor (CRED-7), streamed so token streams keep flowing.
// Every decision is reported to the Auditor; anything else is denied.
//
// Each operation carries a verb from the broker's closed list (ADP-2).
// Only reads are forwarded; any other verb needs an intent before it
// reaches a service, and that path does not exist yet, so it is denied
// (ASSUMPTIONS.md E9). OP-8 metering wraps the proxy in package guest.
//
// The proxy is not on the control path (ARC-2): STOP, STATUS, and
// admission never import it.
package egress

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// DefaultMaxBody caps a request body, in bytes.
const DefaultMaxBody = 8 << 20

// DefaultMaxConcurrent caps one machine's requests in flight.
const DefaultMaxConcurrent = 4

// DefaultInFlightBytes is the memory the requests in flight across every
// machine may hold at once (egress K18, #1771). A request reserves what it
// can hold before it holds it: readCost while its body is read, then
// bodyCost for the body it read. So the bound follows what requests cost in
// memory rather than how many there are: a hostile body that decodes to
// many times its size takes as much of it as it holds, and small ones leave
// room for many. tests/test_egress_memory.py reads it into the vault
// unit's memory derivation.
const DefaultInFlightBytes = 320 << 20

// The terms of bodyCost, bytes per unit, each an upper bound that
// TestBodyCostBoundsApply and TestBodyCheckMemoryPerByte measure against
// BodyRule.apply's allocations for the costliest body shapes.
const (
	// costPerByte covers the body, the walk's record of each object member
	// (four bytes per member, and a member takes at least four bytes) and
	// the output, which is never longer than the body but for the terms
	// below.
	costPerByte = 3
	// costPerInvalid covers an invalid UTF-8 byte, which is forwarded as
	// the three bytes of U+FFFD. Valid UTF-8 is forwarded as it came.
	costPerInvalid = 2
	// costPerDepth is one level of the deepest nesting: the walk's frame.
	// The walk is iterative, so nesting grows no stack.
	costPerDepth = 32
	// callFloor is what any request holds besides its body: buffers,
	// headers and the response copy.
	callFloor = 64 << 10
)

// maxDepth is the deepest nesting a body may have: encoding/json's limit,
// which the decoder this check replaced applied.
const maxDepth = 10000

// DefaultWriteTimeout is how long one write of a response to a guest may
// wait for the guest to read (egress K18, SR3-mail-k18g). A guest that stops
// reading a streamed reply loses the connection, and its slots return to
// the budget, once a write waits this long; a reply that keeps flowing may
// take as long as it needs.
const DefaultWriteTimeout = 30 * time.Second

// Event is one proxy decision. It carries no header or body content, so it
// cannot carry a credential.
type Event struct {
	At        time.Time `json:"at"`
	Machine   string    `json:"machine"`
	Adapter   string    `json:"adapter,omitempty"`
	Operation string    `json:"operation,omitempty"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason,omitempty"`
	Status    int       `json:"status,omitempty"`
}

// Auditor receives every decision. It is required: the broker journals
// denials (ADP-10), and a proxy that could drop them is refused.
type Auditor interface{ Egress(Event) }

// Redactor redacts vault values from agent-bound bytes: *vault.Redactor,
// which holds the values, or *vault.HashRedactor, which holds only keyed
// hashes of them (SIM-split).
type Redactor interface {
	Redact([]byte) []byte
	Writer(io.Writer) *vault.Writer
}

// Secrets is the part of the vault the proxy uses.
type Secrets interface {
	Secret(name string) (vault.Secret, bool)
	Redactor() (*vault.Redactor, error)
}

// Cap is a hard per-machine ceiling on forwarded requests and on request
// plus response bytes, until OP-8 metering replaces it. Zero fields are
// unlimited.
type Cap struct {
	Requests int64
	Bytes    int64
}

// Config configures New.
type Config struct {
	Adapters []Adapter
	// Grants maps an agent machine to the adapters it may use.
	Grants map[string][]string
	// Vault gives the proxy the credentials it injects. It is nil when
	// every adapter has a holder (SIM-split): then the proxy reads no
	// secret, and Redaction is required instead.
	Vault Secrets
	// Holders maps a credential name to the RoundTripper of the holder
	// process that keeps it (SIM-split). The proxy sends the holder the
	// checked request with no credential; the holder injects its own,
	// opens TLS to the adapter's host, swaps any exchange response, and
	// redacts its own secret. A holder answers a dropped exchange with
	// 502 and HolderDropHeader. Holders are all or nothing: with Holders
	// set, Vault must be nil and every adapter's credential needs one.
	Holders map[string]http.RoundTripper
	// Redaction returns the redactor for every vault value when Vault is
	// nil; it holds no plaintext (vault.HashRedactor).
	Redaction func() (Redactor, error)
	Audit     Auditor
	// Transport sends upstream requests; nil means a fresh http.Transport
	// with no proxy from the environment, bounded connect, handshake, and
	// response-header waits, and every dial and handshake owned by Guard.
	// A caller-supplied Transport must dial through a netguard policy too
	// (DEV-2); tools/netguardcheck.py checks the repo's own dialers.
	Transport http.RoundTripper
	// Guard is the home-network address policy (DEV-2) the default
	// Transport uses; nil means a policy with only the IANA registries.
	Guard *netguard.Policy
	// MaxBody caps request bodies; zero means DefaultMaxBody.
	MaxBody int64
	// MaxConcurrent caps one machine's requests in flight; zero means
	// DefaultMaxConcurrent.
	MaxConcurrent int
	// InFlightBytes caps the memory requests in flight may reserve across
	// every machine; zero means DefaultInFlightBytes. One machine may
	// reserve at most half of it.
	InFlightBytes int64
	// WriteTimeout bounds each write of a response to the guest; zero
	// means DefaultWriteTimeout.
	WriteTimeout time.Duration
	// Cap is applied to each machine separately.
	Cap Cap
	// Label returns a machine's REV-5 data label. Nil, or any answer other
	// than LabelPublic, is treated as private: provider-side tools denied.
	Label func(machine string) string
	Now   func() time.Time
	// Swapper holds the credentials a credential exchange issues; required
	// when any operation declares a Response.
	Swapper Swapper
	// RouteFailed tells the owner that an adapter's route stopped, and
	// why (a Reason constant); required when any operation declares a
	// Response or Refused statuses. It is called once per stop.
	RouteFailed func(adapter, reason string)
	// Stops records which routes are stopped, so a stop outlives the
	// proxy (OP-11: the journal). Nil keeps them in this proxy, so a new
	// one starts with every route open.
	Stops RouteStops
	// Granted, if set, grants per request what Grants does not: it is
	// asked with the calling machine itself, never the grants entry a
	// replay machine borrows, and the adapter, only when no static grant
	// covers them, and its answer may change while the proxy serves (the
	// vault process grants a key stored at setup, CRED-5f-mr-grant). Nil
	// grants nothing beyond Grants.
	Granted func(machine, adapter string) bool
}

// LabelPublic is the REV-5 label under which a machine may use
// provider-side tools.
const LabelPublic = "public"

// Proxy is the credentialed egress proxy.
type Proxy struct {
	labelOf  func(string) string
	adapters map[string]Adapter
	grants   map[string]map[string]bool
	granted  func(machine, adapter string) bool
	vault    Secrets
	holders  map[string]http.RoundTripper
	redact   func() (Redactor, error)
	rt       http.RoundTripper
	rtModel  http.RoundTripper // the default transport's second pool, for inference operations
	audit    Auditor
	maxBody  int64
	maxConc  int
	budget   int64
	share    int64 // what one machine may reserve of budget
	cap      Cap
	// writeTimeout bounds each write of a response to the guest.
	writeTimeout time.Duration
	now          func() time.Time
	xch          exchangeHooks

	mu       sync.Mutex
	reserved int64 // bytes reserved by requests in flight, every machine
	usage    map[string]*machineUsage
	stops    RouteStops        // adapter -> why its route stopped (CRED-5t)
	held     map[string]string // adapter -> a stop stops could not record
}

type machineUsage struct {
	inFlight int
	reserved int64
	requests int64
	bytes    int64
}

// New validates every declaration and grant and returns a proxy.
func New(cfg Config) (*Proxy, error) {
	switch {
	case cfg.Vault == nil && cfg.Redaction == nil:
		return nil, errors.New("egress: vault required")
	case cfg.Vault != nil && (cfg.Redaction != nil || len(cfg.Holders) > 0):
		return nil, errors.New("egress: holders and the vault are exclusive")
	}
	if cfg.Audit == nil {
		return nil, errors.New("egress: auditor required")
	}
	p := &Proxy{
		adapters:     map[string]Adapter{},
		grants:       map[string]map[string]bool{},
		granted:      cfg.Granted,
		vault:        cfg.Vault,
		holders:      cfg.Holders,
		redact:       cfg.Redaction,
		rt:           cfg.Transport,
		audit:        cfg.Audit,
		maxBody:      cfg.MaxBody,
		maxConc:      cfg.MaxConcurrent,
		budget:       cfg.InFlightBytes,
		cap:          cfg.Cap,
		now:          cfg.Now,
		writeTimeout: cfg.WriteTimeout,
		usage:        map[string]*machineUsage{},
		labelOf:      cfg.Label,
		xch:          exchangeHooks{swapper: cfg.Swapper, routeFailed: cfg.RouteFailed},
		stops:        cfg.Stops,
		held:         map[string]string{},
	}
	if p.stops == nil {
		p.stops = memStops{}
	}
	for _, a := range cfg.Adapters {
		if err := a.validate(); err != nil {
			return nil, fmt.Errorf("egress: %v", err)
		}
		_, held := p.holders[a.Credential]
		if p.vault == nil && !held {
			return nil, fmt.Errorf("egress: adapter %s: credential %s has no holder", a.Name, a.Credential)
		}
		// Compile response rules on copies, so the caller's declaration
		// is never written.
		a.Operations = append([]Operation(nil), a.Operations...)
		for i, op := range a.Operations {
			if op.Response != nil {
				rule := ResponseRule{Fields: append([]Field(nil), op.Response.Fields...)}
				if err := rule.compile(); err != nil {
					return nil, fmt.Errorf("egress: adapter %s: operation %s: %v", a.Name, op.Name, err)
				}
				if p.xch.swapper == nil && !held {
					return nil, fmt.Errorf("egress: adapter %s: operation %s exchanges credentials and no swapper is set", a.Name, op.Name)
				}
				a.Operations[i].Response = &rule
			}
			if (op.Response != nil || len(op.Refused) > 0) && p.xch.routeFailed == nil {
				return nil, fmt.Errorf("egress: adapter %s: operation %s can stop its route and nobody would be told", a.Name, op.Name)
			}
		}
		if _, dup := p.adapters[a.Name]; dup {
			return nil, fmt.Errorf("egress: adapter %s declared twice", a.Name)
		}
		p.adapters[a.Name] = a
	}
	for m, names := range cfg.Grants {
		p.grants[m] = map[string]bool{}
		for _, n := range names {
			if _, ok := p.adapters[n]; !ok {
				return nil, fmt.Errorf("egress: machine %s granted undeclared adapter %s", m, n)
			}
			p.grants[m][n] = true
		}
	}
	if p.rt == nil {
		g := cfg.Guard
		if g == nil {
			g = netguard.New(netguard.Config{})
		}
		// Two pools, so a connection a model call made to a pinned host is
		// never reused by a request that has no exception (DEV-2).
		p.rt, p.rtModel = DefaultTransport(g), DefaultTransport(g)
	} else {
		p.rtModel = p.rt
	}
	if p.maxBody <= 0 {
		p.maxBody = DefaultMaxBody
	}
	if p.maxConc <= 0 {
		p.maxConc = DefaultMaxConcurrent
	}
	if p.budget <= 0 {
		p.budget = DefaultInFlightBytes
	}
	// No machine above half the budget, so machines at their share always
	// leave room for another (K18g-4).
	p.share = p.budget / 2
	if p.writeTimeout <= 0 {
		p.writeTimeout = DefaultWriteTimeout
	}
	if p.now == nil {
		p.now = time.Now
	}
	return p, nil
}

func (p *Proxy) label(machine string) string {
	if p.labelOf == nil {
		return ""
	}
	return p.labelOf(machine)
}

// Handler serves one agent machine. The broker gives each machine's VM a
// listener of its own and serves this handler on it.
func (p *Proxy) Handler(machine string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.serve(machine, machine, func() string { return p.label(machine) }, p.audit, w, r)
	})
}

// HandlerFor serves one request for machine when the proxy runs in a
// process of its own (P2-4): the broker process that owns the machine's
// socket names the machine and its REV-5 label, and audit receives this
// request's decisions in place of Config.Audit. A nil audit refuses the
// request, as New refuses a proxy without an auditor.
func (p *Proxy) HandlerFor(machine, label string, audit Auditor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if audit == nil {
			http.Error(w, "egress: no auditor", http.StatusInternalServerError)
			return
		}
		p.serve(machine, machine, func() string { return label }, audit, w, r)
	})
}

// HandlerWithGrantsOf is HandlerFor for a replay machine (LOOP-5): the
// request may use only the adapters granted to grantsOf, the agent machine
// whose calls it replays, but is audited as machine and admitted against
// machine's own concurrency and caps, never grantsOf's.
func (p *Proxy) HandlerWithGrantsOf(machine, grantsOf, label string, audit Auditor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if audit == nil {
			http.Error(w, "egress: no auditor", http.StatusInternalServerError)
			return
		}
		p.serve(machine, grantsOf, func() string { return label }, audit, w, r)
	})
}

// admit reserves n bytes of the in-flight budget, within the machine's
// share of it, and a per-machine concurrency slot and checks the cap;
// release returns both.
func (p *Proxy) admit(machine string, n int64) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reserved+n > p.budget {
		return "too many requests in flight", false
	}
	u := p.usage[machine]
	if u == nil {
		u = &machineUsage{}
		p.usage[machine] = u
	}
	switch {
	case u.inFlight >= p.maxConc, u.reserved+n > p.share:
		return "too many requests in flight", false
	case p.cap.Requests > 0 && u.requests >= p.cap.Requests:
		return "request cap reached", false
	case p.cap.Bytes > 0 && u.bytes >= p.cap.Bytes:
		return "byte cap reached", false
	}
	u.inFlight++
	u.reserved += n
	p.reserved += n
	return "", true
}

// resize changes an admitted request's reservation by d bytes. A shrink
// always succeeds; a growth fails, changing nothing, when the budget or the
// machine's share lacks the room.
func (p *Proxy) resize(machine string, d int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := p.usage[machine]
	if d > 0 && (p.reserved+d > p.budget || u.reserved+d > p.share) {
		return false
	}
	u.reserved += d
	p.reserved += d
	return true
}

func (p *Proxy) charge(machine string, requests, bytes int64) {
	p.mu.Lock()
	u := p.usage[machine]
	u.requests += requests
	u.bytes += bytes
	p.mu.Unlock()
}

func (p *Proxy) release(machine string, n int64) {
	p.mu.Lock()
	u := p.usage[machine]
	u.inFlight--
	u.reserved -= n
	p.reserved -= n
	p.mu.Unlock()
}

// readCost is what reading a body of up to n bytes can hold: io.ReadAll's
// buffer, which grows by copying, so the old and the new buffer are live
// together.
func readCost(n int64) int64 { return callFloor + 3*n }

// bodyCost is what BodyRule.apply can hold for body at its peak.
func bodyCost(body []byte) int64 {
	_, invalid, deepest := bodyShape(body)
	return callFloor + costPerByte*int64(len(body)) + costPerInvalid*int64(invalid) +
		costPerDepth*int64(min(deepest, maxDepth+1))
}

// bodyShape counts, in one pass that skips strings, what apply sizes its
// buffers by: the colons outside strings (an upper bound on object
// members), the invalid UTF-8 bytes and the deepest nesting.
func bodyShape(body []byte) (colons, invalid, deepest int) {
	depth := 0
	in, esc := false, false
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c >= 0x80 {
			if r, n := utf8.DecodeRune(body[i:]); r != utf8.RuneError || n != 1 {
				i += n - 1
			} else {
				invalid++
			}
			esc = false
			continue
		}
		switch {
		case esc:
			esc = false
		case in:
			esc, in = c == '\\', c != '"'
		case c == '"':
			in = true
		case c == '{' || c == '[':
			depth++
			deepest = max(deepest, depth)
		case c == '}' || c == ']':
			depth--
		case c == ':':
			colons++
		}
	}
	return colons, invalid, deepest
}

func (p *Proxy) serve(machine, grantsOf string, labelOf func() string, audit Auditor, w http.ResponseWriter, r *http.Request) {
	w = newDeadlineWriter(w, p.writeTimeout)
	ev := Event{At: p.now(), Machine: machine, Method: r.Method}
	deny := func(status int, reason string) {
		ev.Reason, ev.Status = reason, status
		audit.Egress(ev)
		w.Header().Set(DeniedHeader, "1")
		http.Error(w, "egress denied: "+reason, status)
	}
	// The proxy never tunnels: a CONNECT would be a dial to any address the
	// guest names (DEV-2).
	if r.Method == http.MethodConnect {
		ev.Path = ""
		deny(http.StatusForbidden, "CONNECT not supported")
		return
	}
	red, err := p.redactor()
	if err != nil {
		deny(http.StatusServiceUnavailable, "vault unavailable")
		return
	}
	ev.Path = string(red.Redact([]byte(r.URL.EscapedPath())))

	// Only clean paths with nothing escaped and no query are considered;
	// everything ambiguous is denied rather than normalized.
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.Fragment != "" {
		deny(http.StatusForbidden, "undeclared request shape")
		return
	}
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	a, ok := p.adapters[name]
	if !ok {
		deny(http.StatusForbidden, "no such adapter")
		return
	}
	ev.Adapter = a.Name
	if !p.grants[grantsOf][a.Name] && (p.granted == nil || !p.granted(machine, a.Name)) {
		deny(http.StatusForbidden, "adapter not granted to this machine")
		return
	}
	upPath := "/" + rest
	op, ok := a.match(r.Method, upPath)
	if !ok {
		deny(http.StatusForbidden, "no declared operation matches")
		return
	}
	ev.Operation = op.Name
	// CRED-5t: a stopped route's requests never reach the provider, so a
	// CLI's retries cannot worsen an account restriction.
	if why, stopped := p.stopped(a.Name); stopped {
		deny(http.StatusServiceUnavailable, "route stopped: "+why)
		return
	}
	// ADP-10: apply the verb class before forwarding. Reads have no effect
	// on the account. Every other verb needs an intent in the journal
	// before it reaches the service, and the proxy has no intent path yet
	// (E9), so it fails closed.
	if op.Verb != VerbRead {
		deny(http.StatusForbidden, "operation "+op.Verb+" needs an intent; none is wired for proxied effects")
		return
	}

	// Reserve for the body before reading it: its declared length when it
	// has one (the server reads no further), MaxBody when it does not.
	n := r.ContentLength
	if n < 0 || n > p.maxBody {
		n = p.maxBody
	}
	held := readCost(n)
	if reason, ok := p.admit(machine, held); !ok {
		deny(http.StatusTooManyRequests, reason)
		return
	}
	defer func() { p.release(machine, held) }()

	body, err := io.ReadAll(io.LimitReader(r.Body, p.maxBody+1))
	if err != nil {
		deny(http.StatusBadRequest, "unreadable body")
		return
	}
	if int64(len(body)) > p.maxBody {
		deny(http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	// Then hold what the body costs from here on: itself, or what checking
	// it takes. A body no budget could check is refused for good, not as
	// a retry.
	need := callFloor + int64(len(body))
	if op.Body != nil {
		need = bodyCost(body)
	}
	if need > p.share {
		deny(http.StatusRequestEntityTooLarge, "body too costly to check")
		return
	}
	if !p.resize(machine, need-held) {
		deny(http.StatusTooManyRequests, "too many requests in flight")
		return
	}
	held = need
	if op.Body != nil {
		if body, err = checkApart(op.Body, body, labelOf() == LabelPublic); err != nil {
			deny(http.StatusForbidden, err.Error())
			return
		}
	}
	holder := p.holders[a.Credential]
	var sec vault.Secret
	if holder == nil {
		var ok bool
		if sec, ok = p.vault.Secret(a.Credential); !ok {
			deny(http.StatusServiceUnavailable, "credential not in vault")
			return
		}
		// The redactor was built at request start; a rotation since then
		// would inject a key it does not know. Redact the key actually sent.
		red = red.(*vault.Redactor).With([]byte(sec.Reveal()))
	}

	// Only a routed model call to a declared inference operation may reach
	// a pinned compute host or hosted route; nothing else gets a network
	// exception (DEV-2).
	ctx := r.Context()
	if op.Inference {
		ctx = netguard.WithPurpose(ctx, netguard.PurposeModelCall)
	}
	up, err := http.NewRequestWithContext(ctx, op.Method, "https://"+a.Host+upPath, bytes.NewReader(body))
	if err != nil {
		deny(http.StatusBadRequest, "bad request")
		return
	}
	for _, h := range append(append([]string(nil), baseRequestHeaders...), a.RequestHeaders...) {
		if vs := r.Header.Values(h); len(vs) > 0 {
			up.Header[http.CanonicalHeaderKey(h)] = append([]string(nil), vs...)
		}
	}
	if op.Body != nil {
		// The body is the proxy's own JSON encoding; say so, whatever the
		// guest claimed.
		up.Header.Set("Content-Type", "application/json")
	}
	up.Header.Set("Accept-Encoding", "identity")
	rt := p.rt
	if op.Inference {
		rt = p.rtModel
	}
	if holder != nil {
		rt = holder
		up.Header.Del(LabelHeader)
		if labelOf() == LabelPublic {
			up.Header.Set(LabelHeader, LabelPublic)
		}
	} else {
		up.Header.Set(a.Inject.Header, a.Inject.Prefix+sec.Reveal())
	}

	p.charge(machine, 1, int64(len(body)))
	resp, err := rt.RoundTrip(up)
	if errors.Is(err, netguard.ErrDenied) {
		// The destination is a home-network address, or a pinned host
		// whose key changed: refused, journaled, and no request sent.
		deny(http.StatusForbidden, "destination refused by the home-network address policy")
		return
	}
	if err != nil {
		ev.Allowed, ev.Status, ev.Reason = true, http.StatusBadGateway, "upstream unreachable"
		audit.Egress(ev)
		http.Error(w, "egress: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// The redactor reads plain bytes only. A compressed body would pass it
	// unread and be inflated by the guest.
	if encoded(resp.Header) {
		ev.Allowed, ev.Status, ev.Reason = true, http.StatusBadGateway, "encoded response refused"
		audit.Egress(ev)
		http.Error(w, "egress: encoded response refused", http.StatusBadGateway)
		return
	}

	// CRED-5t: neither a refusal of the login nor an exchange's response
	// reaches the guest unless it is in its declared, swapped shape.
	if op.refused(resp.StatusCode) {
		p.stop(a.Name, ReasonLoginRefused)
		ev.Status = resp.StatusCode
		ev.Reason = ReasonLoginRefused
		audit.Egress(ev)
		w.Header().Set(DeniedHeader, "1")
		http.Error(w, "egress denied: route stopped: "+ReasonLoginRefused, http.StatusServiceUnavailable)
		return
	}
	if op.Response != nil {
		var out []byte
		var err error
		if holder != nil {
			out, err = heldExchange(resp)
		} else {
			var commit func() error
			out, commit, err = op.Response.swap(resp, a.Name, p.xch.swapper)
			if err == nil {
				err = commit()
			}
		}
		if err != nil {
			ev.Status = resp.StatusCode
			ev.Reason = ReasonUnswappable
			// An error status is the provider failing, not answering in
			// another shape; anything else may carry credentials the
			// proxy cannot find.
			if resp.StatusCode < 400 || resp.Header.Get(HolderDropHeader) == DropUnswappable {
				p.stop(a.Name, ReasonUnswappable)
			} else {
				ev.Reason = "credential exchange answered with an error; dropped"
			}
			audit.Egress(ev)
			w.Header().Set(DeniedHeader, "1")
			http.Error(w, "egress denied: "+ev.Reason, http.StatusBadGateway)
			return
		}
		p.charge(machine, 0, int64(len(out)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		ev.Allowed, ev.Status = true, http.StatusOK
		audit.Egress(ev)
		rw := red.Writer(w)
		rw.Write(out)
		rw.Close()
		return
	}

	for _, h := range append(append([]string(nil), baseResponseHeaders...), a.ResponseHeaders...) {
		for _, v := range resp.Header.Values(h) {
			w.Header().Add(h, string(red.Redact([]byte(v))))
		}
	}
	w.WriteHeader(resp.StatusCode)
	ev.Allowed, ev.Status = true, resp.StatusCode
	audit.Egress(ev)

	rw := red.Writer(w)
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	var n64 int64
	defer func() { p.charge(machine, 0, n64) }()
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			n64 += int64(n)
			if _, err := rw.Write(buf[:n]); err != nil {
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
	rw.Close()
	if fl != nil {
		fl.Flush()
	}
}

// HolderDropHeader is set by a holder on the 502 with which it drops an
// exchange response it could not swap; its value says why.
const HolderDropHeader = "Agentos-Holder-Drop"

// HolderDropHeader values.
const (
	// DropUnswappable: the exchange answered outside its declared shape,
	// so the response may carry credentials nobody can find. The route
	// stops (CRED-5t).
	DropUnswappable = "unswappable"
	// DropExchangeError: the exchange answered with an error status.
	DropExchangeError = "exchange-error"
)

// redactor returns the redactor for this request: the vault's, or the
// hashed one when holders keep the secrets.
func (p *Proxy) redactor() (Redactor, error) {
	if p.vault == nil {
		return p.redact()
	}
	return p.vault.Redactor()
}

// heldExchange reads an exchange response a holder already swapped. Only
// a 200 with no drop is forwarded.
func heldExchange(resp *http.Response) ([]byte, error) {
	if resp.StatusCode != http.StatusOK || resp.Header.Get(HolderDropHeader) != "" {
		return nil, errors.New("holder dropped the exchange")
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, MaxExchangeResponse+1))
	if err != nil || len(out) > MaxExchangeResponse {
		return nil, errors.New("exchange response too large")
	}
	return out, nil
}

// checkApart runs a body check on a goroutine of its own. Checking a deeply
// nested body grows the stack it runs on by megabytes; a goroutine that
// exits frees its stack, while a keep-alive connection's goroutine would
// keep it after release returned the reservation. A panic in the check is
// raised again here, so it fails only this request.
func checkApart(b *BodyRule, body []byte, public bool) ([]byte, error) {
	type result struct {
		out      []byte
		err      error
		panicked bool
		value    any
	}
	done := make(chan result, 1)
	go func() {
		r := result{panicked: true}
		defer func() {
			if r.panicked {
				r.value = recover()
			}
			done <- r
		}()
		r.out, r.err = b.apply(body, public)
		r.panicked = false
	}()
	r := <-done
	if r.panicked {
		panic(r.value)
	}
	return r.out, r.err
}

var (
	errNotObject = errors.New("body is not a JSON object")
	errTrailing  = errors.New("trailing data after JSON body")
)

// apply checks a JSON object body against the rule and returns the body to
// forward: the proxy's own encoding of what it checked. It walks the body
// in place rather than decoding it (K18g-1): it keeps four bytes per object
// member and one frame per level of nesting, and writes the output in one
// buffer the size of the body. It accepts and refuses what decoding into a
// map[string]any did (K18g-2): duplicate keys compare decoded and the last
// wins, invalid UTF-8 reads as U+FFFD, and a check reads only the members
// that win. The output carries every member that wins, as the body spelled
// it, with the rule's Set in place of the body's own.
func (b *BodyRule) apply(body []byte, public bool) ([]byte, error) {
	if len(body) >= 1<<30 {
		// A member's position must fit its record.
		return nil, errors.New("body too large to check")
	}
	colons, invalid, deepest := bodyShape(body)
	w := &walk{
		b:       body,
		members: make([]uint32, 0, colons),
		frames:  make([]frame, 0, min(deepest, maxDepth)+1),
	}
	w.order = func(x, y uint32) int {
		if c := w.cmpStr(int(x>>2), int(y>>2)); c != 0 {
			return c
		}
		return cmp.Compare(x, y)
	}
	i := skipWS(body, 0)
	if i >= len(body) || body[i] != '{' {
		return nil, errNotObject
	}
	end := w.parse(i)
	if end < 0 {
		return nil, errNotObject
	}
	if skipWS(body, end) != len(body) {
		return nil, errTrailing
	}
	for _, k := range b.DenyKeys {
		if w.find(k) >= 0 {
			return nil, fmt.Errorf("body key %q not allowed", k)
		}
	}
	strict := !(public && b.PublicMayFetch)
	if strict {
		for _, k := range b.ServerToolKeys {
			if w.find(k) >= 0 {
				return nil, fmt.Errorf("body key %q needs a public machine", k)
			}
		}
		if w.topCand {
			return nil, errors.New("remote content sources need a public machine; send content inline")
		}
	}
	if t := w.find("tools"); t >= 0 {
		j := w.valueAt(int(w.top[t] >> 2))
		if body[j] != '[' {
			return nil, errors.New("tools is not a list")
		}
		for j = skipWS(body, j+1); body[j] != ']'; {
			if body[j] != '{' {
				return nil, errors.New("tool entry is not an object")
			}
			if strict && w.providerTool(j) {
				return nil, errors.New("provider-side tools need a public machine")
			}
			if j = skipWS(body, w.skipValue(j)); body[j] == ',' {
				j = skipWS(body, j+1)
			}
		}
	}

	// The members the rule sets, and with StreamUsage on a streamed call
	// stream_options with include_usage, replace the body's own.
	streamOn := false
	if b.StreamUsage {
		if v, ok := b.Set["stream"]; ok {
			streamOn = v == true
		} else if s := w.find("stream"); s >= 0 {
			streamOn = bytes.HasPrefix(body[w.valueAt(int(w.top[s]>>2)):], []byte("true"))
		}
	}
	extra, liveSO := b.Set, -1
	if streamOn {
		extra = maps.Clone(b.Set)
		if extra == nil {
			extra = map[string]any{}
		}
		if v, ok := b.Set["stream_options"]; ok {
			// A copy: the rule is shared by every request.
			m, _ := v.(map[string]any)
			so := maps.Clone(m)
			if so == nil {
				so = map[string]any{}
			}
			so["include_usage"] = true
			extra["stream_options"] = so
		} else if s := w.find("stream_options"); s >= 0 && body[w.valueAt(int(w.top[s]>>2))] == '{' {
			liveSO = w.valueAt(int(w.top[s] >> 2))
		} else {
			extra["stream_options"] = map[string]any{"include_usage": true}
		}
	}
	var inner []byte
	if len(extra) > 0 {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(extra); err != nil {
			return nil, err
		}
		inner = bytes.TrimSuffix(buf.Bytes(), []byte("}\n"))[1:]
	}

	out := make([]byte, 0, len(body)+2*invalid+len(inner)+64)
	out = append(out, '{')
	comma := func() {
		if out[len(out)-1] != '{' {
			out = append(out, ',')
		}
	}
	for _, m := range w.top {
		k := int(m >> 2)
		if w.keyIn(k, b.Set) || (streamOn && w.keyIs(k, "stream_options")) {
			continue
		}
		comma()
		out, _ = w.appendString(out, k)
		out = append(out, ':')
		out = w.emit(out, w.valueAt(k), "")
	}
	if len(inner) > 0 {
		comma()
		out = append(out, inner...)
	}
	if liveSO >= 0 {
		comma()
		out = append(out, `"stream_options":`...)
		out = w.emit(out, liveSO, "include_usage")
		out = out[:len(out)-1]
		comma()
		out = append(out, `"include_usage":true}`...)
	}
	return append(out, '}'), nil
}

// A member record is the position of its key's opening quote, shifted left
// two, with these flags.
const (
	mCand = 1 << iota // its value holds a remote content source
	mURL              // its key is in urlKeys
)

// frame is one open object or array of the walk.
type frame struct {
	base int  // an object's first member in walk.members
	obj  bool // an object, not an array
	url  bool // an array whose strings are content sources (under a urlKeys key)
	cand bool // an array holding a remote content source; in emit, no member written yet
}

// walk is one pass over a body that is checked in place.
type walk struct {
	b       []byte
	members []uint32 // the members of the open objects
	frames  []frame
	// dead marks the keys of nested members a later duplicate replaced, by
	// position/4: keys lie at least four bytes apart.
	dead    []uint64
	top     []uint32 // the top object's members that win, sorted by key
	topCand bool     // whether they hold a remote content source
	order   func(x, y uint32) int
}

// parse reads the value at i, which opens the top object, and returns
// where it ends, or -1 if the JSON is not well formed or nests too deep.
// It records each object's members, and as each object closes, which win
// and whether they hold a remote content source (remoteSource's rule).
func (w *walk) parse(i int) int {
	b := w.b
	for {
		// A value starts at i.
		if i >= len(b) {
			return -1
		}
		cand := false
		switch c := b[i]; c {
		case '{', '[':
			if len(w.frames) >= maxDepth {
				return -1
			}
			w.frames = append(w.frames, frame{base: len(w.members), obj: c == '{', url: c == '[' && w.ctx()})
			if i = skipWS(b, i+1); i < len(b) && b[i] == c+2 { // '}' and ']' follow '{' and '[' by two
				i++
				cand = w.close()
			} else if c == '[' {
				continue
			} else if i = w.member(i); i < 0 {
				return -1
			} else {
				continue
			}
		case '"':
			end := scanString(b, i)
			if end < 0 {
				return -1
			}
			cand = w.ctx() && !w.isData(i)
			i = end
		default:
			if i = scalarEnd(b, i); i < 0 {
				return -1
			}
		}
		// A value ended at i.
		for {
			if len(w.frames) == 0 {
				return i
			}
			f := &w.frames[len(w.frames)-1]
			if f.obj {
				if cand {
					w.members[len(w.members)-1] |= mCand
				}
			} else {
				f.cand = f.cand || cand
			}
			if i = skipWS(b, i); i >= len(b) {
				return -1
			}
			if b[i] == ',' {
				i = skipWS(b, i+1)
				if f.obj {
					if i = w.member(i); i < 0 {
						return -1
					}
				}
				break
			}
			if f.obj && b[i] != '}' || !f.obj && b[i] != ']' {
				return -1
			}
			i++
			cand = w.close()
		}
	}
}

// member records the member whose key is at i and returns where its value
// starts, or -1.
func (w *walk) member(i int) int {
	b := w.b
	if i >= len(b) || b[i] != '"' {
		return -1
	}
	j := scanString(b, i)
	if j < 0 {
		return -1
	}
	if j = skipWS(b, j); j >= len(b) || b[j] != ':' {
		return -1
	}
	m := uint32(i) << 2
	if w.urlKey(i) {
		m |= mURL
	}
	w.members = append(w.members, m)
	return skipWS(b, j+1)
}

// ctx reports whether a string value here is a content source.
func (w *walk) ctx() bool {
	if len(w.frames) == 0 {
		return false
	}
	if f := w.frames[len(w.frames)-1]; !f.obj {
		return f.url
	}
	return w.members[len(w.members)-1]&mURL != 0
}

// close ends the innermost open value and reports whether it holds a
// remote content source.
func (w *walk) close() bool {
	f := w.frames[len(w.frames)-1]
	w.frames = w.frames[:len(w.frames)-1]
	if !f.obj {
		return f.cand
	}
	ms := w.members[f.base:]
	if len(ms) > 1 {
		slices.SortFunc(ms, w.order)
	}
	toolUse := false
	if t := w.findIn(ms, "type"); t >= 0 {
		toolUse = w.strIs(w.valueAt(int(ms[t]>>2)), "tool_use")
	}
	top := len(w.frames) == 0
	cand, n := false, 0
	for k, m := range ms {
		pos := int(m >> 2)
		if k+1 < len(ms) && w.cmpStr(pos, int(ms[k+1]>>2)) == 0 {
			if !top {
				w.setDead(pos)
			}
			continue
		}
		if m&mCand != 0 && !w.keyIs(pos, "input_schema") && !w.keyIs(pos, "parameters") &&
			!(toolUse && w.keyIs(pos, "input")) {
			cand = true
		}
		ms[n] = m
		n++
	}
	if top {
		w.top, w.topCand = ms[:n], cand
	} else {
		w.members = w.members[:f.base]
	}
	return cand
}

func (w *walk) setDead(pos int) {
	if w.dead == nil {
		w.dead = make([]uint64, len(w.b)/256+1)
	}
	w.dead[pos>>8] |= 1 << (pos >> 2 & 63)
}

func (w *walk) isDead(pos int) bool {
	return w.dead != nil && w.dead[pos>>8]&(1<<(pos>>2&63)) != 0
}

// find returns the index in top of the member whose key is name, or -1.
func (w *walk) find(name string) int { return w.findIn(w.top, name) }

// findIn returns the index of the last member of ms, sorted by key, whose
// key is name, or -1.
func (w *walk) findIn(ms []uint32, name string) int {
	if !utf8.ValidString(name) {
		return -1 // a decoded key is valid UTF-8
	}
	k := sort.Search(len(ms), func(k int) bool { return w.cmpName(int(ms[k]>>2), name) > 0 }) - 1
	if k < 0 || w.cmpName(int(ms[k]>>2), name) != 0 {
		return -1
	}
	return k
}

func (w *walk) keyIs(pos int, name string) bool { return w.cmpName(pos, name) == 0 }

func (w *walk) keyIn(pos int, set map[string]any) bool {
	for k := range set {
		if w.keyIs(pos, k) {
			return true
		}
	}
	return false
}

// strIs reports whether a value at i is the string s.
func (w *walk) strIs(i int, s string) bool { return w.b[i] == '"' && w.cmpName(i, s) == 0 }

// cmpStr compares the decoded strings whose opening quotes are at i and j.
func (w *walk) cmpStr(i, j int) int {
	b := w.b
	i, j = i+1, j+1
	for {
		if x, y := b[i], b[j]; x < utf8.RuneSelf && y < utf8.RuneSelf && x != '\\' && y != '\\' && x != '"' && y != '"' {
			if x != y {
				return cmp.Compare(x, y)
			}
			i, j = i+1, j+1
			continue
		}
		x, ni := w.strRune(i)
		y, nj := w.strRune(j)
		if x != y || x < 0 {
			return cmp.Compare(x, y)
		}
		i, j = ni, nj
	}
}

// cmpName compares the decoded string whose opening quote is at i with
// name, which is valid UTF-8.
func (w *walk) cmpName(i int, name string) int {
	i++
	for _, y := range name {
		x, ni := w.strRune(i)
		if x != y {
			return cmp.Compare(x, y)
		}
		i = ni
	}
	if x, _ := w.strRune(i); x >= 0 {
		return 1
	}
	return 0
}

// strRune decodes the rune of a well-formed string at i as encoding/json
// does, returning it and where the next starts, or -1 at the closing quote.
func (w *walk) strRune(i int) (rune, int) {
	b := w.b
	switch c := b[i]; {
	case c == '"':
		return -1, i
	case c < utf8.RuneSelf && c != '\\':
		return rune(c), i + 1
	case c >= utf8.RuneSelf:
		r, n := utf8.DecodeRune(b[i:])
		return r, i + n
	}
	switch e := b[i+1]; e {
	case 'b':
		return '\b', i + 2
	case 'f':
		return '\f', i + 2
	case 'n':
		return '\n', i + 2
	case 'r':
		return '\r', i + 2
	case 't':
		return '\t', i + 2
	case 'u':
	default:
		return rune(e), i + 2 // " \ /
	}
	r := hex4(b[i+2:])
	if !utf16.IsSurrogate(r) {
		return r, i + 6
	}
	if i+12 <= len(b) && b[i+6] == '\\' && b[i+7] == 'u' && isHex4(b[i+8:]) {
		if d := utf16.DecodeRune(r, hex4(b[i+8:])); d != unicode.ReplacementChar {
			return d, i + 12
		}
	}
	return unicode.ReplacementChar, i + 6
}

func isHex4(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	for _, c := range b[:4] {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

func hex4(b []byte) rune {
	var r rune
	for _, c := range b[:4] {
		switch {
		case c <= '9':
			c -= '0'
		case c >= 'a':
			c -= 'a' - 10
		default:
			c -= 'A' - 10
		}
		r = r<<4 | rune(c)
	}
	return r
}

// isData reports whether the string at i, past leading white space, starts
// with data: in any case: an inline source.
func (w *walk) isData(i int) bool {
	i++
	r, n := w.strRune(i)
	for r >= 0 && unicode.IsSpace(r) {
		r, n = w.strRune(n)
	}
	for _, want := range "data:" {
		if r < 0 || unicode.ToLower(r) != want {
			return false
		}
		r, n = w.strRune(n)
	}
	return true
}

// urlKey reports whether the key at i is in urlKeys.
func (w *walk) urlKey(i int) bool {
	var buf [16]byte
	n := 0
	for r, j := w.strRune(i + 1); r >= 0; r, j = w.strRune(j) {
		if r >= utf8.RuneSelf || n == len(buf) {
			return false
		}
		buf[n] = byte(r)
		n++
	}
	return urlKeys[string(buf[:n])]
}

// providerTool reports whether the tool entry object at i has a type other
// than function or custom.
func (w *walk) providerTool(i int) bool {
	b := w.b
	if i = skipWS(b, i+1); b[i] == '}' {
		return false
	}
	for {
		v := w.valueAt(i)
		if !w.isDead(i) && w.keyIs(i, "type") {
			return !w.strIs(v, "function") && !w.strIs(v, "custom")
		}
		if i = skipWS(b, w.skipValue(v)); b[i] != ',' {
			return false
		}
		i = skipWS(b, i+1)
	}
}

// valueAt returns where the value of the member whose key is at i starts.
func (w *walk) valueAt(i int) int {
	return skipWS(w.b, skipWS(w.b, strEnd(w.b, i))+1)
}

// skipValue returns where the well-formed value at i ends.
func (w *walk) skipValue(i int) int {
	b := w.b
	switch b[i] {
	case '"':
		return strEnd(b, i)
	case '{', '[':
	default:
		return scalarEnd(b, i)
	}
	depth := 0
	for ; ; i++ {
		switch b[i] {
		case '"':
			i = strEnd(b, i) - 1
		case '{', '[':
			depth++
		case '}', ']':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
}

// emit appends the well-formed value at i without white space, leaving out
// members a duplicate replaced and, of its own members, any keyed skip.
func (w *walk) emit(out []byte, i int, skip string) []byte {
	b, st := w.b, w.frames[:0]
	const (
		value = iota
		key
		after
	)
	for mode := value; ; {
		switch mode {
		case value:
			switch c := b[i]; c {
			case '"':
				out, i = w.appendString(out, i)
				mode = after
			case '{', '[':
				out = append(out, c)
				st = append(st, frame{obj: c == '{', cand: true})
				if i = skipWS(b, i+1); c == '{' {
					mode = key
				} else if b[i] == ']' {
					mode = after
				}
			default:
				j := scalarEnd(b, i)
				out, i = append(out, b[i:j]...), j
				mode = after
			}
		case key:
			if b[i] == '}' {
				out = append(out, '}')
				st, i, mode = st[:len(st)-1], i+1, after
				break
			}
			v := w.valueAt(i)
			if w.isDead(i) || skip != "" && len(st) == 1 && w.keyIs(i, skip) {
				if i = skipWS(b, w.skipValue(v)); b[i] == ',' {
					i = skipWS(b, i+1)
				}
				break
			}
			if f := &st[len(st)-1]; !f.cand {
				out = append(out, ',')
			} else {
				f.cand = false
			}
			out, _ = w.appendString(out, i)
			out = append(out, ':')
			i, mode = v, value
		case after:
			if len(st) == 0 {
				return out
			}
			i = skipWS(b, i)
			if b[i] != ',' {
				out = append(out, b[i])
				st, i = st[:len(st)-1], i+1
			} else if i = skipWS(b, i+1); st[len(st)-1].obj {
				mode = key
			} else {
				out = append(out, ',')
				mode = value
			}
		}
	}
}

// appendString appends the well-formed string at i as it came, but for
// each invalid UTF-8 byte, which becomes U+FFFD as the decoder read it, and
// returns where the string ends.
func (w *walk) appendString(out []byte, i int) ([]byte, int) {
	b := w.b
	s := i
	for j := i + 1; ; {
		switch c := b[j]; {
		case c == '"':
			return append(out, b[s:j+1]...), j + 1
		case c == '\\' && b[j+1] == 'u':
			j += 6
		case c == '\\':
			j += 2
		case c < utf8.RuneSelf:
			j++
		default:
			r, n := utf8.DecodeRune(b[j:])
			if r == utf8.RuneError && n == 1 {
				out = append(append(out, b[s:j]...), "�"...)
				s = j + 1
			}
			j += n
		}
	}
}

// scanString returns where the string at i ends, or -1 if it is not well
// formed: unescaped control bytes or a bad escape.
func scanString(b []byte, i int) int {
	for j := i + 1; j < len(b); {
		switch c := b[j]; {
		case c == '"':
			return j + 1
		case c < 0x20:
			return -1
		case c != '\\':
			j++
		case j+1 >= len(b):
			return -1
		case strings.IndexByte(`"\/bfnrt`, b[j+1]) >= 0:
			j += 2
		case b[j+1] == 'u' && isHex4(b[j+2:]):
			j += 6
		default:
			return -1
		}
	}
	return -1
}

// strEnd returns where the well-formed string at i ends.
func strEnd(b []byte, i int) int {
	for j := i + 1; ; j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
}

// scalarEnd returns where the number or literal at i ends, or -1.
func scalarEnd(b []byte, i int) int {
	for _, lit := range []string{"true", "false", "null"} {
		if b[i] == lit[0] {
			if !bytes.HasPrefix(b[i:], []byte(lit)) {
				return -1
			}
			return i + len(lit)
		}
	}
	digits := func(j int) int {
		for j < len(b) && '0' <= b[j] && b[j] <= '9' {
			j++
		}
		return j
	}
	j := i
	if b[j] == '-' {
		j++
	}
	switch {
	case j >= len(b):
		return -1
	case b[j] == '0':
		j++
	case '1' <= b[j] && b[j] <= '9':
		j = digits(j)
	default:
		return -1
	}
	if j < len(b) && b[j] == '.' {
		if k := digits(j + 1); k == j+1 {
			return -1
		} else {
			j = k
		}
	}
	if j < len(b) && (b[j] == 'e' || b[j] == 'E') {
		j++
		if j < len(b) && (b[j] == '+' || b[j] == '-') {
			j++
		}
		if k := digits(j); k == j {
			return -1
		} else {
			j = k
		}
	}
	return j
}

func skipWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// encoded reports whether any Content-Encoding value, in any header line or
// comma-separated list, is other than identity.
func encoded(h http.Header) bool {
	for _, line := range h.Values("Content-Encoding") {
		for _, v := range strings.Split(line, ",") {
			if v = strings.TrimSpace(v); v != "" && !strings.EqualFold(v, "identity") {
				return true
			}
		}
	}
	return false
}

// urlKeys name the fields through which provider APIs take a content
// source by address: OpenAI image_url parts and Anthropic image and
// document sources ({"type":"url","url":...}), plus likely variants.
var urlKeys = map[string]bool{
	"url": true, "image_url": true, "file_url": true, "document_url": true,
	"audio_url": true, "video_url": true, "server_url": true,
}

// remoteSource rejects any content source given by address rather than
// inline: a string under a urlKeys key that is not a data: URL. It does not
// look inside JSON schemas (input_schema, parameters) or the arguments of a
// client tool call the guest already ran (tool_use input), where a "url"
// property is the guest's own data, not a provider fetch.
func remoteSource(v any, key string) error {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			if k == "input_schema" || k == "parameters" || (k == "input" && t["type"] == "tool_use") {
				continue
			}
			if err := remoteSource(c, k); err != nil {
				return err
			}
		}
	case []any:
		for _, c := range t {
			if err := remoteSource(c, key); err != nil {
				return err
			}
		}
	case string:
		if urlKeys[key] && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "data:") {
			return errors.New("remote content sources need a public machine; send content inline")
		}
	}
	return nil
}

// deadlineWriter renews the connection's write deadline before every write, so a client that
// stops reading a streamed reply fails the next write within d instead of holding its slot and
// reserved bytes for as long as it likes (CRED-8, K18). A deadline a handler inside sets through
// http.ResponseController (a nested deadlineWriter, a worker route's own) holds when it is the
// earlier one, so wrapping never loosens it.
type deadlineWriter struct {
	http.ResponseWriter
	rc  *http.ResponseController
	d   time.Duration
	set time.Time // the deadline a handler inside last set; zero for none
}

func newDeadlineWriter(w http.ResponseWriter, d time.Duration) http.ResponseWriter {
	if d <= 0 {
		return w
	}
	if dw, ok := w.(*deadlineWriter); ok && dw.d <= d {
		return w
	}
	return &deadlineWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: d}
}

// renew moves the deadline d past now, or to the handler's own if that is earlier; a writer
// without deadlines (a test recorder) ignores it.
func (w *deadlineWriter) renew() { _ = w.rc.SetWriteDeadline(w.until()) }

func (w *deadlineWriter) until() time.Time {
	t := time.Now().Add(w.d)
	if !w.set.IsZero() && w.set.Before(t) {
		return w.set
	}
	return t
}

// SetWriteDeadline is what http.ResponseController calls on this writer: it records the
// handler's deadline and applies the earlier of it and d from now.
func (w *deadlineWriter) SetWriteDeadline(t time.Time) error {
	w.set = t
	return w.rc.SetWriteDeadline(w.until())
}

func (w *deadlineWriter) WriteHeader(code int) { w.renew(); w.ResponseWriter.WriteHeader(code) }

func (w *deadlineWriter) Write(b []byte) (int, error) { w.renew(); return w.ResponseWriter.Write(b) }

func (w *deadlineWriter) Flush() {
	w.renew()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *deadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WithWriteDeadline wraps h so each write of its reply must finish within d of starting (see
// deadlineWriter). Servers that serve the proxy set it in place of a whole-reply WriteTimeout,
// which would cut long streamed replies that the client is reading.
func WithWriteDeadline(h http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dw := newDeadlineWriter(w, d)
		h.ServeHTTP(dw, r)
		if x, ok := dw.(*deadlineWriter); ok {
			x.renew()
		}
	})
}
