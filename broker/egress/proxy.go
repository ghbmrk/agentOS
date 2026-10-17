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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

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
// TestBodyCostBoundsApply measures against BodyRule.apply's allocations
// for the costliest body shapes.
const (
	// costPerByte covers the body, the decoder's copy of it, the decoded
	// strings and the re-encoded output, with the buffers' growth.
	costPerByte = 16
	// costPerHigh covers a byte >= 0x80 that decodes and re-encodes as
	// three (an invalid UTF-8 byte becomes U+FFFD).
	costPerHigh = 28
	// costPerObject is one decoded map[string]any with its first entries.
	costPerObject = 640
	// costPerToken is one value or key: its interface, slice or map slot
	// and the slice and map growth that holds it.
	costPerToken = 160
	// callFloor is what any request holds besides its body: buffers,
	// headers and the response copy.
	callFloor = 64 << 10
)

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
	// every machine; zero means DefaultInFlightBytes.
	InFlightBytes int64
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
	cap      Cap
	now      func() time.Time
	xch      exchangeHooks

	mu       sync.Mutex
	reserved int64 // bytes reserved by requests in flight, every machine
	usage    map[string]*machineUsage
	stops    RouteStops        // adapter -> why its route stopped (CRED-5t)
	held     map[string]string // adapter -> a stop stops could not record
}

type machineUsage struct {
	inFlight int
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
		adapters: map[string]Adapter{},
		grants:   map[string]map[string]bool{},
		granted:  cfg.Granted,
		vault:    cfg.Vault,
		holders:  cfg.Holders,
		redact:   cfg.Redaction,
		rt:       cfg.Transport,
		audit:    cfg.Audit,
		maxBody:  cfg.MaxBody,
		maxConc:  cfg.MaxConcurrent,
		budget:   cfg.InFlightBytes,
		cap:      cfg.Cap,
		now:      cfg.Now,
		usage:    map[string]*machineUsage{},
		labelOf:  cfg.Label,
		xch:      exchangeHooks{swapper: cfg.Swapper, routeFailed: cfg.RouteFailed},
		stops:    cfg.Stops,
		held:     map[string]string{},
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

// admit reserves n bytes of the in-flight budget and a per-machine
// concurrency slot and checks the cap; release returns both.
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
	case u.inFlight >= p.maxConc:
		return "too many requests in flight", false
	case p.cap.Requests > 0 && u.requests >= p.cap.Requests:
		return "request cap reached", false
	case p.cap.Bytes > 0 && u.bytes >= p.cap.Bytes:
		return "byte cap reached", false
	}
	u.inFlight++
	p.reserved += n
	return "", true
}

// resize changes an admitted request's reservation by d bytes. A shrink
// always succeeds; a growth fails, changing nothing, when the budget lacks
// the room.
func (p *Proxy) resize(d int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d > 0 && p.reserved+d > p.budget {
		return false
	}
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
	p.usage[machine].inFlight--
	p.reserved -= n
	p.mu.Unlock()
}

// readCost is what reading a body of up to n bytes can hold: io.ReadAll's
// buffer, which grows by copying, so the old and the new buffer are live
// together.
func readCost(n int64) int64 { return callFloor + 3*n }

// bodyCost is what BodyRule.apply can hold for body at its peak, from one
// pass over the body that counts what decoding it allocates per unit.
func bodyCost(body []byte) int64 {
	var high, objects, tokens int64
	in, esc := false, false
	for _, c := range body {
		if c >= 0x80 {
			high++
		}
		switch {
		case esc:
			esc = false
		case in:
			esc, in = c == '\\', c != '"'
		case c == '"':
			in = true
		case c == '{':
			objects++
			tokens++
		case c == '[' || c == ',' || c == ':':
			tokens++
		}
	}
	return callFloor + costPerByte*int64(len(body)) + costPerHigh*high +
		costPerObject*objects + costPerToken*tokens
}

func (p *Proxy) serve(machine, grantsOf string, labelOf func() string, audit Auditor, w http.ResponseWriter, r *http.Request) {
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
	if need > p.budget {
		deny(http.StatusRequestEntityTooLarge, "body too costly to check")
		return
	}
	if !p.resize(need - held) {
		deny(http.StatusTooManyRequests, "too many requests in flight")
		return
	}
	held = need
	if op.Body != nil {
		if body, err = op.Body.apply(body, labelOf() == LabelPublic); err != nil {
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

// apply checks a JSON object body against the rule and returns the body to
// forward: the proxy's own encoding of what it checked.
func (b *BodyRule) apply(body []byte, public bool) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, errors.New("body is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON body")
	}
	for _, k := range b.DenyKeys {
		if _, ok := obj[k]; ok {
			return nil, fmt.Errorf("body key %q not allowed", k)
		}
	}
	strict := !(public && b.PublicMayFetch)
	if strict {
		for _, k := range b.ServerToolKeys {
			if _, ok := obj[k]; ok {
				return nil, fmt.Errorf("body key %q needs a public machine", k)
			}
		}
		if err := remoteSource(obj, ""); err != nil {
			return nil, err
		}
	}
	if t, ok := obj["tools"]; ok {
		tools, ok := t.([]any)
		if !ok {
			return nil, errors.New("tools is not a list")
		}
		for _, e := range tools {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, errors.New("tool entry is not an object")
			}
			if typ, has := m["type"]; has && typ != "function" && typ != "custom" && strict {
				return nil, errors.New("provider-side tools need a public machine")
			}
		}
	}
	for k, v := range b.Set {
		obj[k] = v
	}
	if b.StreamUsage && obj["stream"] == true {
		so, _ := obj["stream_options"].(map[string]any)
		if so == nil {
			so = map[string]any{}
		}
		so["include_usage"] = true
		obj["stream_options"] = so
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
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
