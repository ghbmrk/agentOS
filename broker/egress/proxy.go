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
// Not yet here (see ASSUMPTIONS.md): the ADP-10 verb-class and intent check
// before forwarding, and OP-8 metering.
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
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// DefaultMaxBody caps a request body, in bytes.
const DefaultMaxBody = 8 << 20

// DefaultMaxConcurrent caps one machine's requests in flight.
const DefaultMaxConcurrent = 4

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
	Vault  Secrets
	Audit  Auditor
	// Transport sends upstream requests; nil means a fresh http.Transport
	// with no proxy from the environment and bounded connect, handshake,
	// and response-header waits.
	Transport http.RoundTripper
	// MaxBody caps request bodies; zero means DefaultMaxBody.
	MaxBody int64
	// MaxConcurrent caps one machine's requests in flight; zero means
	// DefaultMaxConcurrent.
	MaxConcurrent int
	// Cap is applied to each machine separately.
	Cap Cap
	// Label returns a machine's REV-5 data label. Nil, or any answer other
	// than LabelPublic, is treated as private: provider-side tools denied.
	Label func(machine string) string
	Now   func() time.Time
}

// LabelPublic is the REV-5 label under which a machine may use
// provider-side tools.
const LabelPublic = "public"

// Proxy is the credentialed egress proxy.
type Proxy struct {
	labelOf  func(string) string
	adapters map[string]Adapter
	grants   map[string]map[string]bool
	vault    Secrets
	rt       http.RoundTripper
	audit    Auditor
	maxBody  int64
	maxConc  int
	cap      Cap
	now      func() time.Time

	mu    sync.Mutex
	usage map[string]*machineUsage
}

type machineUsage struct {
	inFlight int
	requests int64
	bytes    int64
}

// New validates every declaration and grant and returns a proxy.
func New(cfg Config) (*Proxy, error) {
	if cfg.Vault == nil {
		return nil, errors.New("egress: vault required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("egress: auditor required")
	}
	p := &Proxy{
		adapters: map[string]Adapter{},
		grants:   map[string]map[string]bool{},
		vault:    cfg.Vault,
		rt:       cfg.Transport,
		audit:    cfg.Audit,
		maxBody:  cfg.MaxBody,
		maxConc:  cfg.MaxConcurrent,
		cap:      cfg.Cap,
		now:      cfg.Now,
		usage:    map[string]*machineUsage{},
		labelOf:  cfg.Label,
	}
	for _, a := range cfg.Adapters {
		if err := a.validate(); err != nil {
			return nil, fmt.Errorf("egress: %v", err)
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
		p.rt = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Minute,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	if p.maxBody <= 0 {
		p.maxBody = DefaultMaxBody
	}
	if p.maxConc <= 0 {
		p.maxConc = DefaultMaxConcurrent
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.serve(machine, w, r) })
}

// admit takes a concurrency slot and checks the cap; release returns the
// slot and charges bytes.
func (p *Proxy) admit(machine string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
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
	return "", true
}

func (p *Proxy) charge(machine string, requests, bytes int64) {
	p.mu.Lock()
	u := p.usage[machine]
	u.requests += requests
	u.bytes += bytes
	p.mu.Unlock()
}

func (p *Proxy) release(machine string) {
	p.mu.Lock()
	p.usage[machine].inFlight--
	p.mu.Unlock()
}

func (p *Proxy) serve(machine string, w http.ResponseWriter, r *http.Request) {
	ev := Event{At: p.now(), Machine: machine, Method: r.Method}
	deny := func(status int, reason string) {
		ev.Reason, ev.Status = reason, status
		p.audit.Egress(ev)
		w.Header().Set(DeniedHeader, "1")
		http.Error(w, "egress denied: "+reason, status)
	}
	red, err := p.vault.Redactor()
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
	if !p.grants[machine][a.Name] {
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

	if reason, ok := p.admit(machine); !ok {
		deny(http.StatusTooManyRequests, reason)
		return
	}
	defer p.release(machine)

	body, err := io.ReadAll(io.LimitReader(r.Body, p.maxBody+1))
	if err != nil {
		deny(http.StatusBadRequest, "unreadable body")
		return
	}
	if int64(len(body)) > p.maxBody {
		deny(http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	if op.Body != nil {
		if body, err = op.Body.apply(body, p.label(machine) == LabelPublic); err != nil {
			deny(http.StatusForbidden, err.Error())
			return
		}
	}
	sec, ok := p.vault.Secret(a.Credential)
	if !ok {
		deny(http.StatusServiceUnavailable, "credential not in vault")
		return
	}

	up, err := http.NewRequestWithContext(r.Context(), op.Method, "https://"+a.Host+upPath, bytes.NewReader(body))
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
	up.Header.Set(a.Inject.Header, a.Inject.Prefix+sec.Reveal())

	p.charge(machine, 1, int64(len(body)))
	resp, err := p.rt.RoundTrip(up)
	if err != nil {
		ev.Allowed, ev.Status, ev.Reason = true, http.StatusBadGateway, "upstream unreachable"
		p.audit.Egress(ev)
		http.Error(w, "egress: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// The redactor reads plain bytes only. A compressed body would pass it
	// unread and be inflated by the guest.
	if encoded(resp.Header) {
		ev.Allowed, ev.Status, ev.Reason = true, http.StatusBadGateway, "encoded response refused"
		p.audit.Egress(ev)
		http.Error(w, "egress: encoded response refused", http.StatusBadGateway)
		return
	}

	for _, h := range append(append([]string(nil), baseResponseHeaders...), a.ResponseHeaders...) {
		for _, v := range resp.Header.Values(h) {
			w.Header().Add(h, string(red.Redact([]byte(v))))
		}
	}
	w.WriteHeader(resp.StatusCode)
	ev.Allowed, ev.Status = true, resp.StatusCode
	p.audit.Egress(ev)

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
