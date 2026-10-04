// Package egress is the broker's credentialed egress proxy (CRED-5, ADP-10,
// PLAN P1-3).
//
// A guest reaches a provider as a standard HTTP endpoint and holds only a
// placeholder credential. Each request arrives on a handler bound to one
// agent machine, so identity comes from where the request arrived, never
// from anything the guest sends. The proxy forwards a request only if it
// matches a declared operation of an adapter that machine is granted. It
// then drops every header outside a fixed allowlist (including any
// credential the guest supplied), writes the vault credential into the
// adapter's injection header, and sends the request over HTTPS to the
// adapter's host. Redirects are returned, never followed. The response
// comes back with only allowlisted headers, and its headers and body pass
// the vault redactor (CRED-7), streamed so token streams keep flowing.
// Every decision is reported to the Auditor; anything else is denied.
//
// The proxy is not on the control path (ARC-2): STOP, STATUS, and
// admission never import it.
package egress

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// DefaultMaxBody caps a request body, in bytes.
const DefaultMaxBody = 8 << 20

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

// Auditor receives every decision. The broker journals denials (ADP-10).
type Auditor interface{ Egress(Event) }

// Secrets is the part of the vault the proxy uses.
type Secrets interface {
	Secret(name string) (vault.Secret, bool)
	Redactor() *vault.Redactor
}

// Config configures New.
type Config struct {
	Adapters []Adapter
	// Grants maps an agent machine to the adapters it may use.
	Grants map[string][]string
	Vault  Secrets
	// Transport sends upstream requests; nil means a fresh http.Transport
	// with no proxy from the environment.
	Transport http.RoundTripper
	Audit     Auditor
	// MaxBody caps request bodies; zero means DefaultMaxBody.
	MaxBody int64
	Now     func() time.Time
}

// Proxy is the credentialed egress proxy.
type Proxy struct {
	adapters map[string]Adapter
	grants   map[string]map[string]bool
	vault    Secrets
	rt       http.RoundTripper
	audit    Auditor
	maxBody  int64
	now      func() time.Time
}

// New validates every declaration and grant and returns a proxy.
func New(cfg Config) (*Proxy, error) {
	if cfg.Vault == nil {
		return nil, errors.New("egress: vault required")
	}
	p := &Proxy{
		adapters: map[string]Adapter{},
		grants:   map[string]map[string]bool{},
		vault:    cfg.Vault,
		rt:       cfg.Transport,
		audit:    cfg.Audit,
		maxBody:  cfg.MaxBody,
		now:      cfg.Now,
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
		p.rt = &http.Transport{ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second}
	}
	if p.maxBody <= 0 {
		p.maxBody = DefaultMaxBody
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.audit == nil {
		p.audit = discard{}
	}
	return p, nil
}

type discard struct{}

func (discard) Egress(Event) {}

// Handler serves one agent machine. The broker gives each machine's VM a
// listener of its own and serves this handler on it.
func (p *Proxy) Handler(machine string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.serve(machine, w, r) })
}

func (p *Proxy) serve(machine string, w http.ResponseWriter, r *http.Request) {
	red := p.vault.Redactor()
	ev := Event{At: p.now(), Machine: machine, Method: r.Method, Path: string(red.Redact([]byte(r.URL.EscapedPath())))}
	deny := func(status int, reason string) {
		ev.Reason, ev.Status = reason, status
		p.audit.Egress(ev)
		http.Error(w, "egress denied: "+reason, status)
	}

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

	body, err := io.ReadAll(io.LimitReader(r.Body, p.maxBody+1))
	if err != nil {
		deny(http.StatusBadRequest, "unreadable body")
		return
	}
	if int64(len(body)) > p.maxBody {
		deny(http.StatusRequestEntityTooLarge, "body too large")
		return
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
	up.Header.Set(a.Inject.Header, a.Inject.Prefix+sec.Reveal())

	resp, err := p.rt.RoundTrip(up)
	if err != nil {
		ev.Allowed, ev.Status, ev.Reason = true, http.StatusBadGateway, "upstream unreachable"
		p.audit.Egress(ev)
		http.Error(w, "egress: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

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
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
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
