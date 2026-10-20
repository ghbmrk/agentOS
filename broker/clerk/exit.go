package clerk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Op is one declared request shape (CLK-3): the only HTTPS request a verb may
// become. Everything but argument values is fixed here, and the clerk encodes
// each value for the one place it fills, so a value can never add a path
// segment, a query parameter, a header or a body field.
type Op struct {
	Verb   key.Verb
	Method string
	// URL is https with a fixed host. Its path may hold {arg} slots, each a
	// whole segment, and no escapes; a constant query may follow.
	URL string
	// Query maps a query parameter to the argument that fills it.
	Query map[string]string
	// Headers are sent as declared. They never name the secret's header or
	// one the clerk sets itself.
	Headers map[string]string
	Slot    string // the clerk's secret slot, sent with this request; "" sends none
	Header  string // header that carries the secret; Authorization if empty
	Prefix  string // text before the secret in that header, e.g. "Bearer "
	// Type is the body's encoding, TypeJSON or TypeForm, and Body maps each
	// body field to the argument that fills it. Both empty send no body.
	Type string
	Body map[string]string
	// Idempotent declares that the remote dedupes on Idempotency-Key, so a step
	// whose outcome is unknown may be sent again under the same key (KRN-8).
	Idempotent bool
	Content    string   // content class the clerk reads this op as (KEY-2)
	Labels     []string // flow labels it reads the data as
}

// Body encodings the clerk can write.
const (
	TypeJSON = "application/json"
	TypeForm = "application/x-www-form-urlencoded"
)

// Declaration describes one clerk (CLK-3): its name, the only requests it may
// make, and the home-network address policy every dial goes through (DEV-2).
// A nil Guard is netguard's IANA-only policy; a home device is reached only
// through a pin on the policy the caller passes.
type Declaration struct {
	Name  string
	Ops   []Op
	Guard *netguard.Policy
}

// Detail codes: the typed reasons an exit answers with (CLK-2, OWN-17). A
// detail is one code, then "http N", the declared host or an argument's name;
// never a value, a transport error or a secret, so nothing in it needs
// redacting (CLK-4).
const (
	DSent       = "sent"       // 2xx
	DDone       = "done"       // already done under this idempotency key
	DUndeclared = "undeclared" // no op for this verb
	DArg        = "arg"        // a value cannot fill its slot; then the argument's name
	DCredential = "credential" // the secret slot did not open
	DBlocked    = "blocked"    // the address is not one this clerk may reach; nothing sent
	DNoAnswer   = "noanswer"   // then the host
	DInflight   = "inflight"   // the same step is being sent now
	DAuth       = "auth"       // 401, 403
	DDeclined   = "declined"   // 402
	DNotFound   = "notfound"   // 404, 410
	DRejected   = "rejected"   // any other 4xx
	DTimeout    = "timeout"    // 408
	DConflict   = "conflict"   // 409
	DBusy       = "busy"       // 429: nothing happened, sent again after Retry-After
	DRedirect   = "redirect"   // 3xx: the action may have been applied
	DServer     = "server"     // 5xx
)

// Exit is a clerk whose steps leave the box as HTTPS requests. It re-checks
// every step with Check, sends only a declared shape, adds the secret itself,
// dials only the addresses its declaration allows, and gives back only typed
// details (CLK-1..4, KRN-8).
type Exit struct {
	name    string
	owner   ed25519.PublicKey
	ops     map[key.Verb]decl
	secrets *Secrets
	client  *http.Client

	mu    sync.Mutex // guards state only, never held across a request
	state map[string]*sent
}

type decl struct {
	Op
	host   string
	header string // the secret's header, canonical
}

// sent is what the clerk knows of one idempotency key.
type sent struct {
	phase   string // pSending, pDone, pUnknown or pNotSent
	sends   int
	retryAt int64
}

const (
	pSending = "sending"
	pDone    = "done"
	pUnknown = "unknown"
	pNotSent = "notsent" // the remote refused it before acting
)

var (
	slotRE  = regexp.MustCompile(`\{([a-z][a-z-]*)\}`)
	tokenRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	methRE  = regexp.MustCompile(`^[A-Z]+$`)
)

// clerkHeaders are set by the clerk itself; no declaration may name them.
var clerkHeaders = []string{"Host", "Content-Type", "Content-Length", "Transfer-Encoding", "Connection", "Idempotency-Key"}

// credHeaders carry credentials; only the secret's own header may.
var credHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie"}

// NewExit validates the declaration; a bad one is an error, never a runtime
// surprise. The exit owns its transport: no proxy from the environment, no
// cookie jar, no redirects, and every dial through the guard. roots nil trusts the system's
// certificate authorities.
func NewExit(d Declaration, owner ed25519.PublicKey, secrets *Secrets, roots *x509.CertPool) (*Exit, error) {
	if d.Name == "" {
		return nil, errors.New("clerk: a declaration needs a name")
	}
	x := &Exit{name: d.Name, owner: owner, ops: map[key.Verb]decl{}, secrets: secrets, state: map[string]*sent{}}
	slot := ""
	for _, op := range d.Ops {
		o, err := x.declare(op)
		if err != nil {
			return nil, err
		}
		if op.Slot != "" {
			if slot != "" && slot != op.Slot {
				return nil, errors.New("clerk: one secret slot per clerk (CLK-1)")
			}
			slot = op.Slot
		}
		x.ops[op.Verb] = o
	}
	// The clerk holds its account's secret and no other (CLK-1).
	if n := secrets.Len(); n > 1 || n == 1 && (slot == "" || !secrets.Has(slot)) {
		return nil, errors.New("clerk: the secret store holds another account's secret (CLK-1)")
	}
	g := d.Guard
	if g == nil {
		g = netguard.New(netguard.Config{Timeout: 10 * time.Second})
	}
	x.client = &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         g.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return x, nil
}

func (x *Exit) declare(op Op) (decl, error) {
	o := decl{Op: op}
	if !key.Valid(op.Verb) {
		return o, fmt.Errorf("clerk: %q is not a verb", op.Verb)
	}
	if _, dup := x.ops[op.Verb]; dup {
		return o, fmt.Errorf("clerk: verb %s declared twice", op.Verb)
	}
	if !methRE.MatchString(op.Method) {
		return o, errors.New("clerk: bad method")
	}
	// No escapes before the query: the path checked below is then the path
	// sent, so the decoded and raw forms cannot disagree.
	base, rawq, _ := strings.Cut(op.URL, "?")
	if strings.Contains(base, "%") {
		return o, errors.New("clerk: an op path holds no escapes")
	}
	u, err := url.Parse(op.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(u.Host, "{}") {
		return o, errors.New("clerk: an op needs a plain https URL")
	}
	if u.Fragment != "" || strings.Contains(op.URL, "#") || strings.ContainsAny(rawq, "{}") {
		return o, errors.New("clerk: slots belong in the path only")
	}
	o.host = u.Host
	fixed, err := url.ParseQuery(rawq)
	if err != nil {
		return o, errors.New("clerk: bad constant query")
	}
	names := key.ArgNames(op.Verb)
	arg := func(n string) error {
		if !slices.Contains(names, n) {
			return fmt.Errorf("clerk: %s has no argument %q", op.Verb, n)
		}
		return nil
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if !strings.ContainsAny(seg, "{}") {
			continue
		}
		m := slotRE.FindStringSubmatch(seg)
		if m == nil || m[0] != seg {
			return o, errors.New("clerk: a slot must be a whole path segment")
		}
		if err := arg(m[1]); err != nil {
			return o, err
		}
	}
	for p, n := range op.Query {
		if p == "" || fixed.Has(p) {
			return o, fmt.Errorf("clerk: query parameter %q is empty or fixed", p)
		}
		if err := arg(n); err != nil {
			return o, err
		}
	}
	if (op.Type == "") != (len(op.Body) == 0) || op.Type != "" && op.Type != TypeJSON && op.Type != TypeForm {
		return o, errors.New("clerk: a body needs its fields and a type the clerk encodes")
	}
	for f, n := range op.Body {
		if f == "" {
			return o, errors.New("clerk: empty body field")
		}
		if err := arg(n); err != nil {
			return o, err
		}
	}
	if op.Slot == "" {
		if op.Header != "" || op.Prefix != "" {
			return o, errors.New("clerk: a secret header needs a slot")
		}
	} else {
		if !x.secrets.Has(op.Slot) {
			return o, fmt.Errorf("clerk: no secret slot %q", op.Slot)
		}
		o.header = http.CanonicalHeaderKey(cmp(op.Header, "Authorization"))
		if !tokenRE.MatchString(o.header) || slices.Contains(clerkHeaders, o.header) || !plain(op.Prefix) {
			return o, errors.New("clerk: bad secret header")
		}
	}
	for h, v := range op.Headers {
		c := http.CanonicalHeaderKey(h)
		if !tokenRE.MatchString(h) || !plain(v) || c == o.header || slices.Contains(clerkHeaders, c) || slices.Contains(credHeaders, c) {
			return o, fmt.Errorf("clerk: header %q cannot be declared", h)
		}
	}
	return o, nil
}

func cmp(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// plain reports whether a header value holds no control characters.
func plain(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return false
		}
	}
	return true
}

// Facts is the clerk's own reading of a step (KEY-2): the content and labels
// its declaration gives, and the amount argument if the verb has one.
func (x *Exit) Facts(s key.Step) (string, []string, int64) {
	op, ok := x.ops[s.Verb]
	if !ok {
		return "", nil, 0
	}
	var amount int64
	if a, ok := s.Args[key.ArgAmount]; ok {
		n, err := strconv.ParseInt(a.Value, 10, 64)
		if err != nil {
			n = -1
		}
		amount = n
	}
	return op.Content, op.Labels, amount
}

// Do checks the step first, every time, then sends it once per idempotency
// key; a known key answers from memory without a request.
func (x *Exit) Do(r kernel.Request, v kernel.View) kernel.Result {
	op, ok := x.ops[r.Step.Verb]
	if !ok {
		return kernel.Result{Outcome: "failed", Detail: DUndeclared}
	}
	if rf := Check(x.owner, x.name, x.Facts, r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	req, bad := x.build(op, r)
	if bad != "" {
		return kernel.Result{Outcome: "failed", Detail: bad}
	}
	if op.Slot == "" {
		return x.send(req, r)
	}
	var res kernel.Result
	// The header value is a string copy the wipe in with cannot reach; it
	// lives until the request is collected.
	if err := x.secrets.with(op.Slot, func(s []byte) error {
		req.Header.Set(op.header, op.Prefix+string(s))
		res = x.send(req, r)
		return nil
	}); err != nil {
		return kernel.Result{Outcome: "failed", Detail: DCredential}
	}
	return res
}

func (x *Exit) build(op decl, r kernel.Request) (*http.Request, string) {
	// Check has already matched the arguments to the declaration exactly.
	args := r.Step.Args
	bad := ""
	target := slotRE.ReplaceAllStringFunc(op.URL, func(m string) string {
		n := m[1 : len(m)-1]
		v := args[n].Value
		if v == "" || v == "." || v == ".." || strings.Contains(v, "/") {
			bad = DArg + " " + n
		}
		return url.PathEscape(v)
	})
	if bad != "" {
		return nil, bad
	}
	if len(op.Query) > 0 {
		q := url.Values{}
		for p, n := range op.Query {
			q.Set(p, args[n].Value)
		}
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + q.Encode()
	}
	var body io.Reader
	if len(op.Body) > 0 {
		var b []byte
		if op.Type == TypeJSON {
			f := map[string]string{}
			for field, n := range op.Body {
				f[field] = args[n].Value
			}
			b, _ = json.Marshal(f)
		} else {
			f := url.Values{}
			for field, n := range op.Body {
				f.Set(field, args[n].Value)
			}
			b = []byte(f.Encode())
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(op.Method, target, body)
	if err != nil || req.URL.Scheme != "https" || req.URL.Host != op.host {
		return nil, DArg
	}
	for h, v := range op.Headers {
		req.Header.Set(h, v)
	}
	if op.Type != "" {
		req.Header.Set("Content-Type", op.Type)
	}
	req.Header.Set("Idempotency-Key", r.Idem)
	return req, ""
}

// send performs the one request and classifies the answer (KRN-8). The lock
// covers only the state table, so one slow remote holds up nothing else.
func (x *Exit) send(req *http.Request, r kernel.Request) kernel.Result {
	x.mu.Lock()
	s := x.state[r.Idem]
	if s == nil {
		s = &sent{}
		x.state[r.Idem] = s
	}
	switch s.phase {
	case pDone:
		x.mu.Unlock()
		return kernel.Result{Outcome: "ok", Detail: DDone}
	case pSending:
		x.mu.Unlock()
		return kernel.Result{Outcome: "unknown", Detail: DInflight}
	}
	s.phase = pSending
	s.sends++
	x.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, phase, retry := classify(x.client.Do(req.WithContext(ctx)))
	if res.Detail == DNoAnswer {
		res.Detail += " " + req.URL.Hostname()
	}
	x.mu.Lock()
	s.phase, s.retryAt = phase, r.Now+retry
	x.mu.Unlock()
	return res
}

// classify maps an answer to an outcome, the clerk's phase for the key and,
// for a 429, how long to wait. A 2xx is done. A refusal that proves nothing
// happened (401-404, 410, 400, 422 and the rest of 4xx) is failed. A redirect,
// 408, 409, 5xx or no answer may have acted, so it is unknown and the probe
// decides. A 429 acted on nothing, so it is unknown with phase notsent: the
// probe answers notdone once Retry-After has passed and the kernel sends again.
func classify(resp *http.Response, err error) (kernel.Result, string, int64) {
	if err != nil {
		if errors.Is(err, netguard.ErrDenied) {
			return kernel.Result{Outcome: "failed", Detail: DBlocked}, pNotSent, 0
		}
		return kernel.Result{Outcome: "unknown", Detail: DNoAnswer}, pUnknown, 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	c := resp.StatusCode
	res := func(outcome, code string) kernel.Result {
		return kernel.Result{Outcome: outcome, Detail: code + " http " + strconv.Itoa(c)}
	}
	switch {
	case c >= 200 && c < 300:
		return res("ok", DSent), pDone, 0
	case c == 429:
		secs, _ := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
		return res("unknown", DBusy), pNotSent, max(secs, 0) * 1000
	case c >= 300 && c < 400:
		return res("unknown", DRedirect), pUnknown, 0
	case c == 408:
		return res("unknown", DTimeout), pUnknown, 0
	case c == 409:
		return res("unknown", DConflict), pUnknown, 0
	case c == 401 || c == 403:
		return res("failed", DAuth), pNotSent, 0
	case c == 402:
		return res("failed", DDeclined), pNotSent, 0
	case c == 404 || c == 410:
		return res("failed", DNotFound), pNotSent, 0
	case c >= 400 && c < 500:
		return res("failed", DRejected), pNotSent, 0
	default:
		return res("unknown", DServer), pUnknown, 0
	}
}

// Probe answers from the clerk's memory, never by acting. It says notdone only
// when sending again is safe: the remote refused the step before acting (a
// 429, once Retry-After has passed), or the op is idempotent at the target.
// Otherwise a key it has no record of is unknown, never notdone: after a
// restart this memory is empty and the kernel marks every in-flight step
// unknown, so a clerk that cannot say the step was never sent must not invite
// a resend (KRN-8). It invites at most MaxChecks sends per key.
func (x *Exit) Probe(r kernel.Request, _ kernel.View) string {
	x.mu.Lock()
	defer x.mu.Unlock()
	s := x.state[r.Idem]
	if s == nil {
		s = &sent{phase: pUnknown}
	}
	switch {
	case s.phase == pDone:
		return "done"
	case s.phase == pSending || s.sends >= kernel.MaxChecks:
		return "unknown"
	case s.phase == pNotSent:
		if r.Now >= s.retryAt {
			return "notdone"
		}
		return "unknown"
	case x.ops[r.Step.Verb].Idempotent:
		return "notdone"
	}
	return "unknown"
}
