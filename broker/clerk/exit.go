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
	// Headers are sent as declared, each named in fixedHeaders, so they never
	// carry a credential or name a header the clerk sets itself.
	Headers map[string]string
	Slot    string // the clerk's secret slot, sent with this request; "" sends none
	Header  string // header that carries the secret, from secretHeaders; Authorization if empty
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
// The Guard is required: the broker passes its one shared policy, which has
// learned the home network. The clerk dials with no purpose, so no pin admits
// it and every non-public address is refused.
type Declaration struct {
	Name  string
	Ops   []Op
	Guard *netguard.Policy
	// Refresh is an OAuth 2.0 token endpoint (https), or "" for none. With it,
	// the clerk's slot is of KindGrant and holds the sealed refresh grant, a
	// JSON object of the form fields refresh_token, client_id and
	// client_secret, and the clerk sends an access token it redeems from that
	// grant (RFC 6749 section 6). Without it, the slot is of KindStatic.
	Refresh string
	// Clock is the clerk's own time: holds, token lives and Retry-After are
	// judged on it, never on a time a request carries (CLK-2).
	Clock Clock
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
	DRefresh    = "refresh"    // the token endpoint gave no access token; nothing sent. Then "http N", if it answered
	DReconnect  = "reconnect"  // the token endpoint refused the grant (400, 401): the owner signs in again; then the clerk's name
)

// Exit is a clerk whose steps leave the box as HTTPS requests. It re-checks
// every step with Check, sends only a declared shape, adds the secret itself,
// dials only the addresses its declaration allows, and gives back only typed
// details (CLK-1..4, KRN-8).
type Exit struct {
	name    string
	anchors []ed25519.PublicKey
	ops     map[key.Verb]decl
	secrets *Secrets
	client  *http.Client
	clock   Clock

	mu    sync.Mutex // guards state only, never held across a request
	state map[string]*sent

	// OAuth refresh. The access token lives only here, in memory: it is
	// never logged, returned or written to the store, and a restart redeems
	// a new one. tmu serializes redemptions and is held across the token
	// request, so concurrent steps redeem once.
	refresh  string
	slot     string // the clerk's one slot, "" for none
	tmu      sync.Mutex
	token    string
	tokenExp int64 // when to redeem again, ms; 0 waits for a 401
	// unsaved is a rotated grant the store could not write. It is the only
	// copy of the live refresh token, so it is kept here and every step fails
	// until it is saved; the token it came with is not used before then.
	unsaved map[string]string
	// refused is set once the token endpoint refuses the grant: no step
	// redeems again until the owner reconnects the account (Reconnect).
	refused bool
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

// maxRetryAfter bounds a 429's wait, in seconds: one day. It bounds an access
// token's declared life too.
const maxRetryAfter = 24 * 60 * 60

// grantFields are the only fields a sealed refresh grant may hold.
var grantFields = []string{"refresh_token", "client_id", "client_secret"}

var (
	slotRE = regexp.MustCompile(`\{([a-z][a-z-]*)\}`)
	methRE = regexp.MustCompile(`^[A-Z]+$`)
)

// The headers an op may name, spelled exactly as listed. Everything else is
// refused, so the clerk's own headers (Host, framing, Idempotency-Key),
// hop-by-hop headers, credentials and request-reshaping headers never pass.
// A ported op that needs a header adds its name here, with a test.
var (
	// fixedHeaders may carry declared plaintext constants.
	fixedHeaders = map[string]bool{"Accept": true, "Accept-Language": true, "User-Agent": true}
	// secretHeaders may carry the sealed secret. None is a fixed header, and
	// none is a header remotes commonly log.
	secretHeaders = map[string]bool{"Authorization": true, "X-Api-Key": true}
)

// NewExit validates the declaration; a bad one is an error, never a runtime
// surprise. The exit owns its transport: no proxy from the environment, no
// cookie jar, no redirects, and every dial through the guard, which is
// required. roots nil trusts the system's certificate authorities.
func NewExit(d Declaration, anchors []ed25519.PublicKey, secrets *Secrets, roots *x509.CertPool) (*Exit, error) {
	if d.Name == "" {
		return nil, errors.New("clerk: a declaration needs a name")
	}
	if d.Guard == nil {
		return nil, errors.New("clerk: a declaration needs the home-network policy (DEV-2)")
	}
	x := &Exit{name: d.Name, anchors: anchors, ops: map[key.Verb]decl{}, secrets: secrets, state: map[string]*sent{}, clock: d.Clock}
	slot := ""
	for _, op := range d.Ops {
		o, err := x.declare(op)
		if err != nil {
			return nil, err
		}
		if op.Slot != "" {
			slot = op.Slot
		}
		x.ops[op.Verb] = o
	}
	// The clerk holds its account's secret and no other (CLK-1).
	if n := secrets.Len(); n > 1 || n == 1 && (slot == "" || !secrets.Has(slot)) {
		return nil, errors.New("clerk: the secret store holds another account's secret (CLK-1)")
	}
	// Each path opens only its own kind of slot, so a grant never goes out
	// as a bearer header and a static secret is never posted as a grant.
	if d.Refresh == "" {
		if slot != "" && secrets.with(slot, KindStatic, func([]byte) error { return nil }) != nil {
			return nil, errors.New("clerk: a clerk without a token endpoint needs a static secret in its slot")
		}
	} else {
		u, err := url.Parse(d.Refresh)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(d.Refresh, "#") {
			return nil, errors.New("clerk: a token endpoint needs a plain https URL")
		}
		if slot == "" || secrets.with(slot, KindGrant, func(g []byte) error { _, err := readGrant(g); return err }) != nil {
			return nil, errors.New("clerk: refresh needs a sealed refresh grant in the clerk's slot")
		}
		x.refresh = d.Refresh
	}
	x.slot = slot
	x.client = &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.Guard.DialContext,
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
		o.header = cmp(op.Header, "Authorization")
		if !secretHeaders[o.header] || !plain(op.Prefix) {
			return o, errors.New("clerk: bad secret header")
		}
	}
	for h, v := range op.Headers {
		if !fixedHeaders[h] || !plain(v) {
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
	return op.Content, op.Labels, Amount(s)
}

// Do checks the step first, every time, then sends it once per idempotency
// key; a known key answers from memory without a request.
func (x *Exit) Do(r kernel.Request, v kernel.View) kernel.Result {
	op, ok := x.ops[r.Step().Verb]
	if !ok {
		return kernel.Result{Outcome: "failed", Detail: DUndeclared}
	}
	if res, ok := x.check(r, v); !ok {
		return res
	}
	req, bad := x.build(op, r)
	if bad != "" {
		return kernel.Result{Outcome: "failed", Detail: bad}
	}
	if op.Slot == "" {
		return x.send(req, r)
	}
	if x.refresh != "" {
		return x.sendOAuth(op, req, r, v)
	}
	var res kernel.Result
	// with wipes its plaintext buffer on return, but the header value is a
	// string copy that buffer cannot reach; it lives until the request is
	// collected.
	if err := x.secrets.with(op.Slot, KindStatic, func(s []byte) error {
		req.Header.Set(op.header, op.Prefix+string(s))
		res = x.send(req, r)
		return nil
	}); err != nil {
		return kernel.Result{Outcome: "failed", Detail: DCredential}
	}
	return res
}

// check is the clerk's own authorization, run before every send.
func (x *Exit) check(r kernel.Request, v kernel.View) (kernel.Result, bool) {
	if rf := Check(x.anchors, x.name, x.Facts, x.clock.Now(), r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}, false
	}
	return kernel.Result{}, true
}

// sendOAuth sends with a live access token. A 401 acted on nothing (phase
// notsent), so the clerk redeems a new token once and sends again under the
// same idempotency key. A redemption can wait on the token endpoint and on
// tmu, so the step is checked again before each send (CLK-2).
func (x *Exit) sendOAuth(op decl, req *http.Request, r kernel.Request, v kernel.View) kernel.Result {
	tok, bad := x.access(x.clock.Now(), "")
	if bad != "" {
		return kernel.Result{Outcome: "failed", Detail: bad}
	}
	if res, ok := x.check(r, v); !ok {
		return res
	}
	req.Header.Set(op.header, op.Prefix+tok)
	res := x.send(req, r)
	if res.Detail != DAuth+" http 401" {
		return res
	}
	if tok, bad = x.access(x.clock.Now(), tok); bad != "" {
		return kernel.Result{Outcome: "failed", Detail: bad}
	}
	if req, bad = x.build(op, r); bad != "" {
		return kernel.Result{Outcome: "failed", Detail: bad}
	}
	if res, ok := x.check(r, v); !ok {
		return res
	}
	req.Header.Set(op.header, op.Prefix+tok)
	return x.send(req, r)
}

// access returns a live access token. It redeems the grant when there is no
// token, the token's life has run out, or the token is stale: the one the
// remote just refused. A token another step redeemed meanwhile is reused.
func (x *Exit) access(now int64, stale string) (string, string) {
	x.tmu.Lock()
	defer x.tmu.Unlock()
	if x.refused {
		return "", DReconnect + " " + x.name
	}
	if x.unsaved != nil {
		if bad := x.save(); bad != "" {
			return "", bad
		}
	}
	if x.token != "" && x.token != stale && (x.tokenExp == 0 || now < x.tokenExp) {
		return x.token, ""
	}
	x.token = ""
	var grant map[string]string
	if err := x.secrets.with(x.slot, KindGrant, func(g []byte) (err error) {
		grant, err = readGrant(g)
		return err
	}); err != nil {
		return "", DCredential
	}
	t, status := x.redeem(grant)
	switch {
	case status == 400 || status == 401:
		// invalid_grant or invalid_client (RFC 6749 section 5.2): only a
		// new sign-in fixes it, so the clerk stops redeeming the grant.
		x.refused = true
		return "", DReconnect + " " + x.name
	case status == 0:
		return "", DRefresh
	case t.Access == "":
		return "", DRefresh + " http " + strconv.Itoa(status)
	}
	x.token, x.tokenExp = t.Access, 0
	if secs := min(t.Expires, maxRetryAfter); secs > 0 {
		x.tokenExp = now + (secs-secs/10)*1000
	}
	// The endpoint rotated the refresh token: the old one is spent, so the
	// new one is saved before the access token is used.
	if t.Refresh != "" {
		grant["refresh_token"] = t.Refresh
		x.unsaved = grant
		if bad := x.save(); bad != "" {
			return "", bad
		}
	}
	return x.token, ""
}

// save seals the unsaved grant into the durable store. On failure the grant
// stays in memory, and the next step tries again.
func (x *Exit) save() string {
	g, _ := json.Marshal(x.unsaved)
	defer clear(g)
	if x.secrets.Put(x.slot, KindGrant, g) != nil {
		return DCredential
	}
	x.unsaved = nil
	return ""
}

// Reconnect replaces the clerk's refresh grant with the one the owner's new
// sign-in gave, without enrolling the clerk again. It is the owner's answer
// to DReconnect; the caller has already proved the owner (CH-3). It returns
// once the new grant is durable, and the next step redeems it.
func (x *Exit) Reconnect(grant []byte) error {
	if x.refresh == "" {
		return errors.New("clerk: this clerk has no refresh grant")
	}
	if _, err := readGrant(grant); err != nil {
		return err
	}
	x.tmu.Lock()
	defer x.tmu.Unlock()
	if err := x.secrets.Put(x.slot, KindGrant, grant); err != nil {
		return err
	}
	x.refused, x.unsaved, x.token, x.tokenExp = false, nil, "", 0
	return nil
}

type tokenAnswer struct {
	Access  string `json:"access_token"`
	Expires int64  `json:"expires_in"`
	Refresh string `json:"refresh_token"`
}

// redeem posts the grant to the token endpoint and returns its answer and
// status, 0 for no answer. An answer that is not 2xx, does not decode or holds
// no plain access token comes back with no access token. Only the status
// reaches a detail; the endpoint's body, the grant and the tokens never do
// (CLK-4).
func (x *Exit) redeem(grant map[string]string) (tokenAnswer, int) {
	var t tokenAnswer
	form := url.Values{"grant_type": {"refresh_token"}}
	for k, v := range grant {
		form.Set(k, v)
	}
	req, err := http.NewRequest("POST", x.refresh, strings.NewReader(form.Encode()))
	if err != nil {
		return t, 0
	}
	req.Header.Set("Content-Type", TypeForm)
	req.Header.Set("Accept", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := x.client.Do(req.WithContext(ctx))
	if err != nil {
		return t, 0
	}
	defer resp.Body.Close()
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t)
	if resp.StatusCode/100 != 2 || err != nil || !plain(t.Access) {
		return tokenAnswer{}, resp.StatusCode
	}
	return t, resp.StatusCode
}

// readGrant reads a sealed refresh grant. Only grantFields are allowed, and
// refresh_token is required.
func readGrant(g []byte) (map[string]string, error) {
	var m map[string]string
	if json.Unmarshal(g, &m) != nil || m["refresh_token"] == "" {
		return nil, errors.New("clerk: bad refresh grant")
	}
	for k := range m {
		if !slices.Contains(grantFields, k) {
			return nil, errors.New("clerk: bad refresh grant")
		}
	}
	return m, nil
}

func (x *Exit) build(op decl, r kernel.Request) (*http.Request, string) {
	// Check has already matched the arguments to the declaration exactly.
	args := r.Step().Args
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
	req.Header.Set("Idempotency-Key", r.Idem())
	return req, ""
}

// send performs the one request and classifies the answer (KRN-8). The lock
// covers only the state table, so one slow remote holds up nothing else.
func (x *Exit) send(req *http.Request, r kernel.Request) kernel.Result {
	x.mu.Lock()
	s := x.state[r.Idem()]
	if s == nil {
		s = &sent{}
		x.state[r.Idem()] = s
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
	s.phase, s.retryAt = phase, x.clock.Now()+retry
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
		// Capped before the multiply, so no value overflows the wait.
		secs, _ := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
		return res("unknown", DBusy), pNotSent, min(max(secs, 0), maxRetryAfter) * 1000
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
func (x *Exit) Probe(r kernel.Request, _ kernel.View) kernel.Result {
	x.mu.Lock()
	defer x.mu.Unlock()
	s := x.state[r.Idem()]
	if s == nil {
		s = &sent{phase: pUnknown}
	}
	switch {
	case s.phase == pDone:
		return kernel.Result{Outcome: "done"}
	case s.phase == pSending || s.sends >= kernel.MaxChecks:
		return kernel.Result{Outcome: "unknown"}
	case s.phase == pNotSent:
		if x.clock.Now() >= s.retryAt {
			return kernel.Result{Outcome: "notdone"}
		}
		return kernel.Result{Outcome: "unknown"}
	case x.ops[r.Step().Verb].Idempotent:
		return kernel.Result{Outcome: "notdone"}
	}
	return kernel.Result{Outcome: "unknown"}
}
