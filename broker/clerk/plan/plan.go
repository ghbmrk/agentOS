// Package plan is the clerk of a provider's consumer plan login (CLK-7,
// PLN-5; MIG-4-plan-login-a, #3104).
package plan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// A plan login is a provider's consumer plan sign-in, used only by that
// provider's official CLI running as a guest. The guest holds placeholders;
// this clerk holds the login in its one sealed store, injects it into the
// CLI's declared requests, and swaps every token answer back to that guest's
// placeholders. It is the old core's plan route (egress, measured on Codex
// CLI 0.162.1, #809) moved onto the clerk. It is not package clerk, which
// the kernel's process links for its check: a guest's traffic is parsed here,
// in the model clerk's process only, so the trusted core does not grow
// (KRN-2cap).

// Kind is what a declared plan endpoint carries.
type Kind string

const (
	// Model is a model call: the guest's access placeholder in
	// Authorization becomes the real token, the body is held to the
	// declared Body, and the model clerk's Meter admits and settles it
	// (MIG-4-plan-login-b).
	Model Kind = "model"
	// Read is a bearer-authenticated GET with no body.
	Read Kind = "read"
	// Refresh is the CLI's token refresh: its JSON body carries the
	// guest's refresh placeholder, and its answer is a token exchange.
	Refresh Kind = "refresh"
	// Device is a device-code step of the sign-in: a JSON object of
	// strings, with no credential this clerk holds either way.
	Device Kind = "device"
	// Code is the sign-in's code exchange: a form whose answer is the
	// first login.
	Code Kind = "code"
)

func (k Kind) signIn() bool { return k == Device || k == Code }

// Endpoint is one declared request (CLK-3). Sign-in endpoints answer a
// sign-in guest only, the rest a run guest only.
type Endpoint struct {
	Name, Host, Method, Path string
	Kind                     Kind
	// Query names the query keys the endpoint takes, each at most once.
	Query []string
}

// FieldKind is what a declared token-answer field may hold.
type FieldKind string

const (
	FieldCredential FieldKind = "credential" // a non-empty string, swapped for a placeholder
	FieldNumber     FieldKind = "number"     // a JSON number of at most 20 characters
	FieldBool       FieldKind = "bool"
	FieldText       FieldKind = "text" // at most 256 bytes matching Pattern whole
)

// Field is one declared top-level field of a token answer. A text
// field's Pattern is the declaration's statement that the value is no
// credential, so it should admit only the provider's fixed words.
type Field struct {
	Name     string
	Kind     FieldKind
	Pattern  string
	Optional bool

	re *regexp.Regexp
}

// Declaration is one plan's route, as measured on its CLI.
type Declaration struct {
	// Name is the plan, and the clerk's one slot.
	Name string
	// Version is the declaration's; a release that requalifies the route
	// after an unswappable answer gives it a new one.
	Version   string
	Endpoints []Endpoint
	// Token is the exact token answer: these fields and no others. It
	// declares access_token as a credential; refresh_token and id_token,
	// if declared, are credentials too.
	Token []Field
	// AccountClaim is the path, in the id_token's claims, to the account
	// ID. Every token answer must name its account.
	AccountClaim []string
	// Refused are the error codes a refresh answered 400 or 401 carries
	// when the provider refuses the login, as {"error":"<code>"} or
	// {"error":{"code":"<code>"}}.
	Refused []string
	// RefreshKeys are the refresh body's keys, all strings; grant_type is
	// refresh_token and refresh_token is the guest's placeholder.
	RefreshKeys []string
	// RedirectFrom is the redirect_uri the CLI sends in its code exchange
	// (its local callback); the clerk sends RedirectTo, which the provider
	// bound the code to. Any other redirect_uri is refused.
	RedirectFrom, RedirectTo string
	// RequestHeaders pass on run requests, SignInHeaders on sign-in steps;
	// ResponseHeaders and ResponsePrefixes come back to the guest,
	// redacted. Nothing else passes either way.
	RequestHeaders, SignInHeaders     []string
	ResponseHeaders, ResponsePrefixes []string
	// MaxBody bounds a model call's body; 0 is 16 MiB.
	MaxBody int64
	// Body is a model call's request shape, and Pool how its answer states
	// the plan's usage pool (RES-5).
	Body Body
	Pool Pool
	// Guard is the home-network policy every dial goes through (DEV-2).
	Guard *netguard.Policy
}

// Stops: why a route is down. An unswappable stop outranks a refused one.
const (
	StopRefused     = "refused-login" // the provider refused the login: the owner resumes or signs in again
	StopUnswappable = "unswappable"   // an answer out of its declared shape: a release requalifies
)

// Plan details, beside the exit's D* ones, carrying no value (CLK-4).
const (
	DUndeclared  = "plan-undeclared"  // no declared endpoint or request shape; nothing sent
	DPlaceholder = "plan-placeholder" // no placeholder of this guest; nothing sent
	DStopped     = "plan-stopped"     // the route is stopped; then the stop
	DUnswappable = "plan-unswappable" // the answer was out of shape: dropped, and the route stopped
	DExchange    = "plan-exchange"    // a token exchange answered with an error: dropped; then "http N"
	DSave        = "plan-save"        // the login could not be sealed: the answer was dropped
	DEncoded     = "plan-encoded"     // an encoded body either way
	DStale       = "plan-stale"       // a refresh answered for a login since removed or replaced: dropped, nothing stopped
)

// ErrRequalify is Resume's answer for a route an unswappable answer
// stopped: only a release with a new declaration version reopens it.
var ErrRequalify = errors.New("clerk: the plan route stays stopped until a release requalifies it")

// ErrNoLogin is Guest's answer before the owner has signed in.
var ErrNoLogin = errors.New("clerk: no plan login")

// ErrStopped is Guest's and BeginSignIn's answer while the route is
// stopped for them.
var ErrStopped = errors.New("clerk: the plan route is stopped")

const (
	maxExchange = 64 << 10 // a token exchange's request or answer, bytes
	maxText     = 256
	maxNumber   = 20
	maxDevice   = 512 // a device step's string values
	exchangeFor = 30 * time.Second
)

// The token fields a placeholder stands for, by their RFC 6749 names.
const (
	fAccess  = "access_token"
	fRefresh = "refresh_token"
	fID      = "id_token"
)

// codeKeys is the code exchange's exact form (RFC 6749 §4.1.3, RFC 7636).
var codeKeys = []string{"client_id", "code", "code_verifier", "grant_type", "redirect_uri"}

var (
	queryValue = regexp.MustCompile(`\A[A-Za-z0-9._-]{1,64}\z`)
	planPath   = regexp.MustCompile(`\A(?:/[A-Za-z0-9._-]+)+\z`)
	planHost   = regexp.MustCompile(`\A[a-z0-9.-]+(?::[0-9]{1,5})?\z`)
)

// planState is the slot's sealed value: the login, its account, and any
// stop with the declaration version it was recorded under.
type planState struct {
	Tokens  map[string]string `json:"tokens,omitempty"`
	Account string            `json:"account,omitempty"`
	Stop    string            `json:"stop,omitempty"`
	Version string            `json:"version,omitempty"`
}

// Tokens is a guest's token set: placeholders only, and the account ID,
// which is no credential.
type Tokens struct {
	Account string
	Tokens  map[string]string
}

// Login is the clerk of one plan login. Its methods are safe for
// concurrent use.
type Login struct {
	d       Declaration
	store   *Store
	client  *http.Client
	token   map[string]*Field
	refused map[string]bool

	mu      sync.Mutex
	guests  map[string]*planGuest
	signing map[string]bool // sign-in guests, true once one committed the login
	held    string          // a stop the slot could not record (fail closed)
	// gen counts the logins the store has held: Remove and every sign-in
	// commit move it, under cmu. A refresh exchange reads it together with
	// the token it sends, under cmu, so its answer is judged only against
	// the login it was made for.
	gen uint64

	cmu sync.Mutex // a commit or stop, from its load to its Put

	fmu    sync.Mutex
	flight *planFlight
}

// planGuest is one guest's placeholders. Each stands for a login field, not
// a value, so it resolves to whatever the slot holds now; only a new account
// mints new ones.
type planGuest struct {
	account string
	field   map[string]string // placeholder -> field
	byField map[string]string // field -> placeholder
}

// planAnswer is one token exchange's answer, read whole.
type planAnswer struct {
	status int
	header http.Header
	body   []byte
	// refresh is set on a refresh answer, made from login gen.
	refresh bool
	gen     uint64
}

// planFlight is the one refresh exchange in flight (#1749): the login's
// refresh token is single-use, so a second exchange of it would be refused
// and stop the route for every guest. A refresh that arrives meanwhile joins
// it, and the flight ends when its last member is done, so no commit of an
// older answer lands after a newer one.
type planFlight struct {
	ready   chan struct{}
	ans     *planAnswer
	detail  string
	members int
}

// New validates the declaration; a bad one is an error, never a
// runtime surprise. store is this clerk's own: it holds this plan's login or
// nothing, and one sealed for another plan does not open (CLK-1). A stored
// unswappable stop recorded under another declaration version is lifted:
// that release requalified the route.
func New(d Declaration, store *Store, roots *x509.CertPool) (*Login, error) {
	if !planPath.MatchString("/"+d.Name) || d.Version == "" {
		return nil, errors.New("clerk: a plan declaration needs a plain name and a version")
	}
	if d.Guard == nil {
		return nil, errors.New("clerk: a plan declaration needs the home-network policy (DEV-2)")
	}
	if store == nil {
		return nil, errors.New("clerk: a plan login needs its sealed store")
	}
	p := &Login{d: d, store: store, token: map[string]*Field{}, refused: map[string]bool{},
		guests: map[string]*planGuest{}, signing: map[string]bool{}}
	if err := p.validate(); err != nil {
		return nil, err
	}
	if p.d.MaxBody <= 0 {
		p.d.MaxBody = 16 << 20
	}
	st, err := p.load()
	if err != nil {
		return nil, errors.New("clerk: the plan login's store does not open for this plan")
	}
	if st.Stop == StopUnswappable && st.Version != d.Version {
		st.Stop, st.Version = "", ""
		if err := p.save(st); err != nil {
			p.held = StopUnswappable // stays stopped until the lift is written
		}
	}
	p.client = guarded(d.Guard, roots)
	return p, nil
}

func (p *Login) validate() error {
	d := p.d
	seen := map[string]bool{}
	for _, e := range d.Endpoints {
		switch e.Kind {
		case Model, Read, Refresh, Device, Code:
		default:
			return fmt.Errorf("clerk: plan endpoint %q: kind %q", e.Name, e.Kind)
		}
		if e.Name == "" || !methRE.MatchString(e.Method) || !planPath.MatchString(e.Path) || !planHost.MatchString(e.Host) {
			return fmt.Errorf("clerk: plan endpoint %q is out of shape", e.Name)
		}
		if (e.Kind == Read) != (e.Method == http.MethodGet) {
			return fmt.Errorf("clerk: plan endpoint %q: a read is a GET and only a read is", e.Name)
		}
		k := fmt.Sprint(e.Kind.signIn(), e.Method, e.Path)
		if seen[k] {
			return fmt.Errorf("clerk: plan endpoint %q repeats a request", e.Name)
		}
		seen[k] = true
	}
	for i := range d.Token {
		f := &d.Token[i]
		if f.Name == "" || p.token[f.Name] != nil {
			return fmt.Errorf("clerk: token field %q is unnamed or repeated", f.Name)
		}
		switch f.Kind {
		case FieldCredential, FieldNumber, FieldBool:
			if f.Pattern != "" {
				return fmt.Errorf("clerk: token field %s: only text takes a pattern", f.Name)
			}
		case FieldText:
			re, err := regexp.Compile(`\A(?:` + f.Pattern + `)\z`)
			if f.Pattern == "" || err != nil {
				return fmt.Errorf("clerk: token field %s: text needs a valid pattern", f.Name)
			}
			f.re = re
		default:
			return fmt.Errorf("clerk: token field %s: kind %q", f.Name, f.Kind)
		}
		if (f.Name == fAccess || f.Name == fRefresh || f.Name == fID) != (f.Kind == FieldCredential) {
			return fmt.Errorf("clerk: token field %s: only the access, refresh and id tokens are credentials", f.Name)
		}
		p.token[f.Name] = f
	}
	if a := p.token[fAccess]; a == nil || a.Optional || p.token[fID] == nil || len(d.AccountClaim) == 0 {
		return errors.New("clerk: a token answer declares an access token, an id_token and its account claim")
	}
	for _, e := range d.Endpoints {
		if e.Kind == Model {
			if err := d.Body.validate(); err != nil {
				return err
			}
			break
		}
	}
	for _, c := range d.Refused {
		p.refused[c] = true
	}
	if !contains(d.RefreshKeys, "grant_type") || !contains(d.RefreshKeys, fRefresh) {
		return errors.New("clerk: a refresh declares grant_type and refresh_token")
	}
	for _, h := range append(append(append([]string{}, d.RequestHeaders...), d.SignInHeaders...), d.ResponseHeaders...) {
		if forbiddenHeader(http.CanonicalHeaderKey(h)) {
			return fmt.Errorf("clerk: header %q may not pass", h)
		}
	}
	for _, pre := range d.ResponsePrefixes {
		if forbiddenPrefix(http.CanonicalHeaderKey(pre)) {
			return fmt.Errorf("clerk: header prefix %q may pass a forbidden header", pre)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// forbiddenHeader is a header no plan route passes: credentials, framing,
// hop-by-hop and request-reshaping headers. The clerk sets its own.
func forbiddenHeader(c string) bool {
	if contains(forbiddenNames, c) {
		return true
	}
	return strings.HasPrefix(c, "X-Forwarded-") || strings.HasPrefix(c, "Proxy-")
}

var forbiddenNames = []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Host", "Content-Length",
	"Transfer-Encoding", "Connection", "Upgrade", "Te", "Trailer", "Keep-Alive", "Content-Encoding", "Accept-Encoding"}

// forbiddenPrefix reports whether a response prefix could pass a forbidden
// header: one it begins, or one that begins it.
func forbiddenPrefix(c string) bool {
	if c == "" || forbiddenHeader(c) {
		return true
	}
	for _, n := range append(append([]string{}, forbiddenNames...), "X-Forwarded-", "Proxy-") {
		if strings.HasPrefix(n, c) {
			return true
		}
	}
	return false
}

func (p *Login) load() (planState, error) {
	var st planState
	err := p.store.open(p.d.Name, func(b []byte) error { return json.Unmarshal(b, &st) })
	return st, err
}

func (p *Login) save(st planState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	defer clear(b)
	return p.store.put(p.d.Name, b)
}

func (p *Login) generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gen
}

// stale reports whether a is a refresh answer to a login no longer stored.
func (p *Login) stale(a *planAnswer) bool {
	return a != nil && a.refresh && a.gen != p.generation()
}

func higher(a, b string) string {
	if a == StopUnswappable || b == StopUnswappable {
		return StopUnswappable
	}
	if a != "" {
		return a
	}
	return b
}

// Stopped is why the route is down, or "". A slot that does not open reads
// as unswappable.
func (p *Login) Stopped() string {
	st, err := p.load()
	p.mu.Lock()
	h := p.held
	p.mu.Unlock()
	if err != nil {
		return StopUnswappable
	}
	return higher(st.Stop, h)
}

// Signed reports whether a login is stored. It reads no token.
func (p *Login) Signed() bool {
	st, err := p.load()
	return err == nil && st.Tokens[fAccess] != ""
}

// stop records cause in the slot, keeping a higher one; a stop the slot
// cannot record is held here.
func (p *Login) stop(cause string) { p.stopFor(nil, cause) }

// stopFor is stop for answer a: a refresh answer stops the route only while
// the login it was made for is still the one stored. The answer to a login
// the owner has since removed or replaced judges nothing.
func (p *Login) stopFor(a *planAnswer, cause string) {
	p.cmu.Lock()
	defer p.cmu.Unlock()
	if p.stale(a) {
		return
	}
	if st, err := p.load(); err == nil {
		if st.Stop == StopUnswappable {
			return
		}
		st.Stop, st.Version = higher(st.Stop, cause), p.d.Version
		if p.save(st) == nil {
			return
		}
	}
	p.mu.Lock()
	p.held = higher(p.held, cause)
	p.mu.Unlock()
}

// Resume reopens a route the provider refused the login on: the owner's
// PLAN <plan> ON, whose caller has proved the owner (CH-10). It does not
// reopen an unswappable stop (ErrRequalify), nor one it cannot record.
func (p *Login) Resume() error {
	p.cmu.Lock()
	defer p.cmu.Unlock()
	st, err := p.load()
	if err != nil {
		return err
	}
	p.mu.Lock()
	h := p.held
	p.mu.Unlock()
	if higher(st.Stop, h) == StopUnswappable {
		return ErrRequalify
	}
	if st.Stop != "" {
		st.Stop, st.Version = "", ""
		if err := p.save(st); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.held = ""
	p.mu.Unlock()
	return nil
}

// Remove deletes the login and every placeholder. A stop goes with it
// unless it is unswappable, which only a release lifts.
func (p *Login) Remove() error {
	p.cmu.Lock()
	defer p.cmu.Unlock()
	st, err := p.load()
	if err == nil && st.Stop == StopUnswappable {
		err = p.save(planState{Stop: st.Stop, Version: st.Version})
	} else {
		err = p.store.put(p.d.Name, nil)
	}
	if err != nil {
		return err
	}
	p.mu.Lock()
	clear(p.guests)
	clear(p.signing)
	p.gen++
	p.mu.Unlock()
	return nil
}

func rnd() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("clerk: no randomness")
	}
	return hex.EncodeToString(b)
}

// accountOf reads the account ID from an id_token's claims at the declared
// path. The token is not verified: it is the provider's own answer on the
// clerk's own connection.
func (p *Login) accountOf(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	for _, k := range p.d.AccountClaim {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[k]
	}
	s, _ := v.(string)
	if len(s) > maxText {
		return ""
	}
	return s
}

// placeholderID is an unsigned id_token carrying the account ID at the
// declared claim and nothing else: no email, no plan claims. The CLI reads
// it without verifying it.
func (p *Login) placeholderID(account string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	var claim any = account
	for i := len(p.d.AccountClaim) - 1; i >= 0; i-- {
		claim = map[string]any{p.d.AccountClaim[i]: claim}
	}
	claims := claim.(map[string]any)
	if _, taken := claims["exp"]; !taken {
		claims["exp"] = time.Now().Add(365 * 24 * time.Hour).Unix()
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." + enc(claims) + "." + rnd()
}

func (p *Login) mint(account string) *planGuest {
	g := &planGuest{account: account, field: map[string]string{}, byField: map[string]string{}}
	for f := range p.token {
		if p.token[f].Kind != FieldCredential {
			continue
		}
		ph := "agentos-ph-" + strings.TrimSuffix(f, "_token") + "-" + rnd()
		if f == fID {
			ph = p.placeholderID(account)
		}
		g.field[ph], g.byField[f] = f, ph
	}
	return g
}

// guestFor returns guest's placeholders for account, minting them on first
// use or for a new account. mu must be held.
func (p *Login) guestFor(guest, account string) *planGuest {
	g := p.guests[guest]
	if g == nil || g.account != account {
		g = p.mint(account)
		p.guests[guest] = g
	}
	return g
}

// Guest returns guest's token set, for its auth file: placeholders only.
// It refuses a sign-in guest, a stopped route and a box not signed in.
func (p *Login) Guest(guest string) (Tokens, error) {
	if guest == "" {
		return Tokens{}, errors.New("clerk: a guest needs a name")
	}
	if p.Stopped() != "" {
		return Tokens{}, ErrStopped
	}
	st, err := p.load()
	if err != nil {
		return Tokens{}, err
	}
	if st.Tokens[fAccess] == "" {
		return Tokens{}, ErrNoLogin
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.signing[guest]; ok {
		return Tokens{}, errors.New("clerk: a sign-in guest holds no login")
	}
	g := p.guestFor(guest, st.Account)
	out := Tokens{Account: st.Account, Tokens: map[string]string{}}
	for f, ph := range g.byField {
		if st.Tokens[f] != "" || f == fID {
			out.Tokens[f] = ph
		}
	}
	return out, nil
}

// BeginSignIn marks guest as the owner's sign-in guest: the only guest that
// reaches the device and code steps, and whose code exchange may set the
// account. Its caller is the owner-started sign-in alone (CH-8); every other
// guest only refreshes the stored login. It refuses a guest that already
// holds placeholders and a route stopped as unswappable.
func (p *Login) BeginSignIn(guest string) error {
	if guest == "" {
		return errors.New("clerk: a guest needs a name")
	}
	if p.Stopped() == StopUnswappable {
		return ErrStopped
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.guests[guest] != nil {
		return errors.New("clerk: a run guest cannot become a sign-in guest")
	}
	p.signing[guest] = false
	return nil
}

// SignedIn reports whether guest's own sign-in committed the login. It is
// the sign-in's only success signal: a login stored before it does not
// count, and neither does anything the guest says about itself.
func (p *Login) SignedIn(guest string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signing[guest]
}

// Forget drops guest's placeholders and sign-in mark, when the guest is
// destroyed.
func (p *Login) Forget(guest string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.guests, guest)
	delete(p.signing, guest)
}

// resolve maps guest's own placeholder for field to the value the slot
// holds now. It never answers for another guest's placeholder.
func (p *Login) resolve(guest, field, ph string) (string, bool) {
	if ph == "" {
		return "", false
	}
	p.mu.Lock()
	g := p.guests[guest]
	ok := g != nil && g.field[ph] == field
	p.mu.Unlock()
	if !ok {
		return "", false
	}
	st, err := p.load()
	if err != nil || st.Tokens[field] == "" || st.Account != g.account {
		return "", false
	}
	return st.Tokens[field], true
}

func (p *Login) match(method, path string, signIn bool) (Endpoint, bool) {
	for _, e := range p.d.Endpoints {
		if e.Method == method && e.Path == path && e.Kind.signIn() == signIn {
			return e, true
		}
	}
	return Endpoint{}, false
}

// declaredQuery accepts only the endpoint's keys, each once with a plain
// value, and returns the clerk's own encoding.
func declaredQuery(e Endpoint, raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	for k, vs := range q {
		if !contains(e.Query, k) || len(vs) != 1 || !queryValue.MatchString(vs[0]) {
			return "", false
		}
	}
	return q.Encode(), true
}

func encoded(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		if !strings.EqualFold(strings.TrimSpace(v), "identity") {
			return true
		}
	}
	return false
}

func hasToken(h http.Header, name, token string) bool {
	for _, line := range h.Values(name) {
		for _, v := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(v), token) {
				return true
			}
		}
	}
	return false
}

// Do serves one request a guest made of its plan, and returns the answer to
// give the guest, or a detail with nothing for the guest. The request's
// method, path and query pick a declared endpoint; its host is the
// endpoint's, whatever the guest named. A model call is admitted and
// settled by meter, and is refused without one. The caller closes the
// answer's body.
func (p *Login) Do(ctx context.Context, guest string, r *http.Request, meter Meter) (*http.Response, string) {
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" || hasToken(r.Header, "Connection", "upgrade") ||
		r.URL.RawPath != "" || r.URL.Fragment != "" {
		return nil, DUndeclared
	}
	p.mu.Lock()
	_, signIn := p.signing[guest]
	p.mu.Unlock()
	e, ok := p.match(r.Method, r.URL.Path, signIn)
	if !ok {
		return nil, DUndeclared
	}
	if s := p.Stopped(); s == StopUnswappable || s != "" && !signIn {
		return nil, DStopped + " " + s
	}
	query, ok := declaredQuery(e, r.URL.RawQuery)
	if !ok {
		return nil, DUndeclared
	}
	if encoded(r.Header) {
		return nil, DEncoded
	}
	// A call that must carry the guest's placeholder is refused before its
	// body is read, so a caller holding none cannot make the clerk buffer
	// one.
	var real string
	if e.Kind == Model || e.Kind == Read {
		if real, ok = p.bearer(guest, r.Header); !ok {
			return nil, DPlaceholder
		}
	}
	limit := p.d.MaxBody
	if e.Kind != Model {
		limit = maxExchange
	}
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if err != nil || int64(len(b)) > limit {
			return nil, DUndeclared
		}
		body = b
	}
	switch e.Kind {
	case Refresh:
		return p.refresh(ctx, guest, r.Header, e, query, body)
	case Code:
		out, ok := p.checkCode(r.Header, body)
		if !ok {
			return nil, DUndeclared
		}
		up := p.upstream(ctx, r.Header, e, query, p.d.SignInHeaders, out)
		up.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ans, detail := p.exchange(up)
		if detail != "" {
			return nil, detail
		}
		return p.swap(ans, guest, true)
	case Device:
		out, ok := stringObject(body)
		if !ok {
			return nil, DUndeclared
		}
		up := p.upstream(ctx, r.Header, e, query, p.d.SignInHeaders, out)
		up.Header.Set("Content-Type", "application/json")
		return p.send(up, "")
	case Read:
		if len(body) != 0 {
			return nil, DUndeclared
		}
	case Model:
		if meter == nil {
			return nil, DUnmetered
		}
		out, rule := p.d.Body.check(body)
		if rule != "" {
			return nil, DBody + " " + rule
		}
		settle, detail := meter(out)
		if detail != "" {
			return nil, detail
		}
		up := p.upstream(ctx, r.Header, e, query, p.d.RequestHeaders, out)
		up.Header.Set("Authorization", "Bearer "+real)
		return p.sendModel(up, real, settle)
	}
	up := p.upstream(ctx, r.Header, e, query, p.d.RequestHeaders, body)
	up.Header.Set("Authorization", "Bearer "+real)
	return p.send(up, real)
}

// sendModel sends a metered model call. Its answer is read for its usage as
// it passes to the guest, and the call is settled once it ends; a call that
// gets no answer to pass is settled at once.
func (p *Login) sendModel(up *http.Request, real string, settle func(Used)) (*http.Response, string) {
	resp, err := p.client.Do(up)
	if err != nil {
		settle(Used{Sent: !errors.Is(err, netguard.ErrDenied)})
		return nil, dialDetail(err, up.URL.Hostname())
	}
	pool := p.d.Pool.reading(resp.Header)
	if encoded(resp.Header) {
		resp.Body.Close()
		settle(Used{Sent: true, Pool: pool})
		return nil, DEncoded
	}
	resp.Body = newMeterReader(resp, settle, pool)
	return p.answer(resp, real), ""
}

// bearer resolves the guest's own access placeholder from Authorization.
func (p *Login) bearer(guest string, h http.Header) (string, bool) {
	vs := h.Values("Authorization")
	if len(vs) != 1 {
		return "", false
	}
	ph, ok := strings.CutPrefix(vs[0], "Bearer ")
	if !ok || strings.ContainsAny(ph, " \t") {
		return "", false
	}
	return p.resolve(guest, fAccess, ph)
}

// upstream is the provider request for e, carrying the named headers of the
// guest's request and nothing else.
func (p *Login) upstream(ctx context.Context, h http.Header, e Endpoint, query string, pass []string, body []byte) *http.Request {
	// The host and path are the declaration's, checked at New.
	up, _ := http.NewRequestWithContext(ctx, e.Method, "https://"+e.Host+e.Path, nil)
	up.URL.RawQuery = query
	for _, k := range pass {
		for _, v := range h.Values(k) {
			up.Header.Add(k, v)
		}
	}
	up.Header.Set("Accept-Encoding", "identity")
	if len(body) > 0 {
		up.Body = io.NopCloser(bytes.NewReader(body))
		up.ContentLength = int64(len(body))
		up.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	return up
}

func dialDetail(err error, host string) string {
	if errors.Is(err, netguard.ErrDenied) {
		return clerk.DBlocked
	}
	return clerk.DNoAnswer + " " + host
}

// send makes a run or device request and returns its answer with only the
// declared headers, and real, if any, redacted from them and from the
// streamed body.
func (p *Login) send(up *http.Request, real string) (*http.Response, string) {
	resp, err := p.client.Do(up)
	if err != nil {
		return nil, dialDetail(err, up.URL.Hostname())
	}
	if encoded(resp.Header) {
		resp.Body.Close()
		return nil, DEncoded
	}
	return p.answer(resp, real), ""
}

// answer is resp as the guest gets it: the declared headers only, and
// real, if any, redacted from them and from the streamed body.
func (p *Login) answer(resp *http.Response, real string) *http.Response {
	out := &http.Response{StatusCode: resp.StatusCode, Status: resp.Status, Header: http.Header{}, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		ContentLength: -1, Body: resp.Body}
	for k, vs := range resp.Header {
		if !p.answerHeader(k) {
			continue
		}
		for _, v := range vs {
			if real != "" {
				v = strings.ReplaceAll(v, real, string(redacted))
			}
			out.Header.Add(k, v)
		}
	}
	if real != "" {
		out.Body = &redactReader{r: resp.Body, secret: []byte(real)}
	} else if resp.ContentLength >= 0 {
		out.ContentLength = resp.ContentLength
	}
	return out
}

func (p *Login) answerHeader(k string) bool {
	if forbiddenHeader(k) {
		return false
	}
	for _, n := range p.d.ResponseHeaders {
		if http.CanonicalHeaderKey(n) == k {
			return true
		}
	}
	for _, pre := range p.d.ResponsePrefixes {
		if strings.HasPrefix(k, http.CanonicalHeaderKey(pre)) {
			return true
		}
	}
	return false
}

// exchange makes a token request and reads its answer whole, bounded.
func (p *Login) exchange(up *http.Request) (*planAnswer, string) {
	resp, err := p.client.Do(up)
	if err != nil {
		return nil, dialDetail(err, up.URL.Hostname())
	}
	defer resp.Body.Close()
	if encoded(resp.Header) {
		return nil, DEncoded
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxExchange+1))
	if err != nil {
		return nil, clerk.DNoAnswer + " " + up.URL.Hostname()
	}
	if len(b) > maxExchange {
		return &planAnswer{status: resp.StatusCode, header: resp.Header, body: nil}, ""
	}
	return &planAnswer{status: resp.StatusCode, header: resp.Header, body: b}, ""
}

// refresh forwards the guest's token refresh: one flight per login, each
// joining guest's answer swapped to its own placeholders.
func (p *Login) refresh(ctx context.Context, guest string, h http.Header, e Endpoint, query string, body []byte) (*http.Response, string) {
	if _, ok := p.checkRefresh(guest, body); !ok {
		return nil, DPlaceholder
	}
	ans, detail, done := p.share(ctx, func() (*planAnswer, string) {
		// Resolved again inside the flight: one that ended since the check
		// above may have committed a newer token. The login's generation is
		// read with the token, under the commit lock, so the answer is
		// judged against exactly the login whose token it spent.
		p.cmu.Lock()
		gen := p.generation()
		out, ok := p.checkRefresh(guest, body)
		p.cmu.Unlock()
		if !ok {
			return nil, DPlaceholder
		}
		xctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exchangeFor)
		defer cancel()
		up := p.upstream(xctx, h, e, query, p.d.RequestHeaders, out)
		up.Header.Set("Content-Type", "application/json")
		ans, detail := p.exchange(up)
		if detail == "" {
			ans.refresh, ans.gen = true, gen
			if p.refusedLogin(ans) {
				p.stopFor(ans, StopRefused)
			}
		}
		return ans, detail
	})
	defer done()
	if detail != "" {
		return nil, detail
	}
	return p.swap(ans, guest, false)
}

// share runs exchange, or joins the one in flight and waits for its answer.
// done must be called once the caller has committed or dropped the answer.
func (p *Login) share(ctx context.Context, exchange func() (*planAnswer, string)) (*planAnswer, string, func()) {
	p.fmu.Lock()
	fl := p.flight
	leader := fl == nil
	if leader {
		fl = &planFlight{ready: make(chan struct{}), detail: DExchange}
		p.flight = fl
	}
	fl.members++
	p.fmu.Unlock()
	var once sync.Once
	done := func() {
		once.Do(func() {
			p.fmu.Lock()
			defer p.fmu.Unlock()
			if fl.members--; fl.members == 0 && p.flight == fl {
				p.flight = nil
			}
		})
	}
	if leader {
		func() {
			defer close(fl.ready)
			fl.ans, fl.detail = exchange()
		}()
		return fl.ans, fl.detail, done
	}
	select {
	case <-fl.ready:
		return fl.ans, fl.detail, done
	case <-ctx.Done():
		return nil, DExchange, done
	}
}

// refusedLogin reports whether a refresh answer is the provider refusing the
// login: 400 or 401 with a declared code.
func (p *Login) refusedLogin(a *planAnswer) bool {
	if a.status != http.StatusBadRequest && a.status != http.StatusUnauthorized || a.body == nil {
		return false
	}
	var obj struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(a.body, &obj) != nil {
		return false
	}
	var code string
	if json.Unmarshal(obj.Error, &code) != nil {
		var nested struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(obj.Error, &nested) != nil {
			return false
		}
		code = nested.Code
	}
	return code != "" && p.refused[code]
}

// checkRefresh holds a refresh body to its declared keys, all strings, with
// grant_type refresh_token and the guest's own refresh placeholder, and
// returns it with the real refresh token in its place.
func (p *Login) checkRefresh(guest string, body []byte) ([]byte, bool) {
	obj, err := strictObject(body)
	if err != nil {
		return nil, false
	}
	for k, v := range obj {
		if _, ok := v.(string); !ok || !contains(p.d.RefreshKeys, k) {
			return nil, false
		}
	}
	if obj["grant_type"] != "refresh_token" {
		return nil, false
	}
	ph, _ := obj[fRefresh].(string)
	real, ok := p.resolve(guest, fRefresh, ph)
	if !ok {
		return nil, false
	}
	obj[fRefresh] = real
	out, err := encodeJSON(obj)
	return out, err == nil
}

// checkCode admits the code exchange in its exact form, and rewrites the
// CLI's callback to the one the provider bound the code to.
func (p *Login) checkCode(h http.Header, body []byte) ([]byte, bool) {
	if mt, _, err := mime.ParseMediaType(h.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		return nil, false
	}
	f, err := url.ParseQuery(string(body))
	if err != nil || len(f) != len(codeKeys) || p.d.RedirectFrom == "" {
		return nil, false
	}
	for _, k := range codeKeys {
		if vs := f[k]; len(vs) != 1 || vs[0] == "" {
			return nil, false
		}
	}
	if f.Get("grant_type") != "authorization_code" || f.Get("redirect_uri") != p.d.RedirectFrom {
		return nil, false
	}
	f.Set("redirect_uri", p.d.RedirectTo)
	return []byte(f.Encode()), true
}

// stringObject admits a JSON object of short strings only.
func stringObject(body []byte) ([]byte, bool) {
	obj, err := strictObject(body)
	if err != nil {
		return nil, false
	}
	for _, v := range obj {
		if s, ok := v.(string); !ok || len(s) > maxDevice {
			return nil, false
		}
	}
	out, err := encodeJSON(obj)
	return out, err == nil
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

// tokenAnswer checks a 200 answer against the declared shape and returns
// its object and credentials.
func (p *Login) tokenAnswer(a *planAnswer) (map[string]any, map[string]string, bool) {
	if mt, _, err := mime.ParseMediaType(a.header.Get("Content-Type")); err != nil || mt != "application/json" || a.body == nil {
		return nil, nil, false
	}
	obj, err := strictObject(a.body)
	if err != nil {
		return nil, nil, false
	}
	for name, f := range p.token {
		if _, ok := obj[name]; !ok && !f.Optional {
			return nil, nil, false
		}
	}
	creds := map[string]string{}
	for k, v := range obj {
		f := p.token[k]
		if f == nil || !f.admits(v) {
			return nil, nil, false
		}
		if f.Kind == FieldCredential {
			creds[k] = v.(string)
		}
	}
	return obj, creds, true
}

func (f *Field) admits(v any) bool {
	switch f.Kind {
	case FieldCredential:
		s, ok := v.(string)
		return ok && s != ""
	case FieldNumber:
		n, ok := v.(json.Number)
		return ok && len(n) <= maxNumber
	case FieldBool:
		_, ok := v.(bool)
		return ok
	case FieldText:
		s, ok := v.(string)
		return ok && len(s) <= maxText && f.re.MatchString(s)
	}
	return false
}

// swap answers a token exchange (CLK-7): it reaches the guest only with
// every credential swapped for that guest's placeholder, and only after the
// slot holds the login, since the provider's refresh tokens are single-use.
// An error answer is dropped. An answer out of shape, with no account, or
// naming another account on a refresh is dropped and stops the route. A
// refresh answer to a login the owner has since removed or replaced is
// dropped and stops nothing (DStale).
func (p *Login) swap(a *planAnswer, guest string, signIn bool) (*http.Response, string) {
	if p.stale(a) {
		return nil, DStale
	}
	if a.status != http.StatusOK {
		return nil, DExchange + fmt.Sprintf(" http %d", a.status)
	}
	obj, creds, ok := p.tokenAnswer(a)
	acct := ""
	if ok {
		acct = p.accountOf(creds[fID])
	}
	if acct == "" {
		p.stopFor(a, StopUnswappable)
		return nil, DUnswappable
	}
	p.cmu.Lock()
	st, err := p.load()
	p.mu.Lock()
	held := p.held
	p.mu.Unlock()
	switch {
	case p.stale(a):
		p.cmu.Unlock()
		return nil, DStale
	case err != nil:
		p.cmu.Unlock()
		return nil, DSave
	case higher(st.Stop, held) == StopUnswappable:
		p.cmu.Unlock()
		return nil, DStopped + " " + StopUnswappable
	case !signIn && (st.Tokens[fAccess] == "" || acct != st.Account):
		// A guest only refreshes: with no login stored this refuses a
		// first sign-in as well as an account change.
		p.cmu.Unlock()
		p.stopFor(a, StopUnswappable)
		return nil, DUnswappable
	}
	next := planState{Tokens: map[string]string{}, Account: acct, Stop: st.Stop, Version: st.Version}
	if acct == st.Account {
		for k, v := range st.Tokens {
			next.Tokens[k] = v
		}
	}
	for k, v := range creds {
		next.Tokens[k] = v
	}
	if signIn && next.Stop == StopRefused {
		next.Stop, next.Version = "", "" // signing in again answers a refused login
	}
	if next.Tokens[fAccess] == "" || next.Tokens[fRefresh] == "" {
		p.cmu.Unlock()
		p.stopFor(a, StopUnswappable)
		return nil, DUnswappable
	}
	p.mu.Lock()
	g := p.guests[guest]
	if g == nil || g.account != acct {
		g = p.mint(acct)
	}
	p.mu.Unlock()
	for k := range creds {
		ph := g.byField[k]
		for _, v := range creds {
			if ph == "" || strings.Contains(ph, v) {
				p.cmu.Unlock()
				return nil, DUnswappable
			}
		}
		obj[k] = ph
	}
	if err := p.save(next); err != nil {
		p.cmu.Unlock()
		return nil, DSave
	}
	p.mu.Lock()
	p.guests[guest] = g
	if signIn {
		p.signing[guest] = true
		p.gen++
		if p.held == StopRefused {
			p.held = ""
		}
	}
	p.mu.Unlock()
	p.cmu.Unlock()
	out, err := encodeJSON(obj)
	if err != nil {
		return nil, DUnswappable
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: h, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		ContentLength: int64(len(out)), Body: io.NopCloser(bytes.NewReader(out))}, ""
}

// redactReader replaces secret in a streamed body. It holds back only a
// tail that could begin the secret, so a stream is not delayed by more than
// a partial match.
type redactReader struct {
	r      io.ReadCloser
	secret []byte
	pend   []byte // read, not yet safe to release
	out    []byte // safe to release
	err    error
}

func (x *redactReader) Read(b []byte) (int, error) {
	for len(x.out) == 0 {
		if x.err != nil {
			return 0, x.err
		}
		chunk := make([]byte, 32<<10)
		n, err := x.r.Read(chunk)
		x.pend = bytes.ReplaceAll(append(x.pend, chunk[:n]...), x.secret, redacted)
		if err != nil {
			x.out, x.pend, x.err = x.pend, nil, err
			continue
		}
		keep := partial(x.pend, x.secret)
		x.out = append([]byte(nil), x.pend[:len(x.pend)-keep]...)
		x.pend = append([]byte(nil), x.pend[len(x.pend)-keep:]...)
	}
	n := copy(b, x.out)
	x.out = x.out[n:]
	return n, nil
}

func (x *redactReader) Close() error { return x.r.Close() }

// partial is the length of the longest tail of b that is a proper prefix of
// secret.
func partial(b, secret []byte) int {
	k := min(len(b), len(secret)-1)
	for i := len(b) - k; i < len(b); i++ {
		if b[i] == secret[0] && bytes.HasPrefix(secret, b[i:]) {
			return len(b) - i
		}
	}
	return 0
}

// Codex is the Codex CLI's plan route as measured on CLI 0.162.1 (#809):
// the ChatGPT plan's model and models endpoints, the refresh, and the
// device-code sign-in, with the CLI's local callback rewritten to the auth
// host's. Its version moves with every release that requalifies it.
func Codex(guard *netguard.Policy) Declaration {
	const run, auth = "chatgpt.com", "auth.openai.com"
	return Declaration{
		Name:    "codex",
		Version: "codex-0.162.1-1",
		Endpoints: []Endpoint{
			{Name: "responses", Host: run, Method: "POST", Path: "/backend-api/codex/responses", Kind: Model},
			{Name: "models", Host: run, Method: "GET", Path: "/backend-api/codex/models", Kind: Read, Query: []string{"client_version"}},
			{Name: "refresh", Host: auth, Method: "POST", Path: "/oauth/token", Kind: Refresh},
			{Name: "usercode", Host: auth, Method: "POST", Path: "/api/accounts/deviceauth/usercode", Kind: Device},
			{Name: "devicetoken", Host: auth, Method: "POST", Path: "/api/accounts/deviceauth/token", Kind: Device},
			{Name: "code", Host: auth, Method: "POST", Path: "/oauth/token", Kind: Code},
		},
		Token: []Field{
			{Name: fAccess, Kind: FieldCredential},
			{Name: fRefresh, Kind: FieldCredential, Optional: true},
			{Name: fID, Kind: FieldCredential, Optional: true},
			{Name: "expires_in", Kind: FieldNumber, Optional: true},
			{Name: "token_type", Kind: FieldText, Pattern: `[Bb]earer`, Optional: true},
			{Name: "scope", Kind: FieldText, Pattern: `[a-z_.: ]{1,200}`, Optional: true},
		},
		AccountClaim: []string{"https://api.openai.com/auth", "chatgpt_account_id"},
		// The refresh failures the CLI itself treats as a dead login
		// (codex-rs auth). invalid_grant is not one: a guest can provoke it.
		Refused:      []string{"refresh_token_expired", "refresh_token_reused", "refresh_token_invalidated"},
		RefreshKeys:  []string{"client_id", "grant_type", fRefresh, "scope"},
		RedirectFrom: "http://127.0.0.1:18432/deviceauth/callback",
		RedirectTo:   "https://" + auth + "/deviceauth/callback",
		RequestHeaders: []string{
			"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
			"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
		},
		SignInHeaders:    []string{"Accept", "Content-Type", "User-Agent", "Originator"},
		ResponseHeaders:  []string{"Content-Type", "Retry-After", "X-Request-Id", "Openai-Model"},
		ResponsePrefixes: []string{"X-Codex-"},
		// The CLI's request: #809 saw model, input, tool_choice, include
		// and stream; the rest are the fields the CLI's request type sets.
		Body: Body{
			Keys: []string{
				"model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
				"reasoning", "store", "stream", "include", "prompt_cache_key", "text", "client_metadata",
			},
			InputTypes: []string{
				"message", "reasoning", "function_call", "function_call_output",
				"custom_tool_call", "custom_tool_call_output", "additional_tools",
			},
			ContentTypes: []string{"input_text", "output_text", "input_image"},
			ToolTypes:    clientToolTypes,
			Stream:       true,
			// The tools CLI 0.162.1 declares in code mode under the image's
			// managed config, as captured (#809): all in an additional_tools
			// item.
			Tools: []Tool{
				{"functions", "exec", "custom"},
				{"functions", "wait", "function"},
				{"functions", "request_user_input", "function"},
				{"functions", "request_user_input_async", "function"},
				{"clock", "sleep", "function"},
				{"collaboration", "followup_task", "function"},
				{"collaboration", "interrupt_agent", "function"},
				{"collaboration", "list_agents", "function"},
				{"collaboration", "send_message", "function"},
				{"collaboration", "spawn_agent", "function"},
				{"collaboration", "wait_agent", "function"},
			},
		},
		// The 5-hour and weekly windows of the one Codex pool (#809).
		Pool:  Pool{Windows: []string{"X-Codex-Primary-", "X-Codex-Secondary-"}, Reached: "X-Codex-Rate-Limit-Reached-Type"},
		Guard: guard,
	}
}
