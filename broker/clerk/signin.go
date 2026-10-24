package clerk

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// SignInDeclaration is one API account's installed-app OAuth sign-in (D-150,
// RFC 8252): where consent happens, where the code is redeemed and the grant
// revoked, the loopback address consent returns to, and the one scope each
// declared use asks for (CLK-9). Gmail is the first (inbox.GmailSignIn).
type SignInDeclaration struct {
	Name string
	// Auth is the provider's consent page. The clerk never dials it: the
	// owner opens the address Begin gives on their own phone.
	Auth string
	// Token is the token endpoint the code is redeemed at, the one the
	// account's API declaration names as Refresh. Revoke is its revocation
	// endpoint (RFC 7009), "" for a provider without one.
	Token, Revoke string
	// Redirect is a loopback address that nobody listens on: the browser
	// fails to load it, and the owner pastes the address it shows.
	Redirect string
	// Uses maps each declared use to its one scope; Begin asks for no other.
	Uses map[string]string
	// Params are constant consent-page parameters, such as Google's
	// access_type=offline, which a refresh grant needs.
	Params map[string]string
	// Slot is the account's grant slot, the one its API declaration uses.
	Slot  string
	Guard *netguard.Policy
	Clock Clock
}

// Registration is the household's own client (D-150): its ID and secret,
// sealed with the grant (CLK-1). RFC 8252 section 8.5 says an installed app's
// secret is not confidential, but it is held as if it were.
type Registration struct {
	ID, Secret string
}

// The sign-in's details: typed, carrying no value from the pasted address,
// the provider's answer or a secret (CLK-4).
const (
	DSignedIn   = "signedin"   // the grant is sealed; then the use
	DNoSignIn   = "nosignin"   // no sign-in is waiting, or it ran out
	DNotOurs    = "notours"    // the pasted address is not the declared loopback one
	DState      = "state"      // the pasted state is not this sign-in's
	DRefused    = "refused"    // the owner said no on the consent page
	DScope      = "scope"      // the grant is not exactly the asked scope; it was revoked
	DNoGrant    = "nogrant"    // the provider gave no refresh token
	DExchange   = "exchange"   // the code was not redeemed; then "http N", if it answered
	DRevoked    = "revoked"    // the grant is revoked and removed
	DNoRevoke   = "norevoke"   // the provider kept the grant; then "http N", if it answered
	DNoAccount  = "noaccount"  // no grant is sealed, and no registration was given
	DRegistered = "registered" // a registration was given, but its ID or secret is not plain
)

// signInLife is how long a begun sign-in waits for its paste, in ms.
const signInLife = 15 * 60 * 1000

// SignIn is the account clerk's own side of an installed-app sign-in: PKCE
// S256 (RFC 7636), a state value, and the code redeemed by the clerk itself
// through its guarded transport. Only the consent address leaves it, and
// only the pasted address comes in; the verifier, the code's answer, the
// tokens and the client secret stay in this process (D-154: the owner page
// relays one frame each way). One sign-in waits at a time; a new Begin
// replaces it.
type SignIn struct {
	d       SignInDeclaration
	secrets *Secrets
	client  *http.Client
	// Saved, if set, is told of each grant once it is sealed, so a running
	// API clerk on the same slot drops its refused state (API.Reconnect).
	Saved func(grant []byte) error

	mu      sync.Mutex
	pending *pending
}

type pending struct {
	state, verifier, use, scope string
	reg                         Registration
	until                       int64
}

// NewSignIn validates the declaration. secrets is the account clerk's own
// store, holding no other account's slot (CLK-1); roots nil trusts the
// system's certificate authorities.
func NewSignIn(d SignInDeclaration, secrets *Secrets, roots *x509.CertPool) (*SignIn, error) {
	if d.Name == "" || d.Slot == "" || len(d.Uses) == 0 {
		return nil, errors.New("clerk: a sign-in needs a name, a slot and its uses")
	}
	if d.Guard == nil {
		return nil, errors.New("clerk: a sign-in needs the home-network policy (DEV-2)")
	}
	for i, e := range []string{d.Auth, d.Token, d.Revoke} {
		if i == 2 && e == "" { // a provider without a revocation endpoint
			continue
		}
		if u, err := url.Parse(e); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || strings.Contains(e, "#") {
			return nil, errors.New("clerk: a sign-in endpoint needs a plain https URL")
		}
	}
	if u, err := url.Parse(d.Redirect); err != nil || !loopback(u) {
		return nil, errors.New("clerk: a sign-in returns only to a plain http loopback address (RFC 8252 section 7.3)")
	}
	for use, scope := range d.Uses {
		if use == "" || scope == "" || strings.ContainsAny(scope, " \t") || !plain(scope) {
			return nil, errors.New("clerk: each use asks for one plain scope")
		}
	}
	for k := range d.Params {
		if slices.Contains(ownParams, k) {
			return nil, errors.New("clerk: a sign-in parameter may not replace the clerk's own")
		}
	}
	if n := secrets.Len(); n > 1 || n == 1 && !secrets.Has(d.Slot) {
		return nil, errors.New("clerk: the secret store holds another account's secret (CLK-1)")
	}
	return &SignIn{d: d, secrets: secrets, client: guarded(d.Guard, roots)}, nil
}

// ownParams are the consent-page parameters the clerk sets itself.
var ownParams = []string{"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"}

func loopback(u *url.URL) bool {
	h := u.Hostname()
	return u.Scheme == "http" && (h == "127.0.0.1" || h == "::1") && u.Port() != "" &&
		u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// Begin starts a sign-in for one declared use and returns the consent
// address, which carries the client ID, the scope, the state and the
// verifier's challenge, and nothing secret. reg is the household's client,
// given at its first sign-in; nil signs in again with the client sealed in
// the account's current grant, so a reconnect needs no secret from outside.
func (s *SignIn) Begin(use string, reg *Registration) (string, error) {
	scope, ok := s.d.Uses[use]
	if !ok {
		return "", errors.New(DUndeclared)
	}
	var r Registration
	if reg != nil {
		r = *reg
		if r.ID == "" || r.Secret == "" || !plain(r.ID) || !plain(r.Secret) {
			return "", errors.New(DRegistered)
		}
	} else if err := s.secrets.with(s.d.Slot, KindGrant, func(g []byte) error {
		m, err := readGrant(g)
		r = Registration{m["client_id"], m["client_secret"]}
		return err
	}); err != nil || r.ID == "" {
		return "", errors.New(DNoAccount)
	}
	p := &pending{state: random(), verifier: random(), use: use, scope: scope, reg: r, until: s.d.Clock.Now() + signInLife}
	sum := sha256.Sum256([]byte(p.verifier))
	q := url.Values{}
	for k, v := range s.d.Params {
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", r.ID)
	q.Set("redirect_uri", s.d.Redirect)
	q.Set("scope", scope)
	q.Set("state", p.state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	s.mu.Lock()
	s.pending = p
	s.mu.Unlock()
	return s.d.Auth + "?" + q.Encode(), nil
}

// random is 32 bytes from the clerk's own entropy (D-154 rule 5), base64url:
// a 43-character PKCE verifier (RFC 7636 section 4.1) or a state value.
func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("clerk: no entropy")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Finish takes the address the owner pasted, redeems its code and seals the
// grant, with the registration's client, in the account's slot. A paste of
// the declared loopback address ends the waiting sign-in whatever it holds,
// so a code or state is never tried twice. It returns "signedin <use>" or a
// typed detail; nothing it returns carries a value.
func (s *SignIn) Finish(ctx context.Context, pasted string) string {
	u, err := url.Parse(strings.TrimSpace(pasted))
	want, _ := url.Parse(s.d.Redirect)
	if err != nil || u.Scheme != want.Scheme || u.Host != want.Host || u.Path != want.Path || u.User != nil {
		return DNotOurs
	}
	s.mu.Lock()
	p := s.pending
	s.pending = nil
	s.mu.Unlock()
	if p == nil || s.d.Clock.Now() > p.until {
		return DNoSignIn
	}
	q := u.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.state)) != 1 {
		return DState
	}
	if q.Get("error") != "" {
		return DRefused
	}
	code := q.Get("code")
	if code == "" || !plain(code) {
		return DExchange
	}
	t, status := s.exchange(ctx, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {p.verifier},
		"redirect_uri": {s.d.Redirect}, "client_id": {p.reg.ID}, "client_secret": {p.reg.Secret},
	})
	switch {
	case status == 0:
		return DExchange
	case status/100 != 2 || t.Access == "" && t.Refresh == "":
		return DExchange + " http " + strconv.Itoa(status)
	}
	// The scope granted is the one asked, no wider and no narrower (CLK-9).
	// A provider that adds earlier grants (include_granted_scopes) answers
	// wider; the grant is revoked rather than kept.
	if t.Scope != p.scope {
		s.revoke(ctx, t.Refresh, t.Access)
		return DScope
	}
	if t.Refresh == "" || !plain(t.Refresh) {
		s.revoke(ctx, "", t.Access)
		return DNoGrant
	}
	g, _ := json.Marshal(map[string]string{"refresh_token": t.Refresh, "client_id": p.reg.ID, "client_secret": p.reg.Secret})
	defer clear(g)
	if err := s.secrets.Put(s.d.Slot, KindGrant, g); err != nil {
		return DCredential
	}
	if s.Saved != nil && s.Saved(g) != nil {
		return DCredential
	}
	return DSignedIn + " " + p.use
}

// signInAnswer is a token endpoint's answer to a code (RFC 6749 section 5.1).
type signInAnswer struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Scope   string `json:"scope"`
}

func (s *SignIn) exchange(ctx context.Context, form url.Values) (signInAnswer, int) {
	var t signInAnswer
	status, body := s.post(ctx, s.d.Token, form)
	defer clear(body)
	if status/100 == 2 && json.Unmarshal(body, &t) != nil {
		return signInAnswer{}, status
	}
	return t, status
}

// post sends one form to a declared endpoint through the guarded transport
// and returns the status, 0 for no answer, and at most 1 MiB of the body.
func (s *SignIn) post(ctx context.Context, endpoint string, form url.Values) (int, []byte) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-Type", TypeForm)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b
}

// revoke asks the provider to drop a token, refresh first (which drops the
// grant with it), and reports the status.
func (s *SignIn) revoke(ctx context.Context, tokens ...string) int {
	if s.d.Revoke == "" {
		return 0
	}
	for _, t := range tokens {
		if t != "" {
			st, _ := s.post(ctx, s.d.Revoke, url.Values{"token": {t}})
			return st
		}
	}
	return 0
}

// Revoke is the box cutting itself off: it revokes the account's grant at
// the provider and removes it from the slot. A grant the provider no longer
// knows (400, RFC 7009 section 2.2) is dead already and is removed too; any
// other refusal keeps it, so the owner can try again or revoke it in their
// account, and says "norevoke".
func (s *SignIn) Revoke(ctx context.Context) string {
	var refresh string
	if err := s.secrets.with(s.d.Slot, KindGrant, func(g []byte) error {
		m, err := readGrant(g)
		refresh = m["refresh_token"]
		return err
	}); err != nil {
		return DNoAccount
	}
	if s.d.Revoke == "" {
		return DNoRevoke
	}
	switch st := s.revoke(ctx, refresh); {
	case st == 0:
		return DNoRevoke
	case st/100 != 2 && st != 400:
		return DNoRevoke + " http " + strconv.Itoa(st)
	}
	if s.secrets.Remove(s.d.Slot) != nil {
		return DCredential
	}
	s.mu.Lock()
	s.pending = nil
	s.mu.Unlock()
	return DRevoked
}

// Uses lists the declared uses, sorted.
func (s *SignIn) Uses() []string { return slices.Sorted(maps.Keys(s.d.Uses)) }
