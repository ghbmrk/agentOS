package egress

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// A plan login (CRED-5, broker-held) is one vault entry per provider: the
// token set the provider's CLI would keep in its own auth file. The CLI in a
// worker holds placeholders instead, and the proxy swaps them at the
// declared endpoints (#1014). This file is the vault side: it stores the
// login, mints per-worker placeholders, and resolves them back.

// Reasons a plan login refuses. ErrVaultLocked's text is the refusal
// reason the route reports.
var (
	ErrVaultLocked = errors.New("vault-locked")
	ErrNoLogin     = errors.New("no plan login stored")
	// ErrNotRefresh refuses a worker's swap that would create the login or
	// change its account: only the owner's sign-in does that (ForSignIn).
	ErrNotRefresh = errors.New("plan login: only the owner's sign-in sets the account")
)

// LoginKind is the vault kind of a plan login entry.
const LoginKind = vault.KindPlanLogin

// LoginStore is the part of the vault a plan login needs.
type LoginStore interface {
	Put(name, kind string, value []byte) error
	Delete(name string) error
	Secret(name string) (vault.Secret, bool)
}

// PlanLogins holds plan logins in the vault and the placeholders workers
// hold in their place. Placeholders are per worker (ASSUMPTIONS): one
// worker's placeholder resolves for no other.
type PlanLogins struct {
	open   func() (LoginStore, error)
	revoke map[string]string

	mu sync.Mutex
	// byWorker[provider][worker] is that worker's current placeholders.
	byWorker map[string]map[string]*workerPH
	// signedBy[provider][worker] is set when that worker's sign-in swap
	// (ForSignIn) committed a login: the one record that this sign-in, and
	// not an earlier one, stored the login (SignedInBy).
	signedBy map[string]map[string]bool

	// commitMu[provider] is held by a commit from its load to its Put
	// (#1749), so no commit writes back a token set another one replaced.
	commitMu map[string]*sync.Mutex

	refreshFlights
}

// commitLock returns the provider's commit lock.
func (p *PlanLogins) commitLock(provider string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commitMu == nil {
		p.commitMu = map[string]*sync.Mutex{}
	}
	m := p.commitMu[provider]
	if m == nil {
		m = &sync.Mutex{}
		p.commitMu[provider] = m
	}
	return m
}

// refreshFlights runs at most one refresh exchange per provider at a time
// (#1749). One plan login serves every worker of the box and its refresh
// token is single-use, so a second exchange of the same token is refused
// and stops the route for all of them. A refresh that arrives while one is
// in flight joins it and gets the same answer; each worker then swaps that
// answer for its own placeholders. The flight ends when the last worker
// that joined it is done, so the next flight resolves the token they
// committed and no commit of an older answer lands after a newer one.
type refreshFlights struct {
	fmu     sync.Mutex
	flights map[string]*refreshFlight
}

type refreshFlight struct {
	ready   chan struct{}
	res     *Exchanged
	err     error
	joined  int // refreshes that joined the leader's exchange
	members int // refreshes not yet done with this flight
}

// errFlightAbandoned answers a flight whose exchange ended without a result.
var errFlightAbandoned = errors.New("refresh abandoned")

// ShareRefresh runs exchange for provider, or joins the exchange already in
// flight and waits for its answer. done must be called once the caller has
// committed (or dropped) the answer; until every member is done, a new
// refresh joins this flight rather than starting another.
func (f *refreshFlights) ShareRefresh(ctx context.Context, provider string, exchange func() (*Exchanged, error)) (*Exchanged, func(), error) {
	f.fmu.Lock()
	if f.flights == nil {
		f.flights = map[string]*refreshFlight{}
	}
	fl := f.flights[provider]
	leader := fl == nil
	if leader {
		fl = &refreshFlight{ready: make(chan struct{}), err: errFlightAbandoned}
		f.flights[provider] = fl
	} else {
		fl.joined++
	}
	fl.members++
	f.fmu.Unlock()
	var once sync.Once
	done := func() {
		once.Do(func() {
			f.fmu.Lock()
			defer f.fmu.Unlock()
			if fl.members--; fl.members == 0 && f.flights[provider] == fl {
				delete(f.flights, provider)
			}
		})
	}
	if leader {
		func() {
			defer close(fl.ready)
			fl.res, fl.err = exchange()
		}()
		return fl.res, done, fl.err
	}
	select {
	case <-fl.ready:
		return fl.res, done, fl.err
	case <-ctx.Done():
		return nil, done, ctx.Err()
	}
}

// joined reports how many refreshes joined provider's flight in progress.
func (f *refreshFlights) joined(provider string) int {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	if fl := f.flights[provider]; fl != nil {
		return fl.joined
	}
	return 0
}

type workerPH struct {
	account string            // the account ID the id_token placeholder carries
	field   map[string]string // placeholder -> login field
	byKey   map[string]string // login field -> placeholder
}

// NewPlanLogins returns the store. open yields the unlocked vault or
// ErrVaultLocked. revoke maps each provider to the place the owner revokes
// the login (W9).
func NewPlanLogins(open func() (LoginStore, error), revoke map[string]string) *PlanLogins {
	return &PlanLogins{open: open, revoke: revoke, byWorker: map[string]map[string]*workerPH{}, signedBy: map[string]map[string]bool{}}
}

func entryName(provider string) string { return "plan-login-" + provider }

// loginFields are the credential fields of a token set.
var loginFields = []string{"access_token", "refresh_token", "id_token"}

func (p *PlanLogins) load(provider string) (map[string]string, LoginStore, error) {
	st, err := p.open()
	if err != nil {
		return nil, nil, err
	}
	sec, ok := st.Secret(entryName(provider))
	if !ok {
		return nil, st, ErrNoLogin
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(sec.Reveal()), &m); err != nil {
		return nil, st, errors.New("plan login unreadable")
	}
	return m, st, nil
}

// Signed reports whether provider's plan login is stored: the owner has
// signed in. It never reads the login's values. ErrVaultLocked while the
// vault is not open.
func (p *PlanLogins) Signed(provider string) (bool, error) {
	st, err := p.open()
	if err != nil {
		return false, err
	}
	_, ok := st.Secret(entryName(provider))
	return ok, nil
}

// SignedInBy reports whether worker's own sign-in (ForSignIn) committed
// provider's login to the vault. It is the sign-in's only success signal:
// a login stored before it (an earlier, perhaps refused, one) does not
// count, and neither does anything the worker says about itself. Forget
// and Remove clear it.
func (p *PlanLogins) SignedInBy(provider, worker string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signedBy[provider][worker]
}

// ForWorker returns the Swapper for one worker's refresh responses. Its
// placeholders belong to that worker alone. It only refreshes the stored
// login: a response with no login stored, or naming another account, is
// refused (ErrNotRefresh), so a process in one worker that signs in to its
// own account cannot become the box's login.
func (p *PlanLogins) ForWorker(provider, worker string) Swapper {
	return &workerSwapper{p: p, provider: provider, worker: worker}
}

// ForSignIn returns the Swapper for the owner's sign-in in a fresh worker
// (the sign-in flow the owner starts, ONB step 6). It may create the login
// or replace it with another account's. Its caller is that owner-started
// flow alone; a worker's own traffic gets ForWorker.
func (p *PlanLogins) ForSignIn(provider, worker string) Swapper {
	return &workerSwapper{p: p, provider: provider, worker: worker, signIn: true}
}

type workerSwapper struct {
	p                *PlanLogins
	provider, worker string
	signIn           bool
}

func rnd() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("login: no randomness")
	}
	return hex.EncodeToString(b)
}

// accountOf reads the account ID from an id_token's claims. The token is
// not verified: it is the provider's own answer on the pinned connection.
func accountOf(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Auth struct {
			Account string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.Auth.Account
}

// placeholderIDToken is an unsigned id_token that carries the account ID
// and nothing else: no email, no plan claims (the CLI does not verify it).
func placeholderIDToken(account string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
		enc(map[string]any{
			"exp":                         time.Now().Add(365 * 24 * time.Hour).Unix(),
			"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account},
		}) + "." + rnd()
}

func (p *PlanLogins) mint(account string) (*workerPH, map[string]string) {
	w := &workerPH{account: account, field: map[string]string{}, byKey: map[string]string{}}
	phs := map[string]string{
		"access_token":  "agentos-ph-access-" + rnd(),
		"refresh_token": "agentos-ph-refresh-" + rnd(),
		"id_token":      placeholderIDToken(account),
	}
	for k, v := range phs {
		w.field[v] = k
		w.byKey[k] = v
	}
	return w, phs
}

// Swap implements Swapper for one worker. It stores nothing: commit writes
// the whole token set to the vault in one write, then installs the
// worker's placeholders, so the vault holds the new login before the
// proxy releases the response (single-use refresh tokens, CRED-5b).
func (s *workerSwapper) Swap(adapter string, creds map[string]string) (map[string]string, func() error, error) {
	p := s.p
	if adapter != s.provider {
		return nil, nil, errors.New("plan login: wrong adapter")
	}
	cur, _, err := p.load(s.provider)
	if err != nil && !errors.Is(err, ErrNoLogin) {
		return nil, nil, err
	}
	next, err := mergeLogin(cur, creds)
	if err != nil {
		return nil, nil, err
	}
	// Every response must name its account in an id_token: tokens with no
	// account could belong to anyone, so none is ever assumed (fail closed).
	acct := accountOf(creds["id_token"])
	if acct == "" {
		return nil, nil, errors.New("plan login: no account ID")
	}
	// A worker only refreshes: with no login stored, cur has no account, so
	// this refuses a worker's first sign-in as well as an account change.
	if !s.signIn && acct != cur["account_id"] {
		return nil, nil, ErrNotRefresh
	}
	next["account_id"] = acct
	if _, err := json.Marshal(next); err != nil {
		return nil, nil, err
	}
	// A worker keeps its placeholders across refreshes: each one stands for
	// a login field, not a value, so it resolves to whatever the vault
	// holds now. A refresh that omits a field, or a CLI that fails to write
	// the swapped response back, leaves the worker's auth file working.
	// Only a new account mints new ones (its id_token carries the account).
	p.mu.Lock()
	w := p.byWorker[s.provider][s.worker]
	p.mu.Unlock()
	if w == nil || w.account != acct {
		w, _ = p.mint(acct)
	}
	out := map[string]string{}
	for k := range creds {
		if ph, ok := w.byKey[k]; ok {
			out[k] = ph
		}
	}
	// commit merges the answer into the login as it stands at commit time,
	// under the provider's lock from that load to the Put (#1749): an
	// answer that omits a field keeps the value another commit stored since
	// this swap loaded, not the older one.
	commit := func() error {
		mu := p.commitLock(s.provider)
		mu.Lock()
		defer mu.Unlock()
		cur, st, err := p.load(s.provider)
		if err != nil && !errors.Is(err, ErrNoLogin) {
			return err
		}
		if !s.signIn && acct != cur["account_id"] {
			return ErrNotRefresh
		}
		next, err := mergeLogin(cur, creds)
		if err != nil {
			return err
		}
		next["account_id"] = acct
		val, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := st.Put(entryName(s.provider), LoginKind, val); err != nil {
			return fmt.Errorf("plan login: vault write failed")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.byWorker[s.provider] == nil {
			p.byWorker[s.provider] = map[string]*workerPH{}
		}
		p.byWorker[s.provider][s.worker] = w
		if s.signIn {
			if p.signedBy[s.provider] == nil {
				p.signedBy[s.provider] = map[string]bool{}
			}
			p.signedBy[s.provider][s.worker] = true
		}
		return nil
	}
	return out, commit, nil
}

// mergeLogin lays an answer's credential fields over the stored login. The
// result must hold an access and a refresh token.
func mergeLogin(cur, creds map[string]string) (map[string]string, error) {
	next := map[string]string{}
	for k, v := range cur {
		next[k] = v
	}
	for _, k := range loginFields {
		if v, ok := creds[k]; ok && v != "" {
			next[k] = v
		}
	}
	if next["access_token"] == "" || next["refresh_token"] == "" {
		return nil, errors.New("plan login: incomplete token set")
	}
	return next, nil
}

// AuthJSON returns the placeholder auth file for a worker, minting that
// worker's placeholders on first use. It holds no real value.
func (p *PlanLogins) AuthJSON(provider, worker string) ([]byte, error) {
	cur, _, err := p.load(provider)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byWorker[provider] == nil {
		p.byWorker[provider] = map[string]*workerPH{}
	}
	w := p.byWorker[provider][worker]
	if w == nil || w.account != cur["account_id"] {
		w, _ = p.mint(cur["account_id"])
		p.byWorker[provider][worker] = w
	}
	return json.Marshal(map[string]any{
		"OPENAI_API_KEY": nil,
		"tokens": map[string]string{
			"id_token":      w.byKey["id_token"],
			"access_token":  w.byKey["access_token"],
			"refresh_token": w.byKey["refresh_token"],
			"account_id":    cur["account_id"],
		},
		"last_refresh": time.Now().UTC().Format(time.RFC3339),
	})
}

// CodexAuthFile is where a Codex provider worker's CLI reads its login:
// CODEX_HOME/auth.json, with CODEX_HOME /var/lib/agentos-codex
// (guest/codex/launch.json). It is relative to the worker's root, as a vm
// seed path is.
const CodexAuthFile = "var/lib/agentos-codex/auth.json"

// Seed returns the vm seed for a new Codex provider worker: its
// placeholder auth file at CodexAuthFile, and nothing else.
func (p *PlanLogins) Seed(provider, worker string) (map[string][]byte, error) {
	b, err := p.AuthJSON(provider, worker)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{CodexAuthFile: b}, nil
}

// Resolve maps a worker's own placeholder to the real value it stands for.
// It answers only for the worker the placeholder was minted for, and not
// at all with the vault locked.
func (p *PlanLogins) Resolve(provider, worker, placeholder string) (string, bool) {
	if placeholder == "" {
		return "", false
	}
	p.mu.Lock()
	w := p.byWorker[provider][worker]
	var field string
	if w != nil {
		field = w.field[placeholder]
	}
	p.mu.Unlock()
	if field == "" {
		return "", false
	}
	cur, _, err := p.load(provider)
	if err != nil || cur[field] == "" {
		return "", false
	}
	return cur[field], true
}

// Forget drops a worker's placeholders, when the worker is destroyed.
func (p *PlanLogins) Forget(worker string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.byWorker {
		delete(m, worker)
	}
	for _, m := range p.signedBy {
		delete(m, worker)
	}
}

// Remove deletes the plan's vault entry and every placeholder, and returns
// where the owner revokes the login (W9).
func (p *PlanLogins) Remove(provider string) (string, error) {
	where, ok := p.revoke[provider]
	if !ok {
		return "", errors.New("plan login: unknown provider")
	}
	st, err := p.open()
	if err != nil {
		return "", err
	}
	if err := st.Delete(entryName(provider)); err != nil {
		return "", errors.New("plan login: vault delete failed")
	}
	p.mu.Lock()
	delete(p.byWorker, provider)
	delete(p.signedBy, provider)
	p.mu.Unlock()
	return where, nil
}
