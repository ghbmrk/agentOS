package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// Setup's AI step (P2-2w c4e; CRED-5, CAP-9, ONB-3): agentosd lists the
// built-in providers, stores an API key and records the owner's
// private-data answer through the verify socket, only while setup's
// enrollment is open (K17). The key goes into the vault under the
// adapter's credential name, as put stores it; the answer is a marker
// entry the router reads on each call.
const (
	// PrivateOKPrefix + an adapter's name marks that the owner allowed it
	// private data at setup.
	PrivateOKPrefix = "private-ok-"
	// KindPrivateOK is the marker's kind; its value is random.
	KindPrivateOK = "private_ok"
	// MaxAPIKey bounds a key in bytes.
	MaxAPIKey = 512
)

// Setup's key-check refusals (#1265): the provider refused the key (403),
// or the check got no answer about it (502). Neither stores anything.
var (
	errKeyRefused   = uerr(http.StatusForbidden, "the provider did not accept the key")
	errKeyUnchecked = uerr(http.StatusBadGateway, "the key could not be checked with the provider")
)

// providerNames are the built-in adapters' names as the page shows them.
var providerNames = map[string]string{"openai": "OpenAI", "anthropic": "Anthropic", planProvider: "ChatGPT plan"}

// setupOpen is the guard every setup provider op runs under: the vault
// open and setup's enrollment open. Caller holds mu.
func (c *custody) setupOpen() error {
	if c.ph != open {
		return errLocked
	}
	return c.closedLocked()
}

// setupProviders lists each built-in adapter, whether the vault holds its
// key and the owner's saved private-data answer as PrivateOK, never the
// -private-ok flag: setup's box defaults to that answer, and saving it
// records a lasting owner answer (D-115, Security S1 on #1588). The flag
// is PrivateByConfig alone, so setup shows that box as fixed (#1608). It
// never reads a key's value.
func (c *custody) setupProviders() ([]modelroute.SetupProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setupOpen(); err != nil {
		return nil, err
	}
	return c.providersLocked(false), nil
}

// providersLocked lists the built-in providers, then the plan route, which
// is connected once its sign-in is stored. With withFlag, a provider's
// private answer is the router's (route.go privateOK): its
// -private-ok flag or the owner's marker (#1420); without, the marker
// only. PrivateByConfig is the flag either way (#1608). Caller holds mu
// with the vault open.
func (c *custody) providersLocked(withFlag bool) []modelroute.SetupProvider {
	var out []modelroute.SetupProvider
	for _, a := range adapters() {
		flag := c.privateFlags[a.Name]
		out = append(out, modelroute.SetupProvider{
			ID:              a.Name,
			Name:            providerName(a.Name),
			Connected:       hasKind(c.v, a.Credential, vault.KindAPIKey),
			PrivateOK:       withFlag && flag || hasKind(c.v, PrivateOKPrefix+a.Name, KindPrivateOK),
			PrivateByConfig: flag,
		})
	}
	flag := c.privateFlags[planProvider]
	out = append(out, modelroute.SetupProvider{
		ID:              planProvider,
		Name:            providerName(planProvider),
		Connected:       hasKind(c.v, "plan-login-"+planProvider, egress.LoginKind),
		PrivateOK:       withFlag && flag || hasKind(c.v, PrivateOKPrefix+planProvider, KindPrivateOK),
		PrivateByConfig: flag,
		Plan:            true,
	})
	return out
}

// providerName is the provider's name for the owner.
func providerName(id string) string {
	if n := providerNames[id]; n != "" {
		return n
	}
	return id
}

// setupKey stores key as provider's API key, with put's rules, and only a
// key the proxy could send: printable ASCII with no spaces, at most
// MaxAPIKey bytes. The provider is asked first, with the adapter's key
// check (#1265, ONB-3): a key it refuses is errKeyRefused, a check with
// no answer about the key is errKeyUnchecked, and neither stores
// anything. The check runs without mu, so a slow provider holds up no
// code check or lock, and setup's guard is asked again before the store.
func (c *custody) setupKey(provider string, key []byte) error {
	a, err := c.setupKeyAdapter(provider, key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), modelroute.SetupKeyCheckWait)
	defer cancel()
	rt := c.keyCheck
	if rt == nil {
		g := c.guard
		if g == nil {
			g = netguard.New(netguard.Config{})
		}
		tr := egress.DefaultTransport(g)
		defer tr.CloseIdleConnections()
		rt = tr
	}
	switch a.CheckKey(ctx, rt, key) {
	case nil:
	case egress.ErrKeyRefused:
		return errKeyRefused
	default:
		return errKeyUnchecked
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setupOpen(); err != nil {
		return err
	}
	return c.putKeyLocked(a.Credential, key)
}

// setupKeyAdapter checks, under mu, that setup is open, provider is a
// built-in adapter and key is one the vault would store.
func (c *custody) setupKeyAdapter(provider string, key []byte) (egress.Adapter, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setupOpen(); err != nil {
		return egress.Adapter{}, err
	}
	a, ok := builtinAdapter(provider)
	if !ok || len(key) == 0 || len(key) > MaxAPIKey || !adapterCredential(a.Credential) || hasOtherKind(c.v, a.Credential, vault.KindAPIKey) {
		return egress.Adapter{}, errBadCredential
	}
	for _, b := range key {
		if b <= ' ' || b > '~' {
			return egress.Adapter{}, errBadCredential
		}
	}
	return a, nil
}

// setupPrivate writes provider's private-data marker, or deletes it.
func (c *custody) setupPrivate(provider string, ok bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setupOpen(); err != nil {
		return err
	}
	if err := c.privateMarkOK(provider); err != nil {
		return err
	}
	return c.setPrivateLocked(provider, ok)
}

// privateAllowed is the router's PrivateAllowed check (CAP-9): true only
// while the vault is open and holds provider's marker. A locked vault
// allows nothing private.
func (c *custody) privateAllowed(provider string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return false
	}
	_, known := adapterNamed(provider)
	return known && hasKind(c.v, PrivateOKPrefix+provider, KindPrivateOK)
}

// adapterNamed returns the built-in adapter's credential name.
func adapterNamed(name string) (string, bool) {
	a, ok := builtinAdapter(name)
	return a.Credential, ok
}

// builtinAdapter returns the built-in adapter called name.
func builtinAdapter(name string) (egress.Adapter, bool) {
	for _, a := range adapters() {
		if name != "" && a.Name == name {
			return a, true
		}
	}
	return egress.Adapter{}, false
}

// privateHook binds the router, built before custody, to its model
// source's privateAllowed once it exists (custody, or the proxy process's
// view); until then it allows nothing.
type privateHook struct{ src atomic.Pointer[sourceBox] }

func (h *privateHook) bind(s modelSource) { h.src.Store(&sourceBox{s}) }

// load is the bound source, nil before binding.
func (h *privateHook) load() modelSource {
	if b := h.src.Load(); b != nil {
		return b.modelSource
	}
	return nil
}

func (h *privateHook) allowed(provider string) bool {
	s := h.load()
	return s != nil && s.privateAllowed(provider)
}

// setupProvidersHandler serves the provider ops on the verify socket.
func setupProvidersHandler(c *custody, w http.ResponseWriter, r *http.Request) {
	var res any = struct{}{}
	var err error
	switch r.URL.Path {
	case "/setup/providers":
		var ps []modelroute.SetupProvider
		ps, err = c.setupProviders()
		res = modelroute.SetupProviderList{Providers: ps}
	case "/setup/providers/key":
		var req modelroute.SetupKeyRequest
		if derr := json.NewDecoder(io.LimitReader(r.Body, 1<<11)).Decode(&req); derr != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		err = c.setupKey(req.Provider, []byte(req.Key))
	default:
		var req modelroute.SetupPrivateRequest
		if derr := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); derr != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		err = c.setupPrivate(req.Provider, req.OK)
	}
	switch {
	case err == nil:
	case err == errLocked:
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case err == errEnrolled, err == errNotOpen, err == errBadCredential, err == errKeyRefused, err == errKeyUnchecked:
		http.Error(w, err.Error(), err.(*unlockErr).status)
		return
	default:
		http.Error(w, errInternal.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(res)
}
