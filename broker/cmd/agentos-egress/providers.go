package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/modelroute"
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

// providerNames are the built-in adapters' names as the page shows them.
var providerNames = map[string]string{"openai": "OpenAI", "anthropic": "Anthropic"}

// setupOpen is the guard every setup provider op runs under: the vault
// open and setup's enrollment open. Caller holds mu.
func (c *custody) setupOpen() error {
	if c.ph != open {
		return errLocked
	}
	return c.closedLocked()
}

// setupProviders lists each built-in adapter, whether the vault holds its
// key and the owner's private-data answer. It never reads a key's value.
func (c *custody) setupProviders() ([]modelroute.SetupProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setupOpen(); err != nil {
		return nil, err
	}
	var out []modelroute.SetupProvider
	for _, a := range adapters() {
		name := providerNames[a.Name]
		if name == "" {
			name = a.Name
		}
		out = append(out, modelroute.SetupProvider{
			ID:        a.Name,
			Name:      name,
			Connected: hasKind(c.v, a.Credential, vault.KindAPIKey),
			PrivateOK: hasKind(c.v, PrivateOKPrefix+a.Name, KindPrivateOK),
		})
	}
	return out, nil
}

// setupKey stores key as provider's API key, with put's rules, and only a
// key the proxy could send: printable ASCII with no spaces, at most
// MaxAPIKey bytes.
func (c *custody) setupKey(provider string, key []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setupOpen(); err != nil {
		return err
	}
	a, ok := adapterNamed(provider)
	if !ok || len(key) > MaxAPIKey {
		return errBadCredential
	}
	for _, b := range key {
		if b <= ' ' || b > '~' {
			return errBadCredential
		}
	}
	return c.putKeyLocked(a, key)
}

// setupPrivate writes provider's private-data marker, or deletes it.
func (c *custody) setupPrivate(provider string, ok bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setupOpen(); err != nil {
		return err
	}
	if _, known := adapterNamed(provider); !known {
		return errBadCredential
	}
	name := PrivateOKPrefix + provider
	if hasOtherKind(c.v, name, KindPrivateOK) {
		return errBadCredential
	}
	if ok {
		return c.putMark(name, KindPrivateOK)
	}
	if err := c.v.Delete(name); err != nil {
		return c.putErr(err)
	}
	return nil
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
	for _, a := range adapters() {
		if name != "" && a.Name == name {
			return a.Credential, true
		}
	}
	return "", false
}

// privateHook binds the router, built before custody, to custody's
// privateAllowed once it exists; until then it allows nothing.
type privateHook struct{ c atomic.Pointer[custody] }

func (h *privateHook) allowed(provider string) bool {
	c := h.c.Load()
	return c != nil && c.privateAllowed(provider)
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
	case err == errEnrolled, err == errNotOpen, err == errBadCredential:
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
