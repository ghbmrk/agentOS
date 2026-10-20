package main

import (
	"net/http"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The owner's private-data answer after setup (#1266; CAP-9, CH-3): the
// local page lists the providers on the unlock socket and changes one's
// answer there. Allowing is a tier-4 change approved with a code;
// withdrawing narrows what leaves the box, as STOP, NO and revoke do, so
// it needs none. The answer is setup's own marker (setupPrivate), which
// the router asks per call (privateAllowed), so a change applies to the
// next call without a restart. A Private plan run already admitted asks
// it too, before each content request on its worker route
// (workerRoutes.privateGate, #2359).

// errCodeRequired: a key add or replace is a tier-4 change (CH-10).
var errCodeRequired = uerr(http.StatusForbidden, "adding an AI key needs a code from your code generator")

// providerList is the providers with whether a key is held and whether
// private data is allowed, by the flag or the marker as the router asks,
// never a key (CRED-1). It needs an open vault.
func (c *custody) providerList() ([]modelroute.SetupProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return nil, errLocked
	}
	return c.providersLocked(true), nil
}

// errPrivateByConfig: a withdraw removed the owner's marker, but this
// box's -private-ok flag still allows the provider private data (#1420).
var errPrivateByConfig = uerr(http.StatusConflict, "my configuration allows this provider private data, so it can't be withdrawn here")

// putPrivate records the owner's answer for provider: ok allows private
// data with the code's approval, !ok withdraws it with none. A withdraw
// the -private-ok flag overrides still removes the marker, so it narrows
// once the flag goes, but is errPrivateByConfig and tells no one.
func (c *custody) putPrivate(provider string, ok bool, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if err := c.privateMarkOK(provider); err != nil {
		return err
	}
	if ok {
		if err := c.approvedLocked(code, "allowing a provider private data"); err != nil {
			return err
		}
	}
	fails := c.handFails.Load()
	if err := c.setPrivateLocked(provider, ok); err != nil {
		return err
	}
	if !ok && c.privateFlags[provider] {
		return errPrivateByConfig
	}
	switch {
	case ok:
		c.notify("private data allowed for " + providerName(provider))
	case c.handFails.Load() != fails:
		// The write's hand to the proxy failed (handView told why): the
		// proxy keeps allowing until a later round reaches it (W-2).
		c.notify("private data withdrawn for " + providerName(provider) + ", but not yet in effect: the proxy still allows it until it takes the change")
	default:
		c.notify("private data withdrawn for " + providerName(provider))
	}
	return nil
}

// addKey stores key as provider's API key after setup (CRED-5f-mr-addkey;
// ONB-3, CH-10, CRED-1). Any add or replace needs the one-time code: under
// K24 a key for a provider that had none is a new grant, and a replaced
// key can point at another account. The provider is asked first, without
// mu and before the code is spent, so a refused key burns no code; a
// request that cannot be a code, or that comes during a lockout, never
// reaches the provider, so the route is no key-validity oracle. The code is
// checked under mu just before the store, after the vault and the key are
// checked again. It needs an open vault, and never reads a key's value.
func (c *custody) addKey(provider string, key []byte, code string) error {
	if !codeShaped(code) {
		return errCodeRequired
	}
	c.mu.Lock()
	if c.ph != open {
		c.mu.Unlock()
		return errLocked
	}
	if until, out := c.lockedOut(c.now()); out {
		c.mu.Unlock()
		return errLockedOut(until)
	}
	a, err := c.keyAdapterLocked(provider, key)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.checkKeyWithProvider(a, key); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if _, err := c.keyAdapterLocked(provider, key); err != nil {
		return err
	}
	if err := c.approvedLocked(code, "adding an AI key"); err != nil {
		return err
	}
	if err := c.putKeyLocked(a.Credential, key); err != nil {
		return err
	}
	c.notify("AI key added for " + providerName(provider))
	return nil
}

// codeShaped reports whether code can be a one-time code: six ASCII digits.
func codeShaped(code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// privateMarkOK refuses a provider that is neither built in nor the plan
// route, or whose marker name holds a vault entry of another kind. Caller
// holds mu.
func (c *custody) privateMarkOK(provider string) error {
	if _, known := adapterNamed(provider); !known && provider != planProvider {
		return errBadCredential
	}
	if hasOtherKind(c.v, PrivateOKPrefix+provider, KindPrivateOK) {
		return errBadCredential
	}
	return nil
}

// setPrivateLocked writes or deletes provider's marker. Caller holds mu
// and has checked privateMarkOK.
func (c *custody) setPrivateLocked(provider string, ok bool) error {
	name := PrivateOKPrefix + provider
	if ok {
		return c.putMark(name, KindPrivateOK)
	}
	if err := c.v.Delete(name); err != nil {
		return c.putErr(err)
	}
	return nil
}

// privateGrantedNow is the model state's private (#1266, P-2 on #1280):
// the vault is open and some model provider is both granted (a -grant
// flag, or the agent machine's stored key) and allowed private data (a
// -private-ok flag, or the owner's marker).
func (c *custody) privateGrantedNow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return false
	}
	for _, p := range modelProviders() {
		n := p.Name()
		cred, known := adapterNamed(n)
		granted := c.flagGrants[n] || c.agent != "" && known && hasKind(c.v, cred, vault.KindAPIKey)
		allowed := c.privateFlags[n] || known && hasKind(c.v, PrivateOKPrefix+n, KindPrivateOK)
		if granted && allowed {
			return true
		}
	}
	return false
}

// flagGrantsOf is the model providers g grants on any machine.
func flagGrantsOf(g grants) map[string]bool {
	out := map[string]bool{}
	for _, as := range g {
		for _, a := range as {
			for _, p := range modelProviders() {
				if a == p.Name() {
					out[a] = true
				}
			}
		}
	}
	return out
}

// providerRoutes serves the owner's provider list and private-data
// answer on the unlock socket.
func providerRoutes(mux *http.ServeMux, c *custody, read func(http.ResponseWriter, *http.Request, any) bool,
	reply func(http.ResponseWriter, int, any), fail func(http.ResponseWriter, error)) {
	mux.HandleFunc("/providers", func(w http.ResponseWriter, r *http.Request) {
		ps, err := c.providerList()
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, modelroute.SetupProviderList{Providers: ps})
	})
	mux.HandleFunc("/providers/key", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider string `json:"provider"`
			Key      string `json:"key"`
			Code     string `json:"code"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.addKey(req.Provider, []byte(req.Key), req.Code); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/providers/private", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider string `json:"provider"`
			OK       bool   `json:"ok"`
			Code     string `json:"code"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.putPrivate(req.Provider, req.OK, req.Code); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
