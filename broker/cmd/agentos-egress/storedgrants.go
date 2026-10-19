package main

import (
	"log"

	"github.com/ghbmrk/agentos/broker/vault"
)

// Stored-key grants (CRED-5f-mr-grant, #814): a provider API key the vault
// holds grants that provider to the agent machine (-agent-machine), with
// no -grant flag, from the moment it is stored until the vault locks. The
// router (privateHook.granted) and the proxy (egress Config.Granted) both
// ask storedGrant per call, so a key stored at setup serves without a
// restart and without rebuilding the proxy. Only a key grants: the
// private-data answer stays the router's own check (CAP-9), and builders'
// and replay machines' grants still come only from -builder-from and
// -eval-from.

// storedGrant reports whether a stored key grants provider to machine:
// machine is the agent machine, the vault is open, and it holds provider's
// API key. Builders' and replay machines are never the agent machine
// (checkAgentMachine), so no stored key reaches them.
func (c *custody) storedGrant(machine, provider string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.agent == "" || machine != c.agent || c.ph != open {
		return false
	}
	cred, ok := adapterNamed(provider)
	return ok && hasKind(c.v, cred, vault.KindAPIKey)
}

// granted is the router's stored-key grant once custody exists; until
// then it grants nothing.
func (h *privateHook) granted(machine, provider string) bool {
	s := h.load()
	return s != nil && s.storedGrant(machine, provider)
}

// heldKey reports whether v holds a model provider's API key.
func heldKey(v *vault.Vault) bool {
	for _, a := range adapters() {
		if hasKind(v, a.Credential, vault.KindAPIKey) {
			return true
		}
	}
	return false
}

// modelGrantedNow is the model state's granted (OP-9 C2): a -grant flag
// grants a model provider, or the agent machine has a stored key. While
// the vault is locked the key's presence comes from the state file's Keyed
// mark, which holds no key (CRED-1) and only answers the state: routing
// asks the open vault (storedGrant).
func (c *custody) modelGrantedNow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.granted {
		return true
	}
	if c.agent == "" {
		return false
	}
	if c.ph == open {
		return heldKey(c.v)
	}
	return c.st.Keyed
}

// syncKeyedLocked brings the Keyed mark up to the open vault v. Best
// effort, like syncMarksLocked; with no state file the mark is kept in
// memory. Caller holds mu.
func (c *custody) syncKeyedLocked(v *vault.Vault) {
	keyed := heldKey(v)
	if keyed == c.st.Keyed {
		return
	}
	if c.statePath == "" {
		c.st.Keyed = keyed
		c.keyed.Store(keyed)
		return
	}
	next := c.st
	next.Keyed = keyed
	if err := c.persist(next); err != nil {
		log.Printf("unlock state: %v", err)
	}
}
