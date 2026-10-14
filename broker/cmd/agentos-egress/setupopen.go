package main

import (
	"crypto/rand"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The setup vault's open (CTRL-setup-open, HW-1, ONB-6, ONB-7): while the
// box is in setup mode and finish has not sealed the code generator, the
// vault process opens the setup vault itself at start, with the setup key
// `init -setup` left root-only beside the keys, so step 3 can enroll and
// the card's confirm can provision with no passphrase typed. No passphrase
// exists before the claim (HW-10): the setup vault has no passphrase slot,
// and the setup key opens nothing once the card's provision replaced the
// vault, which also removes the key. After a reset that removed the
// card's vault, or a start that finds no keys file, the box makes a fresh
// setup vault as `init -setup` does (F10, R1 on #1199); never once sealed.

const (
	noteSetupOpen   = "setup vault open for setup"
	noteSetupRemade = "a fresh setup vault was made; setup starts again at the code generator"
)

// startSetup opens the setup vault at start, or remakes it when its keys
// file is gone. It does nothing outside setup mode, once sealed, or when
// the vault is already open.
func (c *custody) startSetup() {
	c.rot.mu.Lock()
	defer c.rot.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != locked || c.keysPath == "" || c.vaultPath == "" || c.statePath == "" {
		return
	}
	if c.st.Sealed {
		c.dropSetupKey()
		return
	}
	if !c.st.Setup {
		return
	}
	if _, err := os.Lstat(c.keysPath); errors.Is(err, os.ErrNotExist) {
		if err := c.remakeSetupLocked(); err != nil {
			log.Printf("setup vault: %v", err)
		}
		return
	}
	raw, err := os.ReadFile(setupKeyFor(c.keysPath))
	if err != nil {
		// The card's vault (or a box whose key is lost): only the card's
		// passphrase opens it, through the unlock.
		return
	}
	rk, err := recovery.ParseRecoveryKey(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil {
		log.Printf("setup key: %v", err)
		return
	}
	defer rk.Wipe()
	c.openSetupLocked(rk)
}

// openSetupLocked opens the setup vault with rk and serves it. It refuses
// a vault rk does not open (the card's: the key is then stale and is
// removed) and one whose enrollment is sealed or not open: only a vault
// `init -setup` made opens without the owner. Caller holds rot.mu and mu,
// with the vault locked.
func (c *custody) openSetupLocked(rk recovery.RecoveryKey) error {
	v, err := vault.OpenSealed(c.vaultPath, c.keysPath, recovery.Factor(rk))
	if errors.Is(err, vault.ErrNoSlotOpens) {
		c.dropSetupKey()
		return err
	}
	if err != nil {
		log.Printf("setup vault: %v", err)
		return err
	}
	if err := enrollClosed(v); err != nil {
		// Sealed (the state's mark was lost) or not a setup vault: keep it
		// locked and record the seal, so no later start reopens it.
		if errors.Is(err, errEnrolled) && !c.st.Sealed {
			next := c.st
			next.Sealed = true
			if perr := c.persist(next); perr != nil {
				log.Printf("unlock state: %v", perr)
			}
		}
		v.Close()
		c.dropSetupKey()
		return err
	}
	if err := c.serve(v); err != nil {
		v.Close()
		return err
	}
	c.notify(noteSetupOpen)
	return nil
}

// remakeSetupLocked makes a fresh setup vault in place of whatever is on
// disk, as `init -setup` does: a new setup key, a new seed and the
// setup-open entry, and opens it. Only in setup mode, before the seal.
// Caller holds rot.mu and mu, with the vault discarded.
func (c *custody) remakeSetupLocked() error {
	if c.st.Sealed || !c.st.Setup || c.ph != locked {
		return errSealedReset
	}
	for _, p := range []string{c.keysPath, c.vaultPath, setupKeyFor(c.keysPath),
		c.keysPath + cardTemp, c.vaultPath + cardTemp, c.keysPath + ".init", c.vaultPath + ".init"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errInternal
		}
	}
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return errInternal
	}
	defer clear(seed)
	rk, err := writeSetupKey(c.keysPath)
	if err != nil {
		return errInternal
	}
	defer rk.Wipe()
	if err := sealNew(c.vaultPath, c.keysPath, recovery.Factor(rk), seed, true); err != nil {
		log.Printf("setup vault: %v", err)
		return errInternal
	}
	next := c.st
	next.Provisioned = false
	if err := c.persist(next); err != nil {
		return errInternal
	}
	if err := c.openSetupLocked(rk); err != nil {
		return errInternal
	}
	c.notify(noteSetupRemade)
	return nil
}

// dropSetupKey removes the setup key: the card's provision and finish's
// seal end what it was for. Caller holds mu.
func (c *custody) dropSetupKey() {
	if c.keysPath == "" {
		return
	}
	if err := os.Remove(setupKeyFor(c.keysPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("setup key: %v", err)
		return
	}
	if err := durable.SyncDir(filepath.Dir(c.keysPath)); err != nil {
		log.Printf("setup key: %v", err)
	}
}
