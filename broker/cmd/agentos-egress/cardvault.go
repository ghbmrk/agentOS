package main

import (
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The Owner Card's vault ops (CTRL-card-vaultop, firstboot F10/F12): the
// card step's Provision makes the box's vault from the confirmed card, and
// its reset discards a vault made from a card whose confirm never latched.
// Both run only in setup mode; once finish sealed the code generator the
// vault is neither remade nor reset (security S1 on #1073).

// cardTemp is the suffix of the card vault's files while they are built
// beside the setup vault's.
const cardTemp = ".card"

var (
	errCardOther   = uerr(http.StatusConflict, "this vault was made from another Owner Card; reset setup to start again")
	errSealedReset = uerr(http.StatusGone, "setup finished and the code generator is sealed; the vault is never reset")
	// errCodesUnconfirmed: no code generator was confirmed on this vault
	// since its last enroll, as after a remade setup vault (R1 on #1203).
	// Setup goes back to step 3 before the card; the page routes there on
	// its reason (#1115).
	errCodesUnconfirmed = &unlockErr{status: http.StatusPreconditionFailed, reason: reasonCodesUnconfirmed,
		msg: "no code generator is confirmed on this vault; set up the code generator again before the card"}
)

// reasonCodesUnconfirmed is errCodesUnconfirmed's reason on the unlock
// socket (localui.ReasonCodesUnconfirmed).
const reasonCodesUnconfirmed = "codes_unconfirmed"

// provisionCard makes the card's vault from the open setup vault: a new
// vault under a fresh data key, sealed with the card's passphrase and
// recovery key (recovery.Provision), holding every entry of the setup
// vault, so the code-generator seed enrolled at step 3 carries into it
// (security S2 on #1073). It replaces the setup vault's files and serves
// the new vault. A retry with the card the vault was made from is a no-op
// (F10); another card is refused.
func (c *custody) provisionCard(card recovery.Card) error {
	c.rot.mu.Lock()
	defer c.rot.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if err := c.closedLocked(); err != nil {
		return err
	}
	if c.st.Sealed {
		return errEnrolled
	}
	if c.vaultPath == "" || c.keysPath == "" {
		return errInternal
	}
	rk, err := recovery.ParseRecoveryKey(card.RecoveryKey)
	if err != nil || len(card.VaultPassphrase) == 0 {
		return uerr(http.StatusBadRequest, "the Owner Card is incomplete")
	}
	if _, ok := c.v.Secret(recovery.CardName); ok {
		return c.sameCardLocked(card, rk)
	}
	// Only a seed the owner's phone confirmed carries into the card's
	// vault, as only one seals (sealEnroll): a remade setup vault's seed
	// was shown to nobody, and a card's vault that held it would open
	// with codes nobody can make.
	if _, ok := c.v.Secret(PendingSeedName); ok || !hasKind(c.v, ConfirmedName, KindConfirmed) {
		return errCodesUnconfirmed
	}
	// The mark goes first: a vault process stopped after the swap still
	// knows, locked, that its vault was made from a card (resetCard).
	next := c.st
	next.Provisioned = true
	if err := c.persist(next); err != nil {
		return errInternal
	}
	vt, kt := c.vaultPath+cardTemp, c.keysPath+cardTemp
	if err := c.buildCardVault(vt, kt, card); err != nil {
		log.Printf("card vault: %v", err)
		return c.unprovisionLocked(vt, kt)
	}
	// Vault first, keys last, as init does: the setup vault's keys file
	// does not open the card's vault (keysbind), so a stop between the two
	// leaves nothing that opens, and reset removes both.
	if err := durable.Rename(vt, c.vaultPath); err != nil {
		return c.unprovisionLocked(vt, kt)
	}
	if err := durable.Rename(kt, c.keysPath); err != nil {
		os.Remove(kt)
		c.gen++
		c.rot.drop()
		c.rot.box = nil
		c.discard()
		return errInternal
	}
	nv, err := vault.OpenSealed(c.vaultPath, c.keysPath, recovery.Factor(rk))
	c.gen++
	c.rot.drop()
	c.rot.box = nil
	old := c.v
	if err != nil {
		c.discard()
		return errInternal
	}
	if err := c.serve(nv); err != nil {
		nv.Close()
		c.discard()
		return errInternal
	}
	old.Close()
	// The setup key opens nothing in the card's vault (keysbind); it goes.
	c.dropSetupKey()
	c.notify("vault made from the Owner Card")
	return nil
}

// unprovisionLocked undoes a provision that stopped before the swap: the
// setup vault is untouched, so its mark is cleared. Caller holds mu.
func (c *custody) unprovisionLocked(vt, kt string) error {
	os.Remove(vt)
	os.Remove(kt)
	next := c.st
	next.Provisioned = false
	if err := c.persist(next); err != nil {
		log.Printf("unlock state: %v", err)
	}
	return errInternal
}

// sameCardLocked answers a provision on a vault that already holds a
// card: a no-op when it is the same card, its passphrase and recovery key
// both opening the vault, else errCardOther. Caller holds mu.
func (c *custody) sameCardLocked(card recovery.Card, rk recovery.RecoveryKey) error {
	have, err := (&recovery.Box{V: c.v}).LoadCard()
	if err != nil {
		return errInternal
	}
	a, err1 := recovery.EncodeCard(have)
	b, err2 := recovery.EncodeCard(card)
	if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(a, b) != 1 {
		return errCardOther
	}
	for _, f := range []vault.Factor{recovery.Factor(rk), vault.Passphrase(card.VaultPassphrase)} {
		v, err := vault.OpenSealed(c.vaultPath, c.keysPath, f)
		if err != nil {
			return errCardOther
		}
		v.Close()
	}
	return nil
}

// buildCardVault writes the card's vault at vt and kt: every entry of the
// open vault, then the card's recovery slot, backup keys and stored
// values. Caller holds mu.
func (c *custody) buildCardVault(vt, kt string, card recovery.Card) error {
	os.Remove(vt)
	os.Remove(kt)
	nv, err := vault.CreateSealed(vt, kt, vault.Passphrase(card.VaultPassphrase))
	if err != nil {
		return err
	}
	defer nv.Close()
	for _, e := range c.v.List() {
		s, ok := c.v.Secret(e.Name)
		if !ok {
			return errors.New("entry vanished while copying")
		}
		if err := nv.Put(e.Name, e.Kind, []byte(s.Reveal())); err != nil {
			return err
		}
	}
	return recovery.Provision(&recovery.Box{VaultPath: vt, KeysPath: kt, V: nv}, card, vault.Passphrase(card.VaultPassphrase))
}

// resetCard removes a vault made from a card whose confirm never latched,
// and the code-generator seed with it (F10). It is refused once finish
// sealed the seed, open or locked, and on an open vault outside setup
// mode. A vault no card made (the setup vault before the card step) is
// kept: there is nothing of a card's to discard, so it is a no-op. In
// setup mode the removed vault is replaced by a fresh setup vault
// (resetCardRemade).
func (c *custody) resetCard() error {
	_, err := c.resetCardRemade()
	return err
}

// resetCardRemade is resetCard, also reporting whether it made a fresh
// setup vault: in setup mode, before the seal, the removed vault is
// replaced by one as `init -setup` makes (setupopen.go), so step 3 and
// the next card's provision can run (HW-1 test 2, F10).
func (c *custody) resetCardRemade() (bool, error) {
	c.rot.mu.Lock()
	defer c.rot.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Sealed {
		return false, errSealedReset
	}
	if c.ph == opening {
		return false, errBusy
	}
	if c.v != nil {
		switch err := c.closedLocked(); {
		case errors.Is(err, errEnrolled):
			return false, errSealedReset
		case err != nil:
			return false, err
		}
		if _, ok := c.v.Secret(recovery.CardName); !ok && !c.st.Provisioned {
			return false, nil
		}
	} else if !c.st.Provisioned {
		return false, nil
	}
	if c.vaultPath == "" || c.keysPath == "" {
		return false, errInternal
	}
	c.gen++
	c.rot.drop()
	c.rot.box = nil
	c.discard()
	for _, p := range []string{c.keysPath, c.vaultPath, c.keysPath + cardTemp, c.vaultPath + cardTemp} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, errInternal
		}
	}
	next := c.st
	next.Provisioned = false
	if err := c.persist(next); err != nil {
		return false, errInternal
	}
	c.notify("the vault made from an unconfirmed Owner Card was removed")
	if !c.st.Setup {
		return false, nil
	}
	if err := c.remakeSetupLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// syncMarksLocked brings the state file's marks up to the vault it
// opened: a vault sealed before the mark existed, or whose mark was lost,
// gets it (the seal mark is never cleared), and the card mark follows
// whether the vault holds a card, so a later locked reset sees the vault
// as it is. Best effort: the open goes on if the write fails. Caller
// holds mu.
func (c *custody) syncMarksLocked(v *vault.Vault) {
	next := c.st
	if hasKind(v, EnrolledName, KindEnrolled) {
		next.Sealed = true
	}
	_, next.Provisioned = v.Secret(recovery.CardName)
	if next.Sealed == c.st.Sealed && next.Provisioned == c.st.Provisioned || c.statePath == "" {
		return
	}
	if err := c.persist(next); err != nil {
		log.Printf("unlock state: %v", err)
	}
}

// provisionRequest is the confirmed card as the card step sends it.
type provisionRequest struct {
	SetupSecret     string `json:"setup_secret"`
	SetupCode       string `json:"setup_code"`
	VaultPassphrase string `json:"vault_passphrase"`
	GridSeed        []byte `json:"grid_seed"`
	RecoveryKey     string `json:"recovery_key"`
}

func cardRoutes(mux *http.ServeMux, c *custody, read func(http.ResponseWriter, *http.Request, any) bool,
	reply func(http.ResponseWriter, int, any), fail func(http.ResponseWriter, error)) {
	mux.HandleFunc("/card/provision", func(w http.ResponseWriter, r *http.Request) {
		var req provisionRequest
		if !read(w, r, &req) {
			return
		}
		err := c.provisionCard(recovery.Card{SetupSecret: req.SetupSecret, SetupCode: req.SetupCode, VaultPassphrase: req.VaultPassphrase,
			GridSeed: req.GridSeed, RecoveryKey: req.RecoveryKey})
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/card/reset", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !read(w, r, &req) {
			return
		}
		remade, err := c.resetCardRemade()
		if err != nil {
			fail(w, err)
			return
		}
		if remade {
			reply(w, http.StatusOK, map[string]any{"ok": true, "remade": true})
			return
		}
		reply(w, http.StatusOK, map[string]any{"ok": true})
	})
}
