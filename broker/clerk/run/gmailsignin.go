package run

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"errors"
	"maps"
	"strings"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
)

// The owner's Gmail sign-in on the mail process's own socket (#3009, D-150,
// D-154): gmailbegin gives the consent address, gmailfinish takes the
// address the owner pasted, seals the grant in the account's own slot and
// sets the account up, and gmailrevoke gives the grant back to Google and
// removes the account. Every sign-in runs on a store of its own, in memory,
// so clerk.SignIn's one-account store holds only it (CLK-1) and its Finish
// never seals over the account's grant. A first sign-in, with the
// household's registration, has an empty store under a key drawn here. A
// sign-in again, with no registration, has a sealed copy of the account's
// grant, which holds the registration, so it never goes back to the main
// side (D-154 rule 1). The new grant reaches the account's slot through
// Saved, inside this process.

// gmailSlot is a first sign-in's store's one slot.
const gmailSlot = "gmail"

// The sign-in's details beside clerk's D* ones, carrying no value (CLK-4).
const (
	// DGmailAddress: Google's profile named no address the clerk can set
	// up, so the new grant was given back.
	DGmailAddress = "address"
	// DNotGmail: gmailrevoke found no Gmail account set up.
	DNotGmail = "notgmail"
)

// Owner notices for a Gmail grant leaving the box (A22).
const (
	noteGmailRevoked = "Gmail was disconnected: I gave its sign-in back to Google and removed the account."
	// noteGmailKept names the step that ends a grant Google kept (CH-12).
	noteGmailKept = "I could not give the Gmail sign-in back to Google, so Google may still list it. " +
		"To end it, open myaccount.google.com/permissions signed in to that Gmail account, and remove the app you made for agentOS."
	// noteGmailUnnamed is dropUnnamed's: nothing was given back, and the
	// set-up account's grant must stay (#3027 L3 delta 1).
	noteGmailUnnamed = "Google did not say which account you signed in as, so I set nothing up and left your Gmail account as it was. " +
		"If you signed in as a different Google account, open myaccount.google.com/permissions in that account and remove the app you made for agentOS. " +
		"Do not remove it from the account set up here, or its mail stops."
)

// errNoSealer: the config names no sealer to hold a copy of a grant under.
var errNoSealer = errors.New("run: no sealer for the account's grants")

// gmailSignIn is one sign-in, the store and slot its grant is sealed in,
// and the grant once Finish has sealed it.
type gmailSignIn struct {
	in    *clerk.SignIn
	sec   *clerk.Secrets
	slot  string
	again bool // a sign-in again: slot is the account's, sec a copy of its grant
	grant []byte
}

// newGmailSignIn is a sign-in whose grant lives in slot of sec; hint, if
// not "", is the address Google's consent page offers first.
func (h *MailHost) newGmailSignIn(sec *clerk.Secrets, slot, hint string) (*gmailSignIn, error) {
	c := h.cfg
	guard, roots := c.gmailNet()
	d := inbox.GmailSignIn(cmp.Or(c.gmail.consent, inbox.GmailConsent), cmp.Or(c.gmail.token, inbox.GmailToken),
		cmp.Or(c.gmail.revoke, inbox.GmailRevoke), slot, guard, nil)
	if hint != "" {
		d.Params = maps.Clone(d.Params)
		d.Params["login_hint"] = hint
	}
	in, err := clerk.NewSignIn(d, sec, roots)
	if err != nil {
		return nil, err
	}
	g := &gmailSignIn{in: in, sec: sec, slot: slot}
	in.Saved = func(grant []byte) error {
		g.grant = bytes.Clone(grant)
		return nil
	}
	return g, nil
}

// ownGmailSignIn is a first sign-in's: a store of its own, in memory under
// a key drawn here.
func (h *MailHost) ownGmailSignIn() (*gmailSignIn, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	sl, err := clerk.NewAESSealer(k)
	clear(k)
	if err != nil {
		return nil, err
	}
	return h.newGmailSignIn(clerk.NewSecrets(sl, nil), gmailSlot, "")
}

// heldGmailSignIn is a sign-in on slot's grant held apart from the
// account's store: a store of its own, in memory, holding a copy of the
// slot as the account's store seals it, under the same sealer, so the grant
// is never opened here (#3026). It stays when the account's store drops
// the slot or a Finish seals over it, so a grant is given back only once
// the account it served is gone, and a sign-in again never seals over the
// account's grant. NewSignIn refuses a copy that holds another slot (CLK-1).
func (h *MailHost) heldGmailSignIn(slot, hint string) (*gmailSignIn, error) {
	if h.cfg.Sealer == nil {
		return nil, errNoSealer
	}
	b, err := h.sec.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sec := clerk.NewSecrets(h.cfg.Sealer, nil)
	if err := sec.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	if err := sec.RemovePrefix(clerk.MailSlots, slot); err != nil {
		return nil, err
	}
	return h.newGmailSignIn(sec, slot, hint)
}

// address is the address of the account the sign-in's grant is for.
func (g *gmailSignIn) address(h *MailHost) (string, error) {
	box, err := gmailBox(g.sec, g.slot, h.cfg)
	if err != nil {
		return "", err
	}
	return box.Address(h.ctx)
}

// gmailBegin starts a sign-in for use and returns the consent address, or a
// detail. reg nil signs in again with the Gmail account's registration, or,
// with no Gmail account set up, signs in with the kept one (#3055).
func (h *MailHost) gmailBegin(use string, reg *clerk.Registration) gmailBegun {
	var g *gmailSignIn
	var err error
	if reg != nil {
		g, err = h.ownGmailSignIn()
	} else {
		h.mu.Lock()
		s, rerr := readMail(h.dir)
		if rerr == nil && s.API == APIGmail && h.sec.Has(slotOf(s)) {
			g, err = h.heldGmailSignIn(slotOf(s), s.Address)
		}
		if g == nil && err == nil && h.cfg.Sealer != nil {
			// No account to sign in again with: a first sign-in with the
			// registration kept apart (#3055).
			if r, ok := loadReg(h.dir, h.cfg.Sealer); ok {
				reg = &r
			}
		}
		h.mu.Unlock()
		if reg != nil {
			g, err = h.ownGmailSignIn()
		} else if g == nil && err == nil {
			return gmailBegun{Detail: clerk.DNoAccount}
		}
	}
	if err != nil {
		return gmailBegun{Detail: clerk.DNoAccount}
	}
	g.again = reg == nil
	consent, err := g.in.Begin(use, reg)
	if err != nil {
		return gmailBegun{Detail: err.Error()} // Begin's errors are its typed details
	}
	h.signMu.Lock()
	h.signing = g // a newer Begin replaces the one waiting
	h.signMu.Unlock()
	return gmailBegun{Consent: consent}
}

// gmailFinish finishes the waiting sign-in with the pasted address and the
// use the owner confirmed, and sets up the Gmail account it is for: the new
// grant goes to its account's slot, the account is opened again, which
// clears a reconnect stop, and only then is a Gmail account it replaced
// given its grant back (A22, #3026). It answers Finish's detail, or
// DGmailAddress.
func (h *MailHost) gmailFinish(use, pasted string) (string, error) {
	// One paste finishes a sign-in: a second, concurrent one finds none
	// waiting, so two calls never share g's grant (#3023 Security).
	h.signMu.Lock()
	g := h.signing
	h.signing = nil
	h.signMu.Unlock()
	if g == nil || g.again && !h.still(g.slot) {
		// None waits, or the account changed while the owner was on
		// Google's page: the owner's later setup stands, and no code is
		// redeemed.
		return clerk.DNoSignIn, nil
	}
	d := g.in.Finish(h.ctx, use, pasted)
	if d == clerk.DNotOurs {
		// Finish kept the sign-in waiting for the right paste.
		h.signMu.Lock()
		if h.signing == nil {
			h.signing = g
		}
		h.signMu.Unlock()
	}
	if !strings.HasPrefix(d, clerk.DSignedIn+" ") {
		return d, nil
	}
	// Only the paste that signed in holds the grant, and only it wipes it: a
	// sign-in put back above may already be another paste's (#3023 Security).
	defer clear(g.grant)
	if g.again && !h.still(g.slot) {
		h.giveBack(g, false) // the account changed during Finish
		return clerk.DNoSignIn, nil
	}
	addr, err := g.address(h)
	if err == nil {
		err = MailSettings{Address: addr, API: APIGmail}.check()
	}
	if err != nil || len(g.grant) == 0 {
		h.dropUnnamed(g) // no account will use it
		return DGmailAddress, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.idle()
	prev, perr := readMail(h.dir)
	slot := GmailSlot(addr)
	if g.again && (perr != nil || slotOf(prev) != g.slot) {
		h.giveBack(g, true) // as above: the account changed meanwhile
		return clerk.DNoSignIn, nil
	}
	same := perr == nil && slotOf(prev) == slot
	release := func() {}
	if perr == nil && !same {
		release = h.holdGmail(prev) // before the new slot is put, so the store holds prev's only (CLK-1)
	}
	end := h.ws.writing() // until the change is told (#3538)
	put := h.sec.Put(slot, clerk.KindGrant, g.grant)
	err = put
	if err == nil {
		err = SetGmail(h.dir, h.sec, addr)
	}
	h.wrote()
	release()
	if put != nil || !h.setUp(slot) {
		end()
		// The account before, and its grant, stand. The same address keeps
		// the new grant: Google's revocation of it would end the account's
		// own grant with it, as on a sign-in again.
		if !same {
			_ = h.sec.Remove(slot)
			h.giveBack(g, true)
		}
		return "", err
	}
	h.changed()
	end()
	if perr == nil && !same {
		h.notify(false, noteMailReplaced)
	}
	// The registration outlives the account (#3055); a failed write leaves
	// the account set up and the owner enters it again after a removal.
	err = errors.Join(err, keepReg(h.dir, h.cfg.Sealer, g.grant))
	h.refresh()
	if err != nil {
		return "", err // the account is set up; only a later step of the write failed
	}
	return d, nil
}

// giveBack revokes g's new grant, which no account will use, with h.mu
// held if locked; it is sealed only in g's own store. If Google keeps it,
// the owner is told the step that ends it.
func (h *MailHost) giveBack(g *gmailSignIn, locked bool) {
	if !locked {
		h.mu.Lock()
		defer h.mu.Unlock()
	}
	if g.in.Revoke(h.ctx) != clerk.DRevoked {
		h.notify(false, noteGmailKept)
	}
}

// dropUnnamed drops g's new grant, whose account Google's profile did not
// name. With a Gmail account set up it may be that account's own grant
// (a sign-in again offers its address first), which Google's revocation
// of the new one would end, so it is not given back, and the owner is
// told how to end it in another account only (#3027 L3 1). With no
// account, or an IMAP one, it is given back.
func (h *MailHost) dropUnnamed(g *gmailSignIn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, err := readMail(h.dir); !errors.Is(err, ErrNoMailAccount) && (err != nil || s.API == APIGmail) {
		// A Gmail account, or settings that do not read: the box may
		// still hold a Gmail grant the revocation would end, so fail
		// closed. An IMAP account holds none (#3027 Security delta 1).
		h.notify(false, noteGmailUnnamed)
		return
	}
	h.giveBack(g, true)
}

// still reports whether the account set up is still the one in slot.
func (h *MailHost) still(slot string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setUp(slot)
}

// setUp is still with h.mu held.
func (h *MailHost) setUp(slot string) bool {
	s, err := readMail(h.dir)
	return err == nil && slotOf(s) == slot
}

// gmailRevoke gives the Gmail account's grant back to Google and, once
// Google has dropped it, removes the account. A grant Google kept stays
// sealed and the account set up, so the owner can try again.
func (h *MailHost) gmailRevoke() (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.idle()
	s, err := readMail(h.dir)
	if err != nil || s.API != APIGmail {
		return DNotGmail, nil
	}
	g, err := h.newGmailSignIn(h.sec, slotOf(s), "")
	if err != nil {
		return clerk.DNoAccount, nil
	}
	if d := g.in.Revoke(h.ctx); d != clerk.DRevoked {
		return d, nil
	}
	if err := RemoveMail(h.dir, h.sec); err != nil {
		return "", err
	}
	h.changed()
	h.notify(false, noteGmailRevoked)
	return clerk.DRevoked, nil
}

// holdGmail holds the grant of s, before a setup or a removal drops its
// slot, and returns what gives it back to Google once that change is made
// (A22, #3026); h.mu is held, and it runs before any new slot is put, so
// the store holds s's only (CLK-1). The release gives the grant back only
// if s is no longer set up with it, so a change that failed leaves s set
// up with a grant that works, never one already given back. An account
// that is not Gmail's, or holds no grant, has nothing to give back. A grant
// Google keeps is dropped all the same, so the owner is never stuck on
// Google's answer, and the owner is told the step that ends it.
func (h *MailHost) holdGmail(s MailSettings) (release func()) {
	slot := slotOf(s)
	if s.API != APIGmail || !h.sec.Has(slot) {
		return func() {}
	}
	g, err := h.heldGmailSignIn(slot, "")
	return func() {
		if h.setUp(slot) && h.sec.Has(slot) {
			return // the change failed: s stands with its grant
		}
		if err != nil || g.in.Revoke(h.ctx) != clerk.DRevoked {
			h.notify(false, noteGmailKept)
		}
	}
}

// gmailRegistration is clerk.Registration on the owner's socket.
type gmailRegistration struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

type gmailBeginArgs struct {
	Use          string             `json:"use"`
	Registration *gmailRegistration `json:"registration,omitempty"`
}

// gmailBegun is gmailbegin's answer: the consent address, or a detail.
type gmailBegun struct {
	Consent string `json:"consent,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type gmailFinishArgs struct {
	Use    string `json:"use"`
	Pasted string `json:"pasted"`
}
