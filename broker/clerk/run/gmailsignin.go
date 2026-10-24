package run

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"maps"
	"strings"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
)

// The owner's Gmail sign-in on the mail process's own socket (#3009, D-150,
// D-154): gmailbegin gives the consent address, gmailfinish takes the
// address the owner pasted, seals the grant in the account's own slot and
// sets the account up, and gmailrevoke gives the grant back to Google and
// removes the account. A first sign-in, with the household's registration,
// runs on a store of its own, in memory under a key drawn here, so
// clerk.SignIn's one-account store holds only it (CLK-1) while the
// account's store still holds the account being replaced. A sign-in again,
// with no registration, runs on the account's store and slot, whose grant
// holds the registration, so it never goes back to the main side (D-154
// rule 1). The new grant reaches the account's slot through Saved, inside
// this process.

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
)

// gmailSignIn is one sign-in, the store and slot its grant is sealed in,
// and the grant once Finish has sealed it.
type gmailSignIn struct {
	in    *clerk.SignIn
	sec   *clerk.Secrets
	slot  string
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

// address is the address of the account the sign-in's grant is for.
func (g *gmailSignIn) address(h *MailHost) (string, error) {
	box, err := gmailBox(g.sec, g.slot, h.cfg)
	if err != nil {
		return "", err
	}
	return box.Address(h.ctx)
}

// gmailBegin starts a sign-in for use and returns the consent address, or a
// detail. reg nil signs in again with the Gmail account's registration.
func (h *MailHost) gmailBegin(use string, reg *clerk.Registration) gmailBegun {
	var g *gmailSignIn
	var err error
	if reg != nil {
		g, err = h.ownGmailSignIn()
	} else {
		h.mu.Lock()
		s, rerr := readMail(h.dir)
		h.mu.Unlock()
		if rerr != nil || s.API != APIGmail || !h.sec.Has(slotOf(s)) {
			return gmailBegun{Detail: clerk.DNoAccount}
		}
		g, err = h.newGmailSignIn(h.sec, slotOf(s), s.Address)
	}
	if err != nil {
		return gmailBegun{Detail: clerk.DNoAccount}
	}
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
// use the owner confirmed, and sets up the Gmail account it is for: a Gmail
// account it replaces has its grant given back first (A22), the new grant
// goes to its account's slot, and the account is opened again, which clears
// a reconnect stop. It answers Finish's detail, or DGmailAddress.
func (h *MailHost) gmailFinish(use, pasted string) (string, error) {
	h.signMu.Lock()
	g := h.signing
	h.signMu.Unlock()
	again := g != nil && g.sec == h.sec // a sign-in again, sealed in the account's own slot
	if g == nil || again && !h.still(g.slot) {
		// None waits, or the account changed while the owner was on
		// Google's page: the owner's later setup stands, and no code is
		// redeemed into its store.
		return clerk.DNoSignIn, nil
	}
	d := g.in.Finish(h.ctx, use, pasted)
	defer func() { clear(g.grant) }() // set by Finish, so read when the call returns
	if !strings.HasPrefix(d, clerk.DSignedIn+" ") {
		return d, nil
	}
	h.signMu.Lock()
	if h.signing == g {
		h.signing = nil
	}
	h.signMu.Unlock()
	if again && !h.still(g.slot) {
		g.in.Revoke(h.ctx) // the account changed during Finish: give it back
		return clerk.DNoSignIn, nil
	}
	addr, err := g.address(h)
	if err == nil {
		err = MailSettings{Address: addr, API: APIGmail}.check()
	}
	if err != nil || len(g.grant) == 0 {
		g.in.Revoke(h.ctx) // no account will use it
		return DGmailAddress, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.idle()
	prev, perr := readMail(h.dir)
	slot := GmailSlot(addr)
	if again && (perr != nil || slotOf(prev) != g.slot) {
		g.in.Revoke(h.ctx) // as above: the account changed meanwhile
		return clerk.DNoSignIn, nil
	}
	replacing := perr == nil && slotOf(prev) != slot
	if replacing && !again {
		h.revokeGmail(prev) // before the new slot is put, so the store holds prev's only
	}
	err = nil
	if slot != g.slot || !again {
		err = h.sec.Put(slot, clerk.KindGrant, g.grant)
	}
	if err == nil {
		err = SetGmail(h.dir, h.sec, addr)
	}
	if err != nil {
		if !again {
			g.in.Revoke(h.ctx) // nothing names the new grant: give it back
		}
		return "", err
	}
	h.changed()
	if replacing {
		h.notify(false, noteMailReplaced)
	}
	h.refresh()
	return d, nil
}

// still reports whether the account set up is still the one in slot.
func (h *MailHost) still(slot string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
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

// revokeGmail gives the grant of s back to Google before a setup or a
// removal drops its slot (A22); h.mu is held, and it runs before any new
// slot is put, so the store holds s's only (CLK-1). An account that is not
// Gmail's, or holds no grant, has nothing to give back. A grant Google kept
// is dropped all the same, so the owner is never stuck on Google's answer,
// and the owner is told the step that ends it.
func (h *MailHost) revokeGmail(s MailSettings) {
	if s.API != APIGmail || !h.sec.Has(slotOf(s)) {
		return
	}
	d := clerk.DNoRevoke
	if g, err := h.newGmailSignIn(h.sec, slotOf(s), ""); err == nil {
		d = g.in.Revoke(h.ctx)
	}
	if d != clerk.DRevoked {
		h.notify(false, noteGmailKept)
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
