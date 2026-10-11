package main

import (
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"net/url"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// Setup's code-generator enrollment (ONB-3, ONB-6; Security L7 and P4 on
// the P2-2w plan): the seed is made here, inside the vault, and handed out
// once, in the answer that made it, for the Wi-Fi page to show as an
// otpauth:// link and QR code. One entered code from it confirms it: the
// seed then becomes the channel's (SeedName). Setup's finish seals the
// enrollment for good, and only a confirmation made since the last
// enroll seals: a setup that starts over (reset secret) enrolls again,
// so a phone that confirmed before the restart cannot leave its seed
// sealed (L3 on #367). A later change of seed is REC-3's re-enrollment,
// which needs the recovery key (recovery.ReEnroll).
const (
	// PendingSeedName holds the seed handed out and not yet confirmed.
	PendingSeedName = "owner-totp-pending"
	// EnrolledName marks a confirmed enrollment. It is in the vault, not
	// the state file, so editing the drive cannot reopen enrollment.
	EnrolledName = "owner-totp-enrolled"
	// KindEnrolled is EnrolledName's kind; its value is random, so the
	// redactor (CRED-7) matches nothing a person would write.
	KindEnrolled = "totp_enrolled"
	// ConfirmedName marks that the seed now in SeedName was confirmed
	// since the last enroll; the seal needs it. Enroll deletes it.
	ConfirmedName = "owner-totp-confirmed"
	// KindConfirmed is ConfirmedName's kind; its value is random.
	KindConfirmed = "totp_confirmed"
	// SetupOpenName opens enrollment. Only `init -setup` writes it (the
	// image's setup path); the seal that writes EnrolledName deletes it. A vault without it is closed, so boxes made by plain
	// init, by REC-3's re-enroll or before c1 cannot have their seed
	// swapped by agentosd.
	SetupOpenName = "owner-totp-setup-open"
	// KindSetupOpen is SetupOpenName's kind; its value is random.
	KindSetupOpen = "totp_setup_open"
)

const noteEnrolled = "A new code generator was enrolled at setup; codes from any earlier one no longer work."

var (
	errEnrolled = uerr(http.StatusGone, "the code generator is already enrolled; a new one needs the recovery key")
	// errNotOpen: setup mode never opened enrollment on this vault, or an
	// entry it keeps is of the wrong kind (P2-2w c2 r1). Apart from
	// errEnrolled, so setup can tell the owner it cannot finish here.
	errNotOpen      = uerr(http.StatusPreconditionFailed, "setup did not open code-generator enrollment on this vault")
	errNoEnrollment = uerr(http.StatusConflict, "no code generator is waiting for confirmation")
	errNotConfirmed = uerr(http.StatusConflict, "no code generator was confirmed since the last enrollment")
)

// closedLocked reports whether enrollment is closed: errEnrolled when
// setup's seal is written (only sealEnroll writes it), errNotOpen when
// setup mode never opened it or an entry is of the wrong kind, nil when
// open. Caller holds mu with the vault open.
func (c *custody) closedLocked() error {
	for _, e := range c.v.List() {
		if e.Name == EnrolledName {
			if e.Kind != KindEnrolled {
				return errNotOpen
			}
			return errEnrolled
		}
	}
	if !hasKind(c.v, SetupOpenName, KindSetupOpen) ||
		hasOtherKind(c.v, PendingSeedName, vault.KindTOTPSeed) {
		return errNotOpen
	}
	return nil
}

// enroll makes a fresh seed in the vault, replacing any pending one, and
// returns it once as an otpauth:// link. Each call makes a new seed, so a
// seed is never handed out twice.
func (c *custody) enroll() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return "", errLocked
	}
	if err := c.closedLocked(); err != nil {
		return "", err
	}
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return "", errInternal
	}
	defer clear(seed)
	if err := c.v.Put(PendingSeedName, vault.KindTOTPSeed, seed); err != nil {
		return "", c.putErr(err)
	}
	// A confirmation made before this enroll no longer seals: the setup
	// that asked for this seed waits on its own confirmation.
	if c.v.Delete(ConfirmedName) != nil {
		return "", errInternal
	}
	return otpauthURI(seed), nil
}

// confirmEnroll checks code against the pending seed. A match spends the
// step (as verify does), makes the pending seed the channel's, and marks
// it confirmed for sealEnroll. Wrong codes count with the channel's counted codes, so a
// taken-over agentosd cannot grind the pending seed faster than the channel.
func (c *custody) confirmEnroll(code string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return false, errLocked
	}
	if err := c.closedLocked(); err != nil {
		return false, err
	}
	pending, ok := c.v.Secret(PendingSeedName)
	if !ok {
		return false, errNoEnrollment
	}
	now := c.now()
	c.wrongCounted = since(c.wrongCounted, now.Add(-VerifyWindow))
	if len(c.wrongCounted) >= MaxWrongCounted {
		return false, &pausedError{until: c.wrongCounted[0].Add(VerifyWindow)}
	}
	seed := []byte(pending.Reveal())
	defer clear(seed)
	step, ok := owner.MatchTOTP(seed, code, now, c.st.LastStep)
	if !ok {
		c.wrongCounted = append(c.wrongCounted, now)
		return false, nil
	}
	next := c.st
	next.LastStep = step
	if err := c.persist(next); err != nil {
		return false, errInternal
	}
	// Seed first, then the mark, then the pending copy: a crash between
	// any two leaves a state the next confirmation or enroll finishes or
	// refuses, never a confirmed mark over the old seed.
	if hasOtherKind(c.v, SeedName, vault.KindTOTPSeed) {
		return false, errInternal
	}
	if err := c.v.Put(SeedName, vault.KindTOTPSeed, seed); err != nil {
		return false, c.putErr(err)
	}
	if err := c.putMark(ConfirmedName, KindConfirmed); err != nil {
		return false, err
	}
	if c.v.Delete(PendingSeedName) != nil {
		return false, errInternal
	}
	return true, nil
}

// sealEnroll closes enrollment for good, at setup's finish. It needs a
// confirmation made since the last enroll, and no newer seed waiting, so
// the seed it seals is the one the finishing setup's phone confirmed.
func (c *custody) sealEnroll() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if err := c.closedLocked(); err != nil {
		return err
	}
	if _, ok := c.v.Secret(PendingSeedName); ok || !hasKind(c.v, ConfirmedName, KindConfirmed) {
		return errNotConfirmed
	}
	// The seal first: once it is written enrollment is closed, whatever
	// a crash leaves of the entries after it.
	if err := c.putMark(EnrolledName, KindEnrolled); err != nil {
		return err
	}
	if c.v.Delete(SetupOpenName) != nil || c.v.Delete(ConfirmedName) != nil {
		return errInternal
	}
	c.notify(noteEnrolled)
	return nil
}

// putMark writes a marker entry with a random value, so the redactor
// (CRED-7) matches nothing a person would write.
func (c *custody) putMark(name, kind string) error {
	mark := make([]byte, 16)
	if _, err := rand.Read(mark); err != nil {
		return errInternal
	}
	if err := c.v.Put(name, kind, mark); err != nil {
		return c.putErr(err)
	}
	return nil
}

// otpauthURI is the link the owner's code generator scans (ONB-6): SHA-1,
// 6 digits, 30-second steps, as owner.MatchTOTP checks.
func otpauthURI(seed []byte) string {
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed))
	q.Set("issuer", "AgentOS")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/AgentOS:box?" + q.Encode()
}
