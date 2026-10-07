package clock

import (
	"errors"
	"time"
)

// PhoneAttestRefused is the fixed wording when a phone-attested time is
// rejected (HOST-1b security T8–T10).
const PhoneAttestRefused = "That time from your phone doesn't look right. Try again from my Wi-Fi page."

// ErrPhoneAttest is returned by PhoneAttest.Check when the attested time
// fails T8–T10. Its Error text is PhoneAttestRefused.
var ErrPhoneAttest = errors.New(PhoneAttestRefused)

// PhoneAttest holds the bounds for a phone-attested time used for codes
// and waits only (HOST-1b part 2; security T8–T10). It never advances the
// floor and is never used for update, TUF, certificate, or 180-day checks.
type PhoneAttest struct {
	// Last is the last accepted attested time; the next must be strictly later (T8).
	Last time.Time
	// Floor is the box clock floor; attested time must be at or after it (T10).
	Floor time.Time
	// RTCOffset is RTC−UTC when known; zero and HasOffset false means unknown (T10).
	RTCOffset time.Duration
	HasOffset bool
	// RTC is the hardware clock reading when HasOffset is true.
	RTC time.Time
}

// Check reports whether attested may be used for codes and waits.
// On success the caller should persist attested as Last (and record the
// code step as used). Check does not mutate PhoneAttest.
func (p PhoneAttest) Check(attested time.Time) error {
	attested = attested.UTC()
	if !p.Last.IsZero() && !attested.After(p.Last.UTC()) {
		return ErrPhoneAttest
	}
	if !p.Floor.IsZero() && attested.Before(p.Floor.UTC()) {
		return ErrPhoneAttest
	}
	if p.HasOffset {
		center := p.RTC.UTC().Add(-p.RTCOffset)
		delta := attested.Sub(center)
		if delta < -24*time.Hour || delta > 24*time.Hour {
			return ErrPhoneAttest
		}
	}
	return nil
}

// Accept is Check followed by recording attested as Last on success.
func (p *PhoneAttest) Accept(attested time.Time) error {
	if err := p.Check(attested); err != nil {
		return err
	}
	p.Last = attested.UTC()
	return nil
}
