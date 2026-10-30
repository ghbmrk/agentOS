package line

// The signing binding (D-154 option A): the clerk keeps the password and
// answers the line process's digest challenges, but only for its own
// registration, at most once per RegisterEvery, and for a MESSAGE that is
// one send the clerk admitted, once, to that send's recipient. This file and
// sign_test.go are the whole of it, so they drop if the line runs in the
// keeper instead (option B).

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/icholy/digest"

	"github.com/ghbmrk/agentos/broker/sipsign"
)

// RegisterEvery is the least time between two REGISTER signatures, in ms.
const RegisterEvery = 30_000

// Refusals from Sign besides sipsign's. Each is counted in Status.
var (
	ErrRegisterRate = errors.New("line: registered too recently")
	ErrUnbound      = errors.New("line: no admitted send for that request")
)

// Signer answers the line process's digest challenges (sipline.Signer).
type Signer struct {
	c *Clerk

	mu           sync.Mutex
	tickets      map[string]*ticket // by idempotency key
	lastRegister int64
	signed       bool // lastRegister is set
	refusals     int
}

// ticket is one admitted send: one MESSAGE signature to one recipient.
type ticket struct {
	to   string
	used bool
}

// NewSigner returns c's signer and binds it to c's sends.
func NewSigner(c *Clerk) *Signer {
	s := &Signer{c: c, tickets: map[string]*ticket{}}
	c.bind = s
	return s
}

func (s *Signer) admit(idem, to string) {
	s.mu.Lock()
	s.tickets[idem] = &ticket{to: to}
	s.mu.Unlock()
}

func (s *Signer) revoke(idem string) {
	s.mu.Lock()
	delete(s.tickets, idem)
	s.mu.Unlock()
}

func (s *Signer) refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refusals
}

// Sign answers ch with an Authorization value, or refuses and counts it.
func (s *Signer) Sign(ctx context.Context, ch sipsign.Challenge) (string, error) {
	auth, err := s.sign(ctx, ch)
	if err != nil {
		s.mu.Lock()
		s.refusals++
		s.mu.Unlock()
	}
	return auth, err
}

func (s *Signer) sign(ctx context.Context, ch sipsign.Challenge) (string, error) {
	acct := s.c.acct
	rec, ok := acct.Record()
	if !ok || !acct.hasPassword() {
		return "", ErrNoAccount
	}
	domain := strings.ToLower(rec.Settings.Domain)
	switch ch.Method {
	case "REGISTER":
		if !strings.EqualFold(ch.URI, "sip:"+domain) {
			return "", ErrUnbound
		}
		now := s.c.cfg.Clock.Now()
		// Held across the signature, so two registrations at once sign one.
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.signed && now-s.lastRegister < RegisterEvery {
			return "", ErrRegisterRate
		}
		realm := rec.Realm
		if realm == "" {
			// The first registration over verified TLS records the realm
			// (SL3), only once the challenge can be answered with it.
			p, err := digest.ParseChallenge(ch.Header)
			if err != nil || p.Realm == "" {
				return "", sipsign.ErrChallenge
			}
			realm = p.Realm
		}
		auth, err := acct.sign(ctx, rec, realm, ch)
		if err != nil {
			return "", err
		}
		if rec.Realm == "" {
			if err := acct.learnRealm(realm); err != nil {
				return "", err
			}
		}
		s.lastRegister, s.signed = now, true
		return auth, nil
	case "MESSAGE":
		to := sipsign.Recipient(ch.URI, rec.Settings.NoPlus)
		if to == "" || !strings.EqualFold(uriHost(ch.URI), domain) {
			return "", ErrUnbound
		}
		s.mu.Lock()
		var t *ticket
		for _, x := range s.tickets {
			if !x.used && x.to == to {
				t = x
				break
			}
		}
		if t == nil {
			s.mu.Unlock()
			return "", ErrUnbound
		}
		t.used = true
		s.mu.Unlock()
		return acct.sign(ctx, rec, rec.Realm, ch)
	}
	// INVITE, BYE and CANCEL wait for calls (part d).
	return "", sipsign.ErrMethod
}

// uriHost is the host of a sip: or sips: URI, "" if it has none.
func uriHost(uri string) string {
	_, rest, ok := strings.Cut(uri, "@")
	if !ok {
		return ""
	}
	host, _, _ := strings.Cut(rest, ";")
	host, _, _ = strings.Cut(host, ":")
	host, _, _ = strings.Cut(host, ">")
	return host
}
