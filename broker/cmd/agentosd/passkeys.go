package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// passkeyKernel is the owner seam the passkey ops call
// (kernelsock.Owner): the anchors and enrollments the log holds, and
// Enroll and Unenroll, which the kernel decides.
type passkeyKernel interface {
	Anchors(ctx context.Context) ([]key.PublicKey, error)
	Enrollments(ctx context.Context) ([]key.Enrollment, []key.PublicKey, error)
	Enroll(ctx context.Context, e key.Enrollment) error
	Unenroll(ctx context.Context, u key.Unenrollment) error
}

// passkeyPending is how long a begun enrolment waits for the hardware
// key's tap.
const passkeyPending = 5 * time.Minute

// maxPending bounds the begun enrolments kept, one per page session
// (localsrv MaxSessions); a new one past it evicts the oldest.
const maxPending = 16

// passkeys is the owner side's passkey ops (#2779a; localsrv.Passkeys):
// it lists the owner's keys from the kernel's log, builds an enrollment
// from the page's two WebAuthn ceremonies, and cuts a phone passkey off
// on a hardware key's tap (#3209).
// It signs nothing and keeps nothing but the begun points: the kernel
// checks every enrollment against its own anchors.
type passkeys struct {
	K    passkeyKernel
	RPID string
	Now  func() time.Time

	mu      sync.Mutex
	pending map[string]pendingKey // by page session
}

type pendingKey struct {
	pk key.PublicKey
	at time.Time
}

func newPasskeys(k passkeyKernel, rpID string) *passkeys {
	return &passkeys{K: k, RPID: rpID, Now: time.Now, pending: map[string]pendingKey{}}
}

// passkeyCode maps the kernel's answer to the page's fixed codes; no
// kernel text passes. refused is the code for the kernel's own refusal.
func passkeyCode(err error, refused string) error {
	var r kernelsock.Refused
	switch {
	case err == nil:
		return nil
	case errors.Is(err, kernelsock.ErrSetupOnly):
		return sockets.Code(localapi.ErrPasskeySetup)
	case errors.Is(err, kernelsock.ErrAnchor):
		return sockets.Code(localapi.ErrPasskeyAnchor)
	case refused != "" && errors.As(err, &r):
		return sockets.Code(refused)
	}
	return sockets.Code(localapi.ErrPasskeyUnavailable)
}

// keyID is a key's ID on the page: the SHA-256 of its signed encoding.
func keyID(pk key.PublicKey) string {
	d := sha256.Sum256(pk.Encode())
	return hex.EncodeToString(d[:])
}

// fingerprint is a key's ID cut to 12 hex digits in groups of four.
func fingerprint(pk key.PublicKey) string {
	id := keyID(pk)
	return id[0:4] + " " + id[4:8] + " " + id[8:12]
}

func listed(pk key.PublicKey, by string) localapi.Passkey {
	return localapi.Passkey{ID: keyID(pk), Fingerprint: fingerprint(pk), Alg: pk.Alg(), By: by}
}

// keys reads the anchors, the live phone passkeys with the anchor that
// enrolled each, and the cut-off keys.
func (p *passkeys) keys(ctx context.Context) (anchors []key.PublicKey, live []key.Enrollment, cut []key.PublicKey, err error) {
	if anchors, err = p.K.Anchors(ctx); err != nil {
		return nil, nil, nil, err
	}
	es, un, err := p.K.Enrollments(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	set := key.Passkeys(anchors, es, un)
	for _, e := range es {
		if key.In(set, e.Passkey) && !key.In(anchors, e.Passkey) && !enrolledIn(live, e.Passkey) &&
			key.In(anchors, e.By) && e.By.Verify(key.EnrollMsg(e.Passkey), e.Sig) {
			live = append(live, e)
		}
	}
	for _, pk := range un {
		if pk.Valid() && !key.In(cut, pk) {
			cut = append(cut, pk)
		}
	}
	return anchors, live, cut, nil
}

func enrolledIn(es []key.Enrollment, pk key.PublicKey) bool {
	for _, e := range es {
		if e.Passkey == pk {
			return true
		}
	}
	return false
}

func (p *passkeys) List(ctx context.Context) (localapi.PasskeyList, error) {
	anchors, live, cut, err := p.keys(ctx)
	if err != nil {
		return localapi.PasskeyList{}, passkeyCode(err, "")
	}
	l := localapi.PasskeyList{Anchors: []localapi.Passkey{}, Enrolled: []localapi.Passkey{}, CutOff: []localapi.Passkey{}}
	for _, a := range anchors {
		l.Anchors = append(l.Anchors, listed(a, ""))
	}
	for _, e := range live {
		k := listed(e.Passkey, fingerprint(e.By))
		c := key.Challenge(key.UnenrollMsg(e.Passkey))
		k.CutChallenge = c[:]
		l.Enrolled = append(l.Enrolled, k)
	}
	for _, pk := range cut {
		l.CutOff = append(l.CutOff, listed(pk, ""))
	}
	return l, nil
}

// Begin keeps the new credential's point for session and returns the
// challenge over EnrollMsg of it. The kernel is asked for its anchors
// first, so a setup-only kernel refuses here.
func (p *passkeys) Begin(ctx context.Context, session string, point []byte) ([]byte, error) {
	pk, err := key.ES256(p.RPID, point)
	if err != nil {
		return nil, sockets.Code(localapi.ErrBadArgs)
	}
	if _, err := p.K.Anchors(ctx); err != nil {
		return nil, passkeyCode(err, "")
	}
	now := p.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for s, k := range p.pending {
		if now.Sub(k.at) >= passkeyPending {
			delete(p.pending, s)
		}
	}
	if _, ok := p.pending[session]; !ok && len(p.pending) >= maxPending {
		oldest := ""
		for s, k := range p.pending {
			if oldest == "" || k.at.Before(p.pending[oldest].at) {
				oldest = s
			}
		}
		delete(p.pending, oldest)
	}
	p.pending[session] = pendingKey{pk, now}
	c := key.Challenge(key.EnrollMsg(pk))
	return c[:], nil
}

// pendingFor is session's begun point while it has not lapsed.
func (p *passkeys) pendingFor(session string) (key.PublicKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.pending[session]
	if !ok || p.Now().Sub(k.at) >= passkeyPending {
		delete(p.pending, session)
		return key.PublicKey{}, false
	}
	return k.pk, true
}

// Finish enrols session's begun point under the anchor whose assertion
// this is. The anchor is found by tapper; these pre-checks only make the
// reply exact: the kernel decides.
func (p *passkeys) Finish(ctx context.Context, session string, authData, clientData, sig []byte) error {
	pk, ok := p.pendingFor(session)
	if !ok {
		return sockets.Code(localapi.ErrPasskeyStale)
	}
	anchors, live, _, err := p.keys(ctx)
	if err != nil {
		return passkeyCode(err, "")
	}
	by, canon, err := tapper(key.EnrollMsg(pk), anchors, live, authData, clientData, sig)
	if err != nil {
		return err
	}
	if err := p.K.Enroll(ctx, key.Enrollment{Passkey: pk, By: by, Sig: canon}); err != nil {
		return passkeyCode(err, localapi.ErrPasskeyRefused)
	}
	p.mu.Lock()
	if p.pending[session].pk == pk {
		delete(p.pending, session)
	}
	p.mu.Unlock()
	return nil
}

// tapper is the anchor whose assertion over msg this is, and the assertion
// in its one accepted encoding (KEY-7). The anchor is found by verifying
// against each; a tap by a live phone passkey is ErrPasskeyNotAnchor, by
// no listed key ErrPasskeyBadAssertion.
func tapper(msg []byte, anchors []key.PublicKey, live []key.Enrollment, authData, clientData, sig []byte) (key.PublicKey, []byte, error) {
	canon, err := key.AssertionSig(key.Assertion{AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig})
	if err != nil {
		return key.PublicKey{}, nil, sockets.Code(localapi.ErrPasskeyBadAssertion)
	}
	for _, a := range anchors {
		if a.Verify(msg, canon) {
			return a, canon, nil
		}
	}
	for _, e := range live {
		if e.Passkey.Verify(msg, canon) {
			return key.PublicKey{}, nil, sockets.Code(localapi.ErrPasskeyNotAnchor)
		}
	}
	return key.PublicKey{}, nil, sockets.Code(localapi.ErrPasskeyBadAssertion)
}

// CutOff cuts the listed phone passkey id off for good on a hardware key's
// assertion over key.UnenrollMsg of it (#3209), found by tapper. An anchor
// is refused before the kernel is called (ErrPasskeyAnchor), and the
// kernel's own refusal of one maps to the same code. A key cut off already
// is done; one not listed is ErrPasskeyStale (the page's list is old).
func (p *passkeys) CutOff(ctx context.Context, id string, authData, clientData, sig []byte) error {
	anchors, live, cut, err := p.keys(ctx)
	if err != nil {
		return passkeyCode(err, "")
	}
	for _, a := range anchors {
		if keyID(a) == id {
			return sockets.Code(localapi.ErrPasskeyAnchor)
		}
	}
	for _, pk := range cut {
		if keyID(pk) == id {
			return nil
		}
	}
	for _, e := range live {
		if keyID(e.Passkey) == id {
			by, canon, err := tapper(key.UnenrollMsg(e.Passkey), anchors, live, authData, clientData, sig)
			if err != nil {
				return err
			}
			u := key.Unenrollment{Passkey: e.Passkey, By: by, Sig: canon}
			return passkeyCode(p.K.Unenroll(ctx, u), localapi.ErrPasskeyRefused)
		}
	}
	return sockets.Code(localapi.ErrPasskeyStale)
}

// validRPID is a WebAuthn RP ID agentosd takes: a lowercase DNS name with
// at least two labels and not an address, as key.ES256 binds a credential to it.
func validRPID(rp string) bool {
	if rp == "" || len(rp) > 253 || strings.Trim(rp, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
		return false
	}
	labels := strings.Split(rp, ".")
	if len(labels) < 2 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false // one label, or an address
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	return true
}
