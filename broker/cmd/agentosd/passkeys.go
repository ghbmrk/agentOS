package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
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
	keyReader
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
	// Tell texts the owner (informOwner): each phone passkey this agentosd
	// enrols is announced once (#3228).
	Tell func(string) error

	mu      sync.Mutex
	pending map[string]pendingKey // by page session
	told    map[key.PublicKey]bool

	// waiting, when set (tests only), is called as a Finish starts waiting
	// for the one under way on its point.
	waiting func()
}

type pendingKey struct {
	pk key.PublicKey
	at time.Time
	// f is the Finish under way on this point, nil when none is: a second
	// Finish waits for it and takes its answer.
	f *finishing
}

type finishing struct {
	done chan struct{}
	err  error // set before done is closed
}

func newPasskeys(k passkeyKernel, rpID string, tell func(string) error) *passkeys {
	return &passkeys{K: k, RPID: rpID, Now: time.Now, Tell: tell, pending: map[string]pendingKey{}, told: map[key.PublicKey]bool{}}
}

// enrolledNotice is the owner's notice of a phone passkey enrolled by the
// hardware key by (#3228): a compromised page could put its own point
// under the owner's tap, so the owner sees every key added and can cut off
// one they did not add. The fingerprints' groups are joined by dashes: a
// 4-digit group beside "key" reads as a code to the owner channel's filter
// (owner.CodeShaped, CH-19), which would hold the notice back, while one
// 14-character word does not.
func enrolledNotice(pk, by key.PublicKey) string {
	return "A phone passkey was added: " + noticePrint(pk) + ", approved by hardware key " + noticePrint(by) +
		". If you didn't add it, cut it off on the passkey page."
}

// noticePrint is fingerprint with its groups joined by dashes.
func noticePrint(pk key.PublicKey) string {
	return strings.ReplaceAll(fingerprint(pk), " ", "-")
}

// LogPasskeyUntold is logged when an enrolment's notice could not be sent.
const LogPasskeyUntold = "passkeys: a passkey was enrolled but the owner could not be told"

// announce tells the owner once that pk is live under by.
func (p *passkeys) announce(pk, by key.PublicKey) {
	p.mu.Lock()
	if p.told[pk] {
		p.mu.Unlock()
		return
	}
	p.told[pk] = true
	p.mu.Unlock()
	if p.Tell == nil || p.Tell(enrolledNotice(pk, by)) != nil {
		log.Print(LogPasskeyUntold)
	}
}

// announceIfLive announces pk when the kernel's log holds it live: an
// Enroll whose answer was lost, or refused because an earlier one landed,
// may still have enrolled it.
func (p *passkeys) announceIfLive(ctx context.Context, pk key.PublicKey) {
	_, live, _, err := p.keys(ctx)
	if err != nil {
		return
	}
	for _, e := range live {
		if e.Passkey == pk {
			p.announce(pk, e.By)
		}
	}
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

// keyReader is the reads ownerKeys makes (kernelsock.Owner).
type keyReader interface {
	Anchors(ctx context.Context) ([]key.PublicKey, error)
	Enrollments(ctx context.Context) ([]key.Enrollment, []key.PublicKey, error)
}

// keys reads the anchors, the live phone passkeys with the anchor that
// enrolled each, and the cut-off keys.
func (p *passkeys) keys(ctx context.Context) (anchors []key.PublicKey, live []key.Enrollment, cut []key.PublicKey, err error) {
	return ownerKeys(ctx, p.K)
}

// ownerKeys is passkeys.keys over any reader of the kernel's keys: the
// Backups page's tap is found among the same keys (tapper).
func ownerKeys(ctx context.Context, k keyReader) (anchors []key.PublicKey, live []key.Enrollment, cut []key.PublicKey, err error) {
	if anchors, err = k.Anchors(ctx); err != nil {
		return nil, nil, nil, err
	}
	es, un, err := k.Enrollments(ctx)
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
	p.pending[session] = pendingKey{pk: pk, at: now}
	c := key.Challenge(key.EnrollMsg(pk))
	return c[:], nil
}

// Finish enrols session's begun point under the anchor whose assertion
// this is. One Finish runs per begun point: one posted while another is
// under way waits for it and gets its answer, so the kernel is asked once
// (#3175). A tap that is refused, or a kernel not reached, leaves the
// point to tap again; the kernel's own answer spends it.
func (p *passkeys) Finish(ctx context.Context, session string, authData, clientData, sig []byte) error {
	p.mu.Lock()
	k, ok := p.pending[session]
	if !ok || p.Now().Sub(k.at) >= passkeyPending {
		delete(p.pending, session)
		p.mu.Unlock()
		return sockets.Code(localapi.ErrPasskeyStale)
	}
	if f := k.f; f != nil {
		p.mu.Unlock()
		if p.waiting != nil {
			p.waiting()
		}
		select {
		case <-f.done:
			return f.err
		case <-ctx.Done():
			return sockets.Code(localapi.ErrPasskeyUnavailable)
		}
	}
	f := &finishing{done: make(chan struct{})}
	k.f = f
	p.pending[session] = k
	p.mu.Unlock()

	spent, err := p.finish(ctx, k.pk, authData, clientData, sig)
	p.mu.Lock()
	if cur, ok := p.pending[session]; ok && cur.f == f {
		if spent {
			delete(p.pending, session)
		} else {
			cur.f = nil
			p.pending[session] = cur
		}
	}
	p.mu.Unlock()
	f.err = err
	close(f.done)
	return err
}

// LogPasskeyRPID is logged when a page's tap is on another RP ID than
// -passkey-rp-id.
const LogPasskeyRPID = "passkeys: the page's RP ID is not -passkey-rp-id; nothing is enrolled"

// finish is Finish's work on the begun point pk, and whether it spent pk.
// The anchor is found by tapper; these pre-checks only make the reply
// exact: the kernel decides.
func (p *passkeys) finish(ctx context.Context, pk key.PublicKey, authData, clientData, sig []byte) (spent bool, err error) {
	anchors, live, _, err := p.keys(ctx)
	if err != nil {
		return false, passkeyCode(err, "")
	}
	by, canon, err := tapper(key.EnrollMsg(pk), anchors, live, authData, clientData, sig)
	if err != nil {
		return false, err
	}
	// The tap verified, so authData names the page's RP ID. The phone's
	// credential was made there, but pk is bound to agentosd's: on
	// another, the kernel would log a passkey that never verifies.
	if rp := sha256.Sum256([]byte(p.RPID)); !bytes.Equal(authData[:32], rp[:]) {
		log.Print(LogPasskeyRPID)
		return true, sockets.Code(localapi.ErrPasskeyUnavailable)
	}
	err = p.K.Enroll(ctx, key.Enrollment{Passkey: pk, By: by, Sig: canon})
	if err == nil {
		p.announce(pk, by)
	} else {
		p.announceIfLive(ctx, pk)
	}
	var r kernelsock.Refused
	answered := err == nil || errors.As(err, &r) || errors.Is(err, kernelsock.ErrSetupOnly) || errors.Is(err, kernelsock.ErrAnchor)
	return answered, passkeyCode(err, localapi.ErrPasskeyRefused)
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
