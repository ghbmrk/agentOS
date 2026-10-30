// Package enfpair is the core's half of handing a safety-list device's
// secret to the enforcer (SPEC STO-3, STO-4; briefs/ENF.md slice r,
// decision 10). A device-pairing clerk (HomeKit, Matter) calls Seal with
// the secret the pairing produced: the secret is sealed to the enforcer's
// pairing key (package pairseal), bound to the device's ID, and the
// caller's plaintext is erased at once. The helper keeps only the sealed
// copy, for the add-device proposal link, until the enforcer's channel
// read reports that fingerprint held (Held); then it drops that too.
//
// It holds no private key: nothing it keeps opens without the enforcer.
// It imports the standard library and broker/enforcer/pairseal only
// (broker/daemon/arc2_test.go). Wiring it into each pairing clerk is that
// device row's work. Its assumptions are in ASSUMPTIONS.md.
package enfpair

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"sync"

	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
)

var ErrNotHeld = errors.New("enfpair: no sealed secret waiting for the device")

// Sealed is one device's sealed secret, as the add-device link carries it.
type Sealed struct {
	Device   string
	Envelope []byte
}

// Hash is the envelope's hash, which the owner's diff names.
func (s Sealed) Hash() string { return pairseal.HashHex(s.Envelope) }

// Link is the add-device proposal link base (the enforcer page's
// https://<name>/p?d=... link for the next document) with the device and
// the envelope's hash as query parameters and the envelope as the
// fragment, which the browser never sends in a request: the page's script
// posts it back with the owner's assertion.
func (s Sealed) Link(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Fragment != "" {
		return "", errors.New("enfpair: not a proposal link")
	}
	q := u.Query()
	q.Set(pairseal.ParamDevice, s.Device)
	q.Set(pairseal.ParamHash, s.Hash())
	u.RawQuery = q.Encode()
	return u.String() + "#" + base64.RawURLEncoding.EncodeToString(s.Envelope), nil
}

// Helper seals device secrets to one enforcer and keeps each sealed copy
// until that enforcer reports it held. Its methods are safe for concurrent
// use.
type Helper struct {
	to   pairseal.Recipient
	mu   sync.Mutex
	held map[string][]byte // device -> envelope, until Held
}

// New seals to the enforcer whose pairing key is to (pinned at the
// enforcer's enrolment).
func New(to pairseal.Recipient) *Helper {
	return &Helper{to: to, held: map[string][]byte{}}
}

// Seal seals secret for device and erases secret in place, whether or not
// sealing succeeded, so the caller's buffer holds no plaintext after it.
// The sealed copy replaces any earlier one for device (a pairing redone).
func (h *Helper) Seal(device string, secret []byte) (Sealed, error) {
	defer clear(secret)
	env, err := pairseal.Seal(h.to, device, secret)
	if err != nil {
		return Sealed{}, err
	}
	h.mu.Lock()
	h.held[device] = env
	h.mu.Unlock()
	return Sealed{Device: device, Envelope: bytes.Clone(env)}, nil
}

// Waiting is device's sealed copy, to draw its link again, while the
// enforcer has not reported it held.
func (h *Helper) Waiting(device string) (Sealed, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	env, ok := h.held[device]
	return Sealed{Device: device, Envelope: bytes.Clone(env)}, ok
}

// Held takes the fingerprint the enforcer's channel read reported for
// device. When it is this copy's hash, the enforcer holds the secret and
// the sealed copy is dropped; any other fingerprint keeps it.
func (h *Helper) Held(device string, fp [pairseal.HashLen]byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	env, ok := h.held[device]
	if !ok || pairseal.Hash(env) != fp {
		return ErrNotHeld
	}
	clear(env)
	delete(h.held, device)
	return nil
}
