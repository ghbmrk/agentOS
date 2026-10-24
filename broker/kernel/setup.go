package kernel

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Setup-only start (#2905 open point 2, Mark 2026-10-24,
// cmsg_01R91wiieBzMSvPKFsAJVvuK7gq3jqjc2vQq7vC7kHmrzJ). A box enrolled with no
// anchors in its store starts with none: nothing it holds can authorize a
// step, and the kernel process serves only the setup step. The owner's two
// hardware keys (ID-1, KEY-4) then come in once, as the log's first entry.
// The log is sealed under the store's keys and its head is numbered by the
// TPM counter, so the entry is as fixed as a store entry, and a drive rolled
// back to before it starts no kernel. No entry is first twice, so the window
// closes for good, as HW-15's first edge key does.

// TAnchorsSet is the setup step's entry: the owner's first anchors.
const TAnchorsSet = "anchors.set"

// SetupAnchors is how many hardware keys setup takes: both of the owner's
// (ID-1). Nothing adds an anchor later but recovery, so one alone is refused.
const SetupAnchors = 2

// DomainSetup separates a hardware key's setup signature from every other
// signature it makes.
const DomainSetup = "agentos.kernel.setup.v1\x00"

var (
	// ErrSetupClosed refuses setup on a box that has its anchors or a log.
	ErrSetupClosed = errors.New("kernel: setup is closed: I already have your hardware keys or a log")
	// ErrSetupKeys refuses a setup that is not the owner's two hardware
	// keys, each signing.
	ErrSetupKeys = errors.New("kernel: setup needs your two hardware keys, each touched once")
)

// FirstAnchors is the setup step: the owner's hardware keys and each one's
// signature over SetupMsg, which proves the key signs and binds it to this
// box's log, so it cannot be replayed onto another box.
type FirstAnchors struct {
	Anchors []ed25519.PublicKey `json:"anchors"`
	Sigs    [][]byte            `json:"sigs"`
}

// SetupMsg is what each hardware key signs: the domain, the box's head key
// and every anchor, in order.
func SetupMsg(box ed25519.PublicKey, anchors []ed25519.PublicKey) []byte {
	m := append([]byte(DomainSetup), box...)
	for _, a := range anchors {
		m = append(m, a...)
	}
	return m
}

// SignSetup is the owner's setup step, signed by each hardware key in turn.
func SignSetup(box ed25519.PublicKey, keys ...ed25519.PrivateKey) FirstAnchors {
	var f FirstAnchors
	for _, k := range keys {
		f.Anchors = append(f.Anchors, k.Public().(ed25519.PublicKey))
	}
	msg := SetupMsg(box, f.Anchors)
	for _, k := range keys {
		f.Sigs = append(f.Sigs, ed25519.Sign(k, msg))
	}
	return f
}

// shape checks what a fold can: SetupAnchors distinct keys.
func (f FirstAnchors) shape() bool {
	if len(f.Anchors) != SetupAnchors {
		return false
	}
	for i, a := range f.Anchors {
		if len(a) != ed25519.PublicKeySize || key.In(f.Anchors[:i], a) {
			return false
		}
	}
	return true
}

// SetupOpen reports whether the setup step can still be taken: no anchors
// and an empty log.
func (s *State) SetupOpen() bool { return len(s.Anchors) == 0 && s.Seq == 0 }

// Box is this box's head key, which the setup step signs over.
func (k *Kernel) Box() ed25519.PublicKey { return slices.Clone(k.log.cfg.Pub) }

// Setup takes the owner's first anchors (D-146) on a box that has none. It
// is the log's first entry and anchors before it returns; from then on the
// kernel serves as any other. The owner channel authenticates the caller as
// the phone setup paired (CH-9, HW-10), as for every owner action.
func (k *Kernel) Setup(now int64, f FirstAnchors) error {
	if !k.s.SetupOpen() {
		return ErrSetupClosed
	}
	if !f.shape() || len(f.Sigs) != len(f.Anchors) {
		return ErrSetupKeys
	}
	msg := SetupMsg(k.log.cfg.Pub, f.Anchors)
	for i, a := range f.Anchors {
		if !ed25519.Verify(a, msg, f.Sigs[i]) {
			return ErrSetupKeys
		}
	}
	return k.owner(now, TAnchorsSet, f)
}

// applySetup folds the setup entry: only as the log's first, on a box whose
// store gave no anchors. A log that breaks either rule is not this box's.
func (s *State) applySetup(e Entry) error {
	f, err := body[FirstAnchors](e)
	if err != nil {
		return err
	}
	if e.Seq != 1 || len(s.Anchors) != 0 || !f.shape() {
		return fmt.Errorf("entry %d %s: setup is not this log's first entry or not two keys: %w", e.Seq, e.Type, ErrCorrupt)
	}
	s.Anchors = slices.Clone(f.Anchors)
	return nil
}
