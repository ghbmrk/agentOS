package kernel

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
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
	Anchors []key.PublicKey `json:"anchors"`
	Sigs    [][]byte        `json:"sigs"`
}

// SetupMsg is what each hardware key signs: the domain, the box's head key
// and every anchor, in order, each after its length.
func SetupMsg(box ed25519.PublicKey, anchors []key.PublicKey) []byte {
	m := append([]byte(DomainSetup), box...)
	for _, a := range anchors {
		e := a.Encode()
		m = append(binary.BigEndian.AppendUint16(m, uint16(len(e))), e...)
	}
	return m
}

// SignSetup is the owner's setup step, signed by each hardware key in turn.
func SignSetup(box ed25519.PublicKey, keys ...key.Signer) FirstAnchors {
	var f FirstAnchors
	for _, k := range keys {
		f.Anchors = append(f.Anchors, k.Public())
	}
	msg := SetupMsg(box, f.Anchors)
	for _, k := range keys {
		f.Sigs = append(f.Sigs, k.Sign(msg))
	}
	return f
}

// shape checks what a fold can: SetupAnchors distinct keys.
func (f FirstAnchors) shape() bool {
	if len(f.Anchors) != SetupAnchors {
		return false
	}
	for i, a := range f.Anchors {
		if !a.Valid() || key.In(f.Anchors[:i], a) {
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
func (k *Kernel) Setup(now int64, f FirstAnchors) error { return k.SetupWithEdge(now, f, nil) }

// SetupWithEdge is Setup on a box whose link port captured a first edge key
// before the Owner Card confirm (HW-15, brief EDGE-link-core decision 3):
// the key is logged right after the anchors, as the log's second entry, and
// no later step logs a first key. A nil edge logs none.
func (k *Kernel) SetupWithEdge(now int64, f FirstAnchors, edge ed25519.PublicKey) error {
	if edge != nil && !edgeKey(edge) {
		return ErrEdgeKey
	}
	if !k.s.SetupOpen() {
		return ErrSetupClosed
	}
	if !f.shape() || len(f.Sigs) != len(f.Anchors) {
		return ErrSetupKeys
	}
	msg := SetupMsg(k.log.cfg.Pub, f.Anchors)
	for i, a := range f.Anchors {
		if !a.Verify(msg, f.Sigs[i]) {
			return ErrSetupKeys
		}
	}
	if err := k.owner(now, TAnchorsSet, f); err != nil || edge == nil {
		return err
	}
	return k.edgeFirst(now, edge)
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
	s.edge.setup = true
	return nil
}

// MaxSetupFrame bounds the log's first frame as LoggedAnchors reads it: far
// above an anchors.set entry with two ES256 keys and their signatures.
const MaxSetupFrame = 64 << 10

// LoggedAnchors reads the owner's anchors from a log's first entry, for the
// unlock step on a box whose setup put them there and not in the store
// (#2995, MAIL-keys). raw is the start of the log file, logKey the log's key
// and box the head key's public half, which each hardware key signed over.
// ok is false for a log with no whole first frame (none yet, or torn by a
// crash). A first entry that is not anchors.set, or does not open under
// logKey, or is not the owner's two keys each signing SetupMsg, is
// ErrCorrupt. Only a holder of the log key writes a frame that opens, and
// the signatures bind the keys to this box's head key.
func LoggedAnchors(raw []byte, logKey [32]byte, box ed25519.PublicKey) (anchors []key.PublicKey, ok bool, err error) {
	a, err := newAEAD(logKey)
	if err != nil {
		return nil, false, err
	}
	if len(raw) < 4 {
		return nil, false, nil
	}
	n := int(binary.BigEndian.Uint32(raw))
	switch {
	case n < a.NonceSize()+a.Overhead() || n > MaxSetupFrame:
		return nil, false, ErrCorrupt
	case len(raw)-4 < n:
		return nil, false, nil
	}
	fr := raw[4 : 4+n]
	pt, err := a.Open(nil, fr[:a.NonceSize()], fr[a.NonceSize():], aad(1))
	if err != nil {
		return nil, false, ErrCorrupt
	}
	var e Entry
	if json.Unmarshal(pt, &e) != nil || e.Seq != 1 || e.Prev != (Hash{}) || e.Type != TAnchorsSet || !Known(e.Type, e.V) {
		return nil, false, ErrCorrupt
	}
	f, err := body[FirstAnchors](e)
	if err != nil || !f.shape() || len(f.Sigs) != len(f.Anchors) {
		return nil, false, ErrCorrupt
	}
	msg := SetupMsg(box, f.Anchors)
	for i, k := range f.Anchors {
		if !k.Verify(msg, f.Sigs[i]) {
			return nil, false, ErrCorrupt
		}
	}
	return f.Anchors, true, nil
}
