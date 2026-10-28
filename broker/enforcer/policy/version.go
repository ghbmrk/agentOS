package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Clerk is the clerk every policy version's root names (brief decision 2).
const Clerk = "enforcer"

var (
	ErrNotOwner = errors.New("policy: not the owner's enforcer passkey")
	ErrBadSig   = errors.New("policy: signature does not verify")
	ErrUnbound  = errors.New("policy: key does not commit to this document and diff")
)

// Proposal is a change as the owner saw it: the next document and the diff
// the enforcer rendered for it (slice b renders; here it is bytes).
type Proposal struct {
	Doc  Document
	Diff []byte
}

// Serial is the root serial that commits to p: its version, the hash of its
// canonical document and the hash of its rendered diff, so the owner's one
// tap approves exactly the change shown (NET-4 Passkey rules).
func (p Proposal) Serial() (string, error) {
	h, err := Hash(p.Doc)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(p.Diff)
	return fmt.Sprintf("policy/%d/%s/%s", p.Doc.Version, h, hex.EncodeToString(d[:])), nil
}

// Root is the unsigned root the owner's passkey signs for p: the page hands
// key.Challenge(key.RootMsg(root)) to WebAuthn get() and the assertion comes
// back to Verify.
func (p Proposal) Root(owner key.PublicKey) (key.Root, error) {
	s, err := p.Serial()
	if err != nil {
		return key.Root{}, err
	}
	return key.PrepareRoot(owner, key.Root{Clerk: Clerk, Serial: s}), nil
}

// Verify checks that sig is the enrolled owner's passkey assertion over the
// root for next, and that next's version is above floor, the highest
// version already signed or pending. It returns the version's key. The
// owner must be an ES256 credential: its RP ID is the enforcer's own name,
// and key.PublicKey.Verify checks the assertion's challenge, RP ID, origin,
// user presence and verification and its one canonical encoding (STO-4,
// NET-4). It does not classify the change: Engine does.
func Verify(owner key.PublicKey, floor uint64, next Proposal, sig []byte) (key.Key, error) {
	if owner.Alg() != key.AlgES256 {
		return key.Key{}, ErrNotOwner
	}
	if next.Doc.Version <= floor {
		return key.Key{}, fmt.Errorf("%w: %d after %d", ErrNotRising, next.Doc.Version, floor)
	}
	r, err := next.Root(owner)
	if err != nil {
		return key.Key{}, err
	}
	if !owner.Verify(key.RootMsg(r), sig) {
		return key.Key{}, ErrBadSig
	}
	return key.AttachRoot(r, sig), nil
}

// Check re-verifies a stored version: k is owner's signature over the root
// for p, and nothing else. A restart runs it on every stored version.
func Check(owner key.PublicKey, k key.Key, p Proposal) error {
	r, err := p.Root(owner)
	if err != nil {
		return err
	}
	if k.Root.Owner != owner || len(k.Links) != 0 || k.Root.Clerk != Clerk || len(k.Root.Verbs) != 0 {
		return ErrNotOwner
	}
	if k.Root.Serial != r.Serial {
		return ErrUnbound
	}
	if owner.Alg() != key.AlgES256 || !owner.Verify(key.RootMsg(r), k.Root.Sig) {
		return ErrBadSig
	}
	return nil
}
