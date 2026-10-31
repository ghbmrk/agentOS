package kernel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Recovery-key rotation (REC-4, BAK-1, MIG-4-recovery-r1, D-201). The
// kernel is the only checker of the owner's hardware keys, so a rotation
// starts here: an anchor signs RecoveryRotateHash(old, next), the kernel
// logs it and its process signs an approval with the head key, which the
// root steps that hold the store verify. The kernel holds no recipient
// itself (its process does); old is what the process holds now.

// TRecoveryRotate logs an anchor's approval of a recovery-key rotation.
const TRecoveryRotate = "recovery.rotate"

// The two routes of a rotation (D-201): RouteCard, on the running box with
// a factor from the Owner Card, names the new key's recipient; RouteLost,
// when the whole card is lost, names none, since the key is made at the
// next boot.
const (
	RouteCard = "a"
	RouteLost = "b"
)

// DomainRecoveryRotate starts the message an anchor signs for a rotation.
const DomainRecoveryRotate = "agentos.recovery.rotate.v1\x00"

// ErrRotateSig refuses a rotation no hardware key signed over
// RecoveryRotateHash(old, next).
var ErrRotateSig = errors.New("kernel: changing the recovery key needs your hardware key's signature")

// ErrRotate refuses a rotation out of shape: an ID that is not a recipient
// ID, or a new recipient equal to the old.
var ErrRotate = errors.New("kernel: not a recovery-key change I can approve")

type recoveryRotate struct {
	Route  string     `json:"route"`
	Old    string     `json:"old"`
	Next   string     `json:"next"`
	Cosign key.Cosign `json:"cosign"`
}

// RecoveryRotateHash names rotating the backup recipient old (its
// backup.Recipient ID, "" when there is none) to next ("" on RouteLost), so
// a signature over one rotation never replays as another, nor after it.
func RecoveryRotateHash(old, next string) [32]byte {
	m := []byte(DomainRecoveryRotate)
	for _, s := range []string{old, next} {
		m = append(binary.BigEndian.AppendUint16(m, uint16(len(s))), s...)
	}
	return sha256.Sum256(m)
}

// RecipientID reports whether s is a backup recipient's ID as
// backup.Recipient.ID gives it: 16 bytes, lowercase hex.
func RecipientID(s string) bool {
	return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == ""
}

// rotateOK is the check a rotation passes, live and on replay.
func (s *State) rotateOK(b recoveryRotate) error {
	want := RouteCard
	if b.Next == "" {
		want = RouteLost
	}
	if b.Old != "" && !RecipientID(b.Old) || b.Next != "" && (!RecipientID(b.Next) || b.Next == b.Old) || b.Route != want {
		return ErrRotate
	}
	if !key.In(s.Anchors, b.Cosign.By) || !b.Cosign.Over(RecoveryRotateHash(b.Old, b.Next)) {
		return ErrRotateSig
	}
	return nil
}

// applyRotate folds a rotation: it changes no state, since the sealed store
// is the recipient's record and the approval is what the root steps check,
// so one written past the kernel grants nothing. Its body must still decode.
func (s *State) applyRotate(e Entry) error {
	_, err := body[recoveryRotate](e)
	return err
}

// RecoveryRotate logs an anchor's signature c over RecoveryRotateHash(old,
// next): next is the new recovery key's recipient ID on RouteCard, "" on
// RouteLost. A phone passkey's, a missing or another change's signature is
// ErrRotateSig and logs nothing. It is a widening, so it anchors, and a
// failed anchor is returned: the caller then signs no approval.
func (k *Kernel) RecoveryRotate(now int64, old, next string, c key.Cosign) error {
	b := recoveryRotate{Route: RouteCard, Old: old, Next: next, Cosign: c}
	if next == "" {
		b.Route = RouteLost
	}
	if err := k.s.rotateOK(b); err != nil {
		return err
	}
	return k.owner(now, TRecoveryRotate, b)
}

// DomainRecoveryCard starts the message an anchor signs to see the
// lost-card route's new card (MIG-4-recovery-r4c, #4128).
const DomainRecoveryCard = "agentos.recovery.card.v1\x00"

// RecoveryCardHash names showing the new card whose backup recipient ID is
// id, so a tap to see one card never shows another.
func RecoveryCardHash(id string) [32]byte {
	return sha256.Sum256(append([]byte(DomainRecoveryCard), id...))
}

// RecoveryCardTap is nil when c is an anchor's signature over
// RecoveryCardHash(id), and ErrRotateSig otherwise: the new card holds the
// only recovery key that opens the store until the owner confirms it, so
// only a hardware key's tap shows it, never a phone passkey's. A read, it
// logs nothing.
func (k *Kernel) RecoveryCardTap(id string, c key.Cosign) error {
	if !RecipientID(id) || !key.In(k.s.Anchors, c.By) || !c.Over(RecoveryCardHash(id)) {
		return ErrRotateSig
	}
	return nil
}
