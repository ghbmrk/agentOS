package handoff

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"strings"
)

// A recovery-key rotation's approval (REC-4, BAK-1, MIG-4-recovery-r1,
// D-201). The kernel checks the anchor's tap, then signs an Approval with
// its head key; the root steps that open the sealed store (the keeper's
// one-shot, the unlock step) verify it with the store's head key, so no
// anchor list lives outside the kernel. It binds the recipient the store
// holds now, so once the store's recipient changes it verifies as stale:
// single use by construction.

// The routes, as the kernel logs them (kernel.RouteCard, kernel.RouteLost).
const (
	RouteCard = "a" // on the running box, with a factor from the Owner Card
	RouteLost = "b" // the whole card is lost: the unlock step makes the key at boot
)

// How long an approval verifies, in milliseconds: a quarter hour on the
// card route, and a week on the lost-card route, which waits on a restart
// and reads the boot clock before time sync.
const (
	CardApprovalFor = 15 * 60 * 1000
	LostApprovalFor = 7 * 24 * 60 * 60 * 1000
)

const approvalTag = "agentos-recovery-rotate/v1\n"

// approvalV is the body's version, after the tag.
const approvalV = 1

// recipientIDLen is a backup.Recipient ID's length: 16 bytes, lowercase hex.
const recipientIDLen = 32

// MaxApproval bounds an approval: the tag, the version and route bytes, two
// length-prefixed recipient IDs, the expiry and the head key's signature.
const MaxApproval = len(approvalTag) + 2 + 2*(1+recipientIDLen) + 8 + ed25519.SignatureSize

var (
	// ErrApproval: the bytes are not an approval the head key signed, or
	// one out of shape.
	ErrApproval = errors.New("handoff: not a recovery-key approval from my kernel")
	// ErrApprovalExpired: the approval verifies but its time is over.
	ErrApprovalExpired = errors.New("handoff: the recovery-key approval has expired; ask again")
)

// Approval is what the kernel approves: rotating the backup recipient Old
// ("" when the store holds none) to Next ("" on RouteLost, whose key does
// not exist yet), until Expires, in milliseconds since the epoch.
type Approval struct {
	Route   string
	Old     string
	Next    string
	Expires int64
}

func (a Approval) valid() bool {
	id := func(s string) bool {
		return s == "" || len(s) == recipientIDLen && strings.Trim(s, "0123456789abcdef") == ""
	}
	if !id(a.Old) || !id(a.Next) {
		return false
	}
	switch a.Route {
	case RouteCard:
		return a.Next != "" && a.Next != a.Old
	case RouteLost:
		return a.Next == ""
	}
	return false
}

func (a Approval) body() []byte {
	b := append([]byte(approvalTag), approvalV, a.Route[0])
	for _, s := range []string{a.Old, a.Next} {
		b = append(append(b, byte(len(s))), s...)
	}
	return binary.BigEndian.AppendUint64(b, uint64(a.Expires))
}

// SignApproval is a signed with head, the kernel's head key.
func SignApproval(head ed25519.PrivateKey, a Approval) ([]byte, error) {
	if !a.valid() || len(head) != ed25519.PrivateKeySize {
		return nil, ErrApproval
	}
	b := a.body()
	return append(b, ed25519.Sign(head, b)...), nil
}

// VerifyApproval reads b, checks head's signature over it, and refuses one
// whose Expires is not after now. The caller checks the route and that Old
// is the recipient it holds.
func VerifyApproval(head ed25519.PublicKey, b []byte, now int64) (Approval, error) {
	if len(head) != ed25519.PublicKeySize || len(b) > MaxApproval || len(b) < ed25519.SignatureSize {
		return Approval{}, ErrApproval
	}
	msg, sig := b[:len(b)-ed25519.SignatureSize], b[len(b)-ed25519.SignatureSize:]
	r, ok := bytes.CutPrefix(msg, []byte(approvalTag))
	if !ok || len(r) < 2 || r[0] != approvalV {
		return Approval{}, ErrApproval
	}
	a := Approval{Route: string(r[1:2])}
	r = r[2:]
	for _, s := range []*string{&a.Old, &a.Next} {
		if len(r) < 1 || len(r) < 1+int(r[0]) {
			return Approval{}, ErrApproval
		}
		*s, r = string(r[1:1+int(r[0])]), r[1+int(r[0]):]
	}
	if len(r) != 8 {
		return Approval{}, ErrApproval
	}
	a.Expires = int64(binary.BigEndian.Uint64(r))
	if !a.valid() || !ed25519.Verify(head, msg, sig) {
		return Approval{}, ErrApproval
	}
	if now >= a.Expires {
		return Approval{}, ErrApprovalExpired
	}
	return a, nil
}
