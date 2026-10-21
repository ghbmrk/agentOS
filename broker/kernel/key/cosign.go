package key

import (
	"crypto/ed25519"
)

// DomainCosign signs a passkey's approval of a big change: a big grant, a
// very large one-off or a raised line (D-146).
const DomainCosign = "agentos.key.cosign.v1\x00"

// Cosign is a passkey's approval of the change whose hash it signs.
type Cosign struct {
	By  ed25519.PublicKey `json:"by"`
	Sig []byte            `json:"sig"`
}

func cosignMsg(what [32]byte) []byte { return append([]byte(DomainCosign), what[:]...) }

// Approve is passkey's co-signature over the change named what.
func Approve(passkey ed25519.PrivateKey, what [32]byte) Cosign {
	return Cosign{By: passkey.Public().(ed25519.PublicKey), Sig: ed25519.Sign(passkey, cosignMsg(what))}
}

// Approved reports whether two distinct passkeys of owners, one of them an
// anchor, stand behind the change named what: each co-signature over what
// that verifies, and signers, passkeys whose own signature already binds that
// exact change, such as a one-off's use.
func Approved(owners, anchors []ed25519.PublicKey, what [32]byte, signers []ed25519.PublicKey, cos []Cosign) bool {
	var by []ed25519.PublicKey
	add := func(pk ed25519.PublicKey) {
		if In(owners, pk) && !In(by, pk) {
			by = append(by, pk)
		}
	}
	for _, pk := range signers {
		add(pk)
	}
	for _, c := range cos {
		if len(c.By) == ed25519.PublicKeySize && ed25519.Verify(c.By, cosignMsg(what), c.Sig) {
			add(c.By)
		}
	}
	anchored := false
	for _, pk := range by {
		anchored = anchored || In(anchors, pk)
	}
	return len(by) >= 2 && anchored
}

// UseSigner is the passkey of owners that signed use under the bare root
// k, or nil.
func UseSigner(k Key, owners []ed25519.PublicKey, use, sig []byte) ed25519.PublicKey {
	if len(k.Links) > 0 {
		return nil
	}
	return whoSigned(owners, useMsg(k.Tip(), use), sig)
}

func whoSigned(owners []ed25519.PublicKey, msg, sig []byte) ed25519.PublicKey {
	for _, p := range owners {
		if len(p) == ed25519.PublicKeySize && ed25519.Verify(p, msg, sig) {
			return p
		}
	}
	return nil
}
