package key

// DomainCosign signs a passkey's approval of a big change: a big grant, a
// very large one-off or a raised line (D-146).
const DomainCosign = "agentos.key.cosign.v1\x00"

// Cosign is a passkey's approval of the change whose hash it signs.
type Cosign struct {
	By  PublicKey `json:"by"`
	Sig []byte    `json:"sig"`
}

// CosignMsg is the message a passkey signs to approve the change named what.
func CosignMsg(what [32]byte) []byte { return append([]byte(DomainCosign), what[:]...) }

// Approve is passkey's co-signature over the change named what.
func Approve(passkey Signer, what [32]byte) Cosign {
	return Cosign{By: passkey.Public(), Sig: passkey.Sign(CosignMsg(what))}
}

// Approved reports whether two distinct passkeys of owners, one of them an
// anchor, stand behind the change named what: each co-signature over what
// that verifies, and signers, passkeys whose own signature already binds that
// exact change, such as a one-off's use.
func Approved(owners, anchors []PublicKey, what [32]byte, signers []PublicKey, cos []Cosign) bool {
	var by []PublicKey
	add := func(pk PublicKey) {
		if In(owners, pk) && !In(by, pk) {
			by = append(by, pk)
		}
	}
	for _, pk := range signers {
		add(pk)
	}
	for _, c := range cos {
		if c.Over(what) {
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
// k, or the zero PublicKey.
func UseSigner(k Key, owners []PublicKey, use, sig []byte) PublicKey {
	if len(k.Links) > 0 {
		return PublicKey{}
	}
	return whoSigned(owners, useMsg(k.Tip(), use), sig)
}

func whoSigned(owners []PublicKey, msg, sig []byte) PublicKey {
	for _, p := range owners {
		if p.Verify(msg, sig) {
			return p
		}
	}
	return PublicKey{}
}

// Over reports whether c is a verifying co-signature over the change named what.
func (c Cosign) Over(what [32]byte) bool { return c.By.Verify(CosignMsg(what), c.Sig) }
