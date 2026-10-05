package tpmseal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Re-encryption away from the PC (V7, review of #45, B5 and the
// arbitrator's ruling). When the vault moves to a new data key and a new
// policy key, every other trusted PC needs a slot sealed under the new
// policy key, without the PC being present. The vault recorded each PC's
// storage root key public area when it was trusted (Sealed.SRKPublic), so
// the vault process builds the sealed object itself and wraps it for that
// SRK as a TPM duplication blob (go-tpm's CreateDuplicate, outer wrapper
// only); the PC imports it on its next unseal. This is the pattern of
// systemd-cryptenroll --tpm2-device-key. The object's policy is the same
// PolicyAuthorize by the (new) policy key as Seal's, so the PC's signed
// boot policies apply unchanged once re-signed (Resign).
//
// An imported object cannot be fixedTPM or fixedParent (the TPM requires
// both clear for TPM2_Import). Duplicating it again needs a policy
// session the policy key authorizes, so only a holder of the new policy
// key, which lives in the vault, could move it.

// SealTo seals secret to the PC whose SRK public area (TPM2B) is
// srkPublic, under policy key pub, without that PC. It cannot add a boot
// PIN: the PIN is the PC owner's to type.
func SealTo(srkPublic []byte, secret []byte, pub *ecdsa.PublicKey, host string) (*Sealed, error) {
	if len(secret) == 0 || len(secret) > 128 {
		return nil, errors.New("tpmseal: secret must be 1 to 128 bytes")
	}
	sp, err := tpm2.Unmarshal[tpm2.TPM2BPublic](srkPublic)
	if err != nil {
		return nil, ErrSRK
	}
	srkPub, err := sp.Contents()
	if err != nil || !srkShape(srkPub) {
		return nil, ErrSRK
	}
	srkName, err := tpm2.ObjectName(srkPub)
	if err != nil {
		return nil, ErrSRK
	}
	ek, err := tpm2.ImportEncapsulationKey(srkPub)
	if err != nil {
		return nil, err
	}
	kp, err := eccPublic(pub)
	if err != nil {
		return nil, err
	}
	keyName, err := tpm2.ObjectName(&kp)
	if err != nil {
		return nil, err
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pol, err := objectPolicy(*keyName, false)
	if err != nil {
		return nil, err
	}
	obfuscate := make([]byte, sha256.Size)
	if _, err := rand.Read(obfuscate); err != nil {
		return nil, err
	}
	unique := sha256.Sum256(append(append([]byte(nil), obfuscate...), secret...))
	objPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			// Policy only: no plain auth-value path to Unseal.
			UserWithAuth: false,
			NoDA:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: pol},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: unique[:]}),
	}
	name, err := tpm2.ObjectName(&objPub)
	if err != nil {
		return nil, err
	}
	sens := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue:     tpm2.TPM2BDigest{Buffer: obfuscate},
		Sensitive:     tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BSensitiveData{Buffer: secret}),
	})
	defer wipeBytes(sens)
	dup, seed, err := tpm2.CreateDuplicate(rand.Reader, ek, name.Buffer, sens)
	if err != nil {
		return nil, err
	}
	return &Sealed{
		SRKName:   append([]byte(nil), srkName.Buffer...),
		Public:    tpm2.Marshal(tpm2.New2B(objPub)),
		Private:   tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: dup}),
		PolicyKey: pkix,
		Host:      host,
		SRKPublic: append([]byte(nil), srkPublic...),
		Seed:      seed,
	}, nil
}

// Resign approves p's boot path again under key, for a policy key that
// replaces the one p was signed with.
func Resign(key *ecdsa.PrivateKey, p Policy) (Policy, error) {
	pcrs, err := normPCRs(p.PCRs)
	if err != nil {
		return Policy{}, err
	}
	ap, err := approved(pcrs, p.Digest)
	if err != nil {
		return Policy{}, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, aHash(ap))
	if err != nil {
		return Policy{}, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Policy{PCRs: pcrs, Digest: append([]byte(nil), p.Digest...), Signature: sig}, nil
}

// SignedBy reports whether key signed p.
func SignedBy(p Policy, key *ecdsa.PublicKey) bool { return signedBy(&p, key) }

func signedBy(p *Policy, key *ecdsa.PublicKey) bool {
	if key == nil || len(p.Signature) != 64 {
		return false
	}
	pcrs, err := normPCRs(p.PCRs)
	if err != nil {
		return false
	}
	ap, err := approved(pcrs, p.Digest)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(p.Signature[:32])
	s := new(big.Int).SetBytes(p.Signature[32:])
	return ecdsa.Verify(key, aHash(ap), r, s)
}

// SameSRK reports whether srkPublic is the SRK named srkName.
func SameSRK(srkPublic, srkName []byte) bool {
	sp, err := tpm2.Unmarshal[tpm2.TPM2BPublic](srkPublic)
	if err != nil {
		return false
	}
	pub, err := sp.Contents()
	if err != nil {
		return false
	}
	n, err := tpm2.ObjectName(pub)
	return err == nil && bytes.Equal(n.Buffer, srkName)
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
