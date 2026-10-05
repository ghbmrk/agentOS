// Package tpmseal seals a vault key-encryption key to this PC's TPM under a
// signed PCR policy: the trusted-host slot of CRED-8, whose policy seal is
// what HW-5a rests the integrity of AgentOS's boot files on.
//
// The sealed object's policy is PolicyAuthorize by the box's own policy key
// (an ECDSA P-256 key whose private half lives only inside the vault), plus
// PolicyAuthValue when the owner added a boot PIN. It names no PCR values
// itself. Each Policy is one boot path the box approved: a PCR selection,
// the composite digest of those PCRs, and the box key's signature over the
// resulting PolicyPCR digest. Unseal reads the PCRs, picks the policy that
// matches them, and lets the TPM check both the PCRs and the signature, so
// a modified boot path matches no policy, and a policy signed by any other
// key fails PolicyAuthorize. An update adds a policy for the new boot path
// (Sign) without touching the sealed object, so an A/B update does not lock
// the vault.
//
// Every TPM session that carries the secret is salted to the storage root
// key and encrypts the secret on the bus. The SRK's name is recorded at
// seal time and checked before any later use, so an interposer on a
// discrete TPM's bus cannot substitute its own salt key.
package tpmseal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// PolicyRef qualifies every signed policy, so a signature the policy key
// made for another purpose authorizes nothing here.
var PolicyRef = []byte("agentos-vault-pcr-policy/v1")

// MaxPCRs bounds a policy's selection: one PCR_Read returns at most eight
// digests.
const MaxPCRs = 8

// Errors callers act on. They carry no secret material.
var (
	// ErrOtherTPM: the sealed object belongs to another PC's TPM.
	ErrOtherTPM = errors.New("tpmseal: sealed to another TPM")
	// ErrNoPolicy: no approved policy matches the PCRs now, so this boot
	// path is not one the box signed (modified, or updated without a
	// policy for the new release).
	ErrNoPolicy = errors.New("tpmseal: no signed policy matches this boot path")
	// ErrPolicy: the TPM refused the policy (PCRs or signature).
	ErrPolicy = errors.New("tpmseal: the TPM refused the policy")
	// ErrPIN: the boot PIN is wrong. The TPM counts it toward its
	// dictionary-attack lockout.
	ErrPIN = errors.New("tpmseal: wrong boot PIN")
	// ErrLockout: the TPM is in dictionary-attack lockout.
	ErrLockout = errors.New("tpmseal: the TPM is locked out after wrong PINs")
	// ErrNeedPIN: the object was sealed with a PIN and none was given.
	ErrNeedPIN = errors.New("tpmseal: this slot needs the boot PIN")
	// ErrUnmeasured: a selected PCR was never extended (all zeros or all
	// ones), so it measures nothing; a policy over it would accept any
	// boot path.
	ErrUnmeasured = errors.New("tpmseal: a selected PCR measures nothing on this boot path")
)

// Sealed is the opaque part of a trusted-host slot. Nothing in it is
// secret: the private area is encrypted by the TPM's storage key.
type Sealed struct {
	// SRKName is the name of this TPM's storage root key, derived from
	// the TPM's owner seed: the PC's identity.
	SRKName []byte `json:"srk_name"`
	// Public and Private are the sealed object's TPM2B areas.
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
	// PolicyKey is the box's policy key (PKIX), committed to by the
	// object's policy digest.
	PolicyKey []byte `json:"policy_key"`
	// PINSalt is set when the owner added a boot PIN.
	PINSalt []byte `json:"pin_salt,omitempty"`
	// Host names the PC for the owner (its DMI product name), if known.
	Host string `json:"host,omitempty"`
}

// HasPIN reports whether unsealing needs the boot PIN.
func (s *Sealed) HasPIN() bool { return len(s.PINSalt) > 0 }

// Policy is one approved boot path.
type Policy struct {
	// PCRs are SHA-256 bank indices, ascending.
	PCRs []uint `json:"pcrs"`
	// Digest is SHA-256 over the selected PCR values in index order.
	Digest []byte `json:"digest"`
	// Signature is the policy key's ECDSA signature, r||s, over
	// SHA-256(approved PolicyPCR digest || PolicyRef).
	Signature []byte `json:"signature"`
}

// NewPolicyKey makes a box policy key. Its private half belongs in the
// vault (HW-5a: never readable from the drive alone, never a project key).
func NewPolicyKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalPolicyKey and ParsePolicyKey store the key as PKCS #8.
func MarshalPolicyKey(k *ecdsa.PrivateKey) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k) }

func ParsePolicyKey(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("tpmseal: policy key is not ECDSA P-256")
	}
	return ek, nil
}

// normPCRs sorts and checks a selection.
func normPCRs(pcrs []uint) ([]uint, error) {
	if len(pcrs) == 0 || len(pcrs) > MaxPCRs {
		return nil, fmt.Errorf("tpmseal: select 1 to %d PCRs", MaxPCRs)
	}
	out := append([]uint(nil), pcrs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	for i, p := range out {
		if p > 23 || (i > 0 && out[i-1] == p) {
			return nil, fmt.Errorf("tpmseal: bad PCR selection %v", pcrs)
		}
	}
	return out, nil
}

func selection(pcrs []uint) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
	}}}
}

// composite is the PolicyPCR digest of values, which are in index order.
func composite(values [][]byte) []byte {
	h := sha256.New()
	for _, v := range values {
		h.Write(v)
	}
	return h.Sum(nil)
}

// approved is the PolicyPCR policy digest that a signature approves.
func approved(pcrs []uint, digest []byte) ([]byte, error) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if err := (tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: digest}, Pcrs: selection(pcrs)}).Update(calc); err != nil {
		return nil, err
	}
	return calc.Hash().Digest, nil
}

func aHash(approvedDigest []byte) []byte {
	h := sha256.New()
	h.Write(approvedDigest)
	h.Write(PolicyRef)
	return h.Sum(nil)
}

// measured reports whether a PCR value records anything: a PCR never
// extended reads all zeros (or all ones for the locality-reset PCRs).
func measured(v []byte) bool {
	z, f := true, true
	for _, b := range v {
		z = z && b == 0
		f = f && b == 0xff
	}
	return len(v) == sha256.Size && !z && !f
}

// Sign approves the boot path whose selected PCRs read values (index
// order). It refuses an unmeasured PCR (ErrUnmeasured). It needs no TPM:
// the updater computes values for a new release and the box signs them.
func Sign(key *ecdsa.PrivateKey, pcrs []uint, values [][]byte) (Policy, error) {
	pcrs, err := normPCRs(pcrs)
	if err != nil {
		return Policy{}, err
	}
	if len(values) != len(pcrs) {
		return Policy{}, errors.New("tpmseal: one value per PCR")
	}
	for _, v := range values {
		if !measured(v) {
			return Policy{}, ErrUnmeasured
		}
	}
	d := composite(values)
	ap, err := approved(pcrs, d)
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
	return Policy{PCRs: pcrs, Digest: d, Signature: sig}, nil
}

// ReadPCRs returns the SHA-256 bank values of pcrs, in index order.
func ReadPCRs(t transport.TPM, pcrs []uint) ([][]byte, error) {
	pcrs, err := normPCRs(pcrs)
	if err != nil {
		return nil, err
	}
	rsp, err := tpm2.PCRRead{PCRSelectionIn: selection(pcrs)}.Execute(t)
	if err != nil {
		return nil, err
	}
	if len(rsp.PCRValues.Digests) != len(pcrs) {
		return nil, errors.New("tpmseal: the TPM has no SHA-256 bank for these PCRs")
	}
	out := make([][]byte, len(pcrs))
	for i, d := range rsp.PCRValues.Digests {
		out[i] = append([]byte(nil), d.Buffer...)
	}
	return out, nil
}

// SignCurrent approves the boot path this PC is running now.
func SignCurrent(t transport.TPM, key *ecdsa.PrivateKey, pcrs []uint) (Policy, error) {
	vals, err := ReadPCRs(t, pcrs)
	if err != nil {
		return Policy{}, err
	}
	return Sign(key, pcrs, vals)
}

func eccPublic(pub *ecdsa.PublicKey) (tpm2.TPMTPublic, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return tpm2.TPMTPublic{}, errors.New("tpmseal: policy key is not ECDSA P-256")
	}
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			NoDA:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID:   tpm2.TPMECCNistP256,
			KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: y},
		}),
	}, nil
}

// objectPolicy is the sealed object's policy digest.
func objectPolicy(keyName tpm2.TPM2BName, pin bool) ([]byte, error) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if err := (tpm2.PolicyAuthorize{PolicyRef: tpm2.TPM2BDigest{Buffer: PolicyRef}, KeySign: keyName}).Update(calc); err != nil {
		return nil, err
	}
	if pin {
		if err := (tpm2.PolicyAuthValue{}).Update(calc); err != nil {
			return nil, err
		}
	}
	return calc.Hash().Digest, nil
}

// pinAuth turns the PIN into the object's auth value. The TPM, not this
// derivation, rate-limits guesses (dictionary-attack lockout). It is 128
// bits as 32 hex characters, so it holds no zero byte: go-tpm v0.9.8's
// session HMAC key cuts an auth value at its first zero byte where the
// TPM drops only trailing ones (hmacKeyFromAuthValue), which failed about
// one right PIN in eight.
func pinAuth(salt []byte, pin string) []byte {
	h := sha256.New()
	h.Write([]byte("agentos-boot-pin/v1\x00"))
	h.Write(salt)
	h.Write([]byte(pin))
	return []byte(hex.EncodeToString(h.Sum(nil)[:16]))
}

type srk struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    tpm2.TPMTPublic
}

// ErrSRK: the storage root key's public area does not match its name or
// the template, as when something on the bus substitutes its own key.
var ErrSRK = errors.New("tpmseal: the storage root key's public area does not match its name")

// loadSRK recreates the storage root key from the owner seed (TCG ECC
// P-256 template), so the same TPM always yields the same key and name.
// The public area is the salt key for every later session, so it must
// hash to the name the TPM returned and keep the template's attributes;
// callers then compare that name with the one a slot recorded.
func loadSRK(t transport.TPM) (*srk, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: storage root key: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		flush(t, rsp.ObjectHandle)
		return nil, err
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil || !bytes.Equal(name.Buffer, rsp.Name.Buffer) || !srkShape(pub) {
		flush(t, rsp.ObjectHandle)
		return nil, ErrSRK
	}
	return &srk{handle: rsp.ObjectHandle, name: rsp.Name, pub: *pub}, nil
}

// srkShape reports whether pub is the template's kind of key: a restricted
// P-256 decryption key, fixed to this TPM, with no policy.
func srkShape(pub *tpm2.TPMTPublic) bool {
	want := tpm2.ECCSRKTemplate
	if pub.Type != want.Type || pub.NameAlg != want.NameAlg ||
		pub.ObjectAttributes != want.ObjectAttributes || len(pub.AuthPolicy.Buffer) != 0 {
		return false
	}
	p, err := pub.Parameters.ECCDetail()
	if err != nil {
		return false
	}
	return p.CurveID == tpm2.TPMECCNistP256
}

func flush(t transport.TPM, h tpm2.TPMHandle) {
	tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

// Identity returns this TPM's SRK name: the value Sealed.SRKName holds for
// a slot sealed here.
func Identity(t transport.TPM) ([]byte, error) {
	s, err := loadSRK(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, s.handle)
	return append([]byte(nil), s.name.Buffer...), nil
}

// Seal seals secret (at most 128 bytes) to this TPM under the box policy
// key pub, with a boot PIN when pin is not empty.
func Seal(t transport.TPM, secret []byte, pub *ecdsa.PublicKey, pin, host string) (*Sealed, error) {
	if len(secret) == 0 || len(secret) > 128 {
		return nil, errors.New("tpmseal: secret must be 1 to 128 bytes")
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
	var salt, auth []byte
	if pin != "" {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		auth = pinAuth(salt, pin)
	}
	pol, err := objectPolicy(*keyName, pin != "")
	if err != nil {
		return nil, err
	}
	s, err := loadSRK(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, s.handle)
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: s.handle,
			Name:   s.name,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Salted(s.handle, s.pub)),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{Buffer: auth},
			Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:    true,
				FixedParent: true,
				// Policy only: no plain auth-value path to Unseal.
				UserWithAuth: false,
				// A PIN is guarded by the TPM's lockout; without
				// one there is nothing to guess.
				NoDA: pin == "",
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: pol},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
		}),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: seal: %w", err)
	}
	return &Sealed{
		SRKName:   append([]byte(nil), s.name.Buffer...),
		Public:    tpm2.Marshal(rsp.OutPublic),
		Private:   tpm2.Marshal(rsp.OutPrivate),
		PolicyKey: pkix,
		PINSalt:   salt,
		Host:      host,
	}, nil
}

// PolicyPublicKey returns the policy key the object was sealed under.
func (s *Sealed) PolicyPublicKey() (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(s.PolicyKey)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("tpmseal: policy key is not ECDSA")
	}
	return ek, nil
}

// match picks the first policy whose PCRs read their digest now.
func match(t transport.TPM, policies []Policy) (*Policy, error) {
	for i := range policies {
		p := &policies[i]
		pcrs, err := normPCRs(p.PCRs)
		if err != nil || len(p.Signature) != 64 {
			continue
		}
		vals, err := ReadPCRs(t, pcrs)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(composite(vals), p.Digest) {
			return p, nil
		}
	}
	return nil, ErrNoPolicy
}

// Unseal returns the secret if this is the TPM it was sealed to, the
// running boot path matches one of policies, and pin is right when the
// slot has one.
func Unseal(t transport.TPM, sealed *Sealed, policies []Policy, pin string) ([]byte, error) {
	if sealed.HasPIN() && pin == "" {
		return nil, ErrNeedPIN
	}
	pub, err := sealed.PolicyPublicKey()
	if err != nil {
		return nil, err
	}
	kp, err := eccPublic(pub)
	if err != nil {
		return nil, err
	}
	s, err := loadSRK(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, s.handle)
	if !bytes.Equal(s.name.Buffer, sealed.SRKName) {
		return nil, ErrOtherTPM
	}
	p, err := match(t, policies)
	if err != nil {
		return nil, err
	}

	objPub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](sealed.Public)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: sealed public area: %w", err)
	}
	objPriv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](sealed.Private)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: sealed private area: %w", err)
	}
	// The object must be the one this slot describes: policy-only, under
	// this policy key, with or without PIN as recorded.
	op, err := objPub.Contents()
	if err != nil {
		return nil, err
	}
	keyName, err := tpm2.ObjectName(&kp)
	if err != nil {
		return nil, err
	}
	want, err := objectPolicy(*keyName, sealed.HasPIN())
	if err != nil {
		return nil, err
	}
	if op.ObjectAttributes.UserWithAuth || !bytes.Equal(op.AuthPolicy.Buffer, want) {
		return nil, ErrPolicy
	}

	obj, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: s.handle, Name: s.name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    *objPriv,
		InPublic:     *objPub,
	}.Execute(t)
	if err != nil {
		return nil, ErrOtherTPM
	}
	defer flush(t, obj.ObjectHandle)

	ext, err := tpm2.LoadExternal{
		InPublic:  tpm2.New2B(kp),
		Hierarchy: tpm2.TPMRHOwner,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: policy key: %w", err)
	}
	defer flush(t, ext.ObjectHandle)
	if !bytes.Equal(ext.Name.Buffer, keyName.Buffer) {
		return nil, ErrPolicy
	}

	ap, err := approved(p.PCRs, p.Digest)
	if err != nil {
		return nil, err
	}
	ver, err := tpm2.VerifySignature{
		KeyHandle: ext.ObjectHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: aHash(ap)},
		Signature: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash:       tpm2.TPMAlgSHA256,
				SignatureR: tpm2.TPM2BECCParameter{Buffer: p.Signature[:32]},
				SignatureS: tpm2.TPM2BECCParameter{Buffer: p.Signature[32:]},
			}),
		},
	}.Execute(t)
	if err != nil {
		return nil, ErrPolicy
	}

	var opts []tpm2.AuthOption
	opts = append(opts, tpm2.Salted(s.handle, s.pub), tpm2.AESEncryption(128, tpm2.EncryptOut))
	if sealed.HasPIN() {
		opts = append(opts, tpm2.Auth(pinAuth(sealed.PINSalt, pin)))
	}
	sess, closeSess, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, opts...)
	if err != nil {
		return nil, fmt.Errorf("tpmseal: policy session: %w", err)
	}
	defer closeSess()
	if _, err := (tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: p.Digest},
		Pcrs:          selection(p.PCRs),
	}).Execute(t); err != nil {
		return nil, ErrPolicy
	}
	if _, err := (tpm2.PolicyAuthorize{
		PolicySession:  sess.Handle(),
		ApprovedPolicy: tpm2.TPM2BDigest{Buffer: ap},
		PolicyRef:      tpm2.TPM2BDigest{Buffer: PolicyRef},
		KeySign:        *keyName,
		CheckTicket:    ver.Validation,
	}).Execute(t); err != nil {
		return nil, ErrPolicy
	}
	if sealed.HasPIN() {
		if _, err := (tpm2.PolicyAuthValue{PolicySession: sess.Handle()}).Execute(t); err != nil {
			return nil, ErrPolicy
		}
	}
	out, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: obj.ObjectHandle,
		Name:   obj.Name,
		Auth:   sess,
	}}.Execute(t)
	if err != nil {
		return nil, unsealErr(err)
	}
	return out.OutData.Buffer, nil
}

// unsealErr maps the TPM's answer to Unseal.
func unsealErr(err error) error {
	switch {
	case errors.Is(err, tpm2.TPMRCLockout):
		return ErrLockout
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return ErrPIN
	}
	return ErrPolicy
}

// Dictionary-attack parameters a PIN slot sets when it takes the lockout
// hierarchy. Ten wrong PINs lock the PIN out; the TPM then forgives one
// failure every two hours, so a thief gets about twelve guesses a day. A
// wrong lockout authorization locks the lockout hierarchy for a day.
const (
	PINMaxTries        = 10
	PINRecoverySeconds = 2 * 60 * 60
	LockoutRecoverySec = 24 * 60 * 60
)

// ErrLockoutOwned: something other than this box set the TPM's lockout
// authorization, so the box cannot vouch for the PIN's guess limit.
var ErrLockoutOwned = errors.New("tpmseal: the TPM's lockout authorization is held by someone else")

// NewLockoutAuth makes a lockout authorization: 128 random bits as 32 hex
// characters (no zero byte; see pinAuth).
func NewLockoutAuth() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(b)), nil
}

// lockoutAuthSet reads TPMA_PERMANENT.lockoutAuthSet.
func lockoutAuthSet(t transport.TPM) (bool, error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTPermanent),
		PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return false, err
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil || len(props.TPMProperty) == 0 || props.TPMProperty[0].Property != tpm2.TPMPTPermanent {
		return false, errors.New("tpmseal: cannot read the TPM's permanent attributes")
	}
	return props.TPMProperty[0].Value&(1<<2) != 0, nil
}

// TakeLockout makes the TPM's lockout hierarchy the box's, so that only
// the vault can reset the dictionary-attack counter that limits PIN
// guesses. With the lockout authorization empty, as a TPM leaves the
// factory, anyone holding the PC could reset the counter and guess on.
//
// auth is the authorization the vault keeps for this TPM; held says the
// vault already had it from an earlier PIN slot. When the TPM's lockout
// authorization is empty, TakeLockout sets the dictionary-attack
// parameters (while there is still no authorization to expose) and then
// changes the authorization to auth in a session salted to the SRK and
// encrypted on the bus. When it is already set, TakeLockout accepts it
// only if held, and never guesses: ErrLockoutOwned.
func TakeLockout(t transport.TPM, auth []byte, held bool) error {
	set, err := lockoutAuthSet(t)
	if err != nil {
		return err
	}
	if set {
		if held {
			return nil
		}
		return ErrLockoutOwned
	}
	if err := daParameters(t); err != nil {
		return fmt.Errorf("tpmseal: dictionary-attack parameters: %w", err)
	}
	s, err := loadSRK(t)
	if err != nil {
		return err
	}
	defer flush(t, s.handle)
	change := func(from []byte) error {
		_, err := tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHLockout,
				Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
					tpm2.Auth(from),
					tpm2.AESEncryption(128, tpm2.EncryptIn),
					tpm2.Salted(s.handle, s.pub)),
			},
			NewAuth: tpm2.TPM2BAuth{Buffer: auth},
		}.Execute(t)
		return err
	}
	// The TPM answers a change of the lockout authorization with an HMAC
	// keyed by the new value, which go-tpm v0.9.8 checks against the old
	// one, so the first change reports a bad response HMAC even when it
	// took effect. Changing auth to auth then proves the TPM holds it.
	first := change(nil)
	if set, err := lockoutAuthSet(t); err != nil || !set {
		return fmt.Errorf("tpmseal: lockout authorization: %w", errors.Join(first, err))
	}
	if err := change(auth); err != nil {
		return fmt.Errorf("tpmseal: lockout authorization: %w", err)
	}
	return nil
}

// daParameters runs TPM2_DictionaryAttackParameters with the empty
// lockout authorization. go-tpm v0.9.8 has no type for this command, so
// it is marshalled here: header, TPM_RH_LOCKOUT, a password session with
// an empty password, and the three parameters.
func daParameters(t transport.TPM) error {
	cmd := binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMSTSessions))
	cmd = binary.BigEndian.AppendUint32(cmd, 0) // size, set below
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMCCDictionaryAttackParameters))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMRHLockout))
	cmd = binary.BigEndian.AppendUint32(cmd, 9) // authorization area size
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMRSPW))
	cmd = append(cmd, 0, 0, 0, 0, 0) // nonce, attributes, password: empty
	cmd = binary.BigEndian.AppendUint32(cmd, PINMaxTries)
	cmd = binary.BigEndian.AppendUint32(cmd, PINRecoverySeconds)
	cmd = binary.BigEndian.AppendUint32(cmd, LockoutRecoverySec)
	binary.BigEndian.PutUint32(cmd[2:6], uint32(len(cmd)))
	rsp, err := t.Send(cmd)
	if err != nil {
		return err
	}
	if len(rsp) < 10 {
		return errors.New("short response")
	}
	if rc := binary.BigEndian.Uint32(rsp[6:10]); rc != 0 {
		return tpm2.TPMRC(rc)
	}
	return nil
}
