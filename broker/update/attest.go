package update

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Attestations (OSS-8): an installation that reproduced a release says
// what happened, on what hardware, with what versions, and signs it. The
// envelope is DSSE, the in-toto signing format, with the attestor's
// Ed25519 public key inside the signed statement.
//
// Attestations are evidence, not authority (OSS-9). Their one hard use
// here is UPD-8 with Mark's D6, as the arbitrator corrected it: a security
// fix auto-stages only with its threshold signatures plus at least one
// passing fast-channel attestation from an independent attestor. Anyone
// can mint a key, a compromised signing quorum included, so independent
// means on the box's allow-list (Options.Attestors: pinned in the image or
// added by the owner), and still not a key any accepted root listed, not
// maintainer-operated, and not the box's own. The list starts empty, so
// until it has entries every security fix goes to the owner.
//
// A maintainer-run attestor (the project's test box) runs from day one:
// its key is in the signed target AttestorsPath and its statements carry
// Operator "maintainer". Its passes are shown as evidence
// (MaintainerPasses). As an interim (Mark, 2026-10-05) it also counts as
// the check while every allow-listed key is maintainer-operated, so it
// must be both allow-listed and in the signed list; once an outside
// attestor is listed it stops counting.

// AttestationType is the DSSE payload type.
const AttestationType = "application/vnd.agentos.attestation.v1+json"

// AttestorsPath is the signed target listing maintainer-operated attestor
// keys: {"keys": ["<base64 Ed25519 public key>", ...]}.
const AttestorsPath = "attestors/maintainer.json"

// OperatorMaintainer marks a statement from a maintainer-operated attestor.
const OperatorMaintainer = "maintainer"

type attestorList struct {
	Keys []string `json:"keys"`
}

var attestorListFields = fields("keys")

// attestorFingerprint is the seen-key fingerprint of a base64 Ed25519 key.
func attestorFingerprint(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", errors.New("attestor is not an Ed25519 key")
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		return "", err
	}
	return fingerprint(der), nil
}

// Attestation results.
const (
	ResultPass = "pass"
	ResultFail = "fail"
)

// Statement is what an attestation says.
type Statement struct {
	// Manifest is the manifest target path, e.g. releases/12.json, and
	// ManifestSHA256 its hash, so the statement names exact bytes.
	Release        string `json:"release"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Result         string `json:"result"`
	// Channel the attesting installation follows.
	Channel       string            `json:"channel"`
	HardwareClass string            `json:"hardware_class"`
	Versions      map[string]string `json:"versions,omitempty"`
	// Attestor is the signer's Ed25519 public key, standard base64.
	Attestor string `json:"attestor"`
	// Operator is OperatorMaintainer for a maintainer-run attestor, else
	// empty. A statement with any operator never counts as independent.
	Operator string `json:"operator,omitempty"`
}

var (
	statementFields = fields("release", "manifest_sha256", "result", "channel", "hardware_class", "versions", "attestor", "operator")
	envelopeFields  = fields("payloadType", "payload", "signatures")
	signatureFields = fields("keyid", "sig")
)

// ErrNeedsAttestation: a security fix lacks an independent attestation.
var ErrNeedsAttestation = errors.New("security fix has no independent fast-channel attestation yet")

// envelope is a DSSE envelope (github.com/secure-systems-lab/dsse, v1).
// The format is small enough to write out here; go-securesystemslib's
// dsse package would also vendor golang.org/x/crypto/ssh.
type envelope struct {
	PayloadType string         `json:"payloadType"`
	Payload     string         `json:"payload"`
	Signatures  []envSignature `json:"signatures"`
}

type envSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// pae is DSSE's pre-authentication encoding, what the signature covers.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// Attest signs a statement for the release v names. Attestor and the
// release fields are filled in from v and priv.
func Attest(priv ed25519.PrivateKey, v *Verified, st Statement) ([]byte, error) {
	if !v.ok() {
		return nil, ErrNotChecked
	}
	st.Release = v.manifest.Path
	st.ManifestSHA256 = v.manifest.SHA256
	st.Attestor = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if st.Result != ResultPass && st.Result != ResultFail {
		return nil, fmt.Errorf("result %q is not pass or fail", st.Result)
	}
	if st.Operator != "" && st.Operator != OperatorMaintainer {
		return nil, fmt.Errorf("operator %q is not %q", st.Operator, OperatorMaintainer)
	}
	body, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	id, err := KeyID(priv.Public())
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{
		PayloadType: AttestationType,
		Payload:     base64.StdEncoding.EncodeToString(body),
		Signatures:  []envSignature{{KeyID: id, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pae(AttestationType, body)))}},
	})
}

// ParseAttestation checks an envelope's signature and returns its
// statement and the attestor key. Envelope, signatures and statement are
// decoded strictly: no unknown, duplicate or case-variant key.
func ParseAttestation(b []byte) (Statement, ed25519.PublicKey, error) {
	var env struct {
		PayloadType string            `json:"payloadType"`
		Payload     string            `json:"payload"`
		Signatures  []json.RawMessage `json:"signatures"`
	}
	if err := decodeStrict(b, &env, envelopeFields); err != nil {
		return Statement{}, nil, fmt.Errorf("attestation envelope: %w", err)
	}
	if env.PayloadType != AttestationType {
		return Statement{}, nil, fmt.Errorf("payload type %q", env.PayloadType)
	}
	sigs := make([]envSignature, 0, len(env.Signatures))
	for _, raw := range env.Signatures {
		var sig envSignature
		if err := decodeStrict(raw, &sig, signatureFields); err != nil {
			return Statement{}, nil, fmt.Errorf("attestation signature: %w", err)
		}
		sigs = append(sigs, sig)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, nil, err
	}
	var st Statement
	if err := decodeStrict(body, &st, statementFields); err != nil {
		return Statement{}, nil, fmt.Errorf("attestation statement: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(st.Attestor)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return Statement{}, nil, errors.New("attestor is not an Ed25519 key")
	}
	pub := ed25519.PublicKey(raw)
	for _, sig := range sigs {
		raw, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err == nil && ed25519.Verify(pub, pae(env.PayloadType, body), raw) {
			return st, pub, nil
		}
	}
	return Statement{}, nil, errors.New("attestation signature does not verify")
}

// passes calls f with the fingerprint and statement of each distinct
// attestor with a valid, passing, fast-channel attestation for exactly
// this release, other than own. Malformed or unrelated attestations are
// skipped, not fatal: they arrive from anyone.
func (v *Verified) passes(atts [][]byte, own ed25519.PublicKey, f func(fp string, st Statement)) {
	done := map[string]bool{}
	for _, b := range atts {
		st, pub, err := ParseAttestation(b)
		if err != nil || st.Release != v.manifest.Path || st.ManifestSHA256 != v.manifest.SHA256 ||
			st.Result != ResultPass || st.Channel != ChannelFast {
			continue
		}
		if own != nil && pub.Equal(own) {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			continue
		}
		fp := fingerprint(der)
		if !done[fp] {
			done[fp] = true
			f(fp, st)
		}
	}
}

// IndependentPasses counts distinct allow-listed independent attestors
// (see above)
// with a valid, passing, fast-channel attestation for exactly this
// release. own is this box's key and may be nil.
func (v *Verified) IndependentPasses(atts [][]byte, own ed25519.PublicKey) int {
	if !v.ok() {
		return 0
	}
	n := 0
	v.passes(atts, own, func(fp string, st Statement) {
		if !v.allowed[fp] || v.maintainers[fp] {
			return
		}
		if v.pinned[fp] {
			// The project's test box: only the interim check.
			if v.interim {
				n++
			}
			return
		}
		if !v.operated[fp] && st.Operator == "" {
			n++
		}
	})
	return n
}

// MaintainerPasses counts passing attestations from maintainer-operated
// attestors (listed in AttestorsPath or self-marked). They are evidence
// for the owner's digest, labelled maintainer-operated, never authority.
func (v *Verified) MaintainerPasses(atts [][]byte, own ed25519.PublicKey) int {
	if !v.ok() {
		return 0
	}
	n := 0
	v.passes(atts, own, func(fp string, st Statement) {
		if v.operated[fp] || v.pinned[fp] || st.Operator == OperatorMaintainer {
			n++
		}
	})
	return n
}

// SecurityAutoStage reports whether a security fix may stage without the
// owner: threshold signatures (already checked to make v) plus at least
// one independent fast-channel attestation of exactly v (UPD-8, D6). The
// newest release counts as a security fix when it supersedes one
// (Result.SecurityFix, security lens C2). Other releases
// follow UPD-5's soak, which is not decided here.
func (v *Verified) SecurityAutoStage(atts [][]byte, own ed25519.PublicKey) error {
	if !v.ok() {
		return ErrNotChecked
	}
	if !v.release.Security && !v.coversFix {
		return errors.New("not a security fix")
	}
	if v.IndependentPasses(atts, own) < 1 {
		return ErrNeedsAttestation
	}
	return nil
}

// InterimAttestation reports whether the box's allow-list holds only the
// project's own test box (Options.InterimAttestors) and never held an
// outside attestor, so the digest can say the fix was checked by the
// project rather than an outside attestor.
func (v *Verified) InterimAttestation() bool { return v.ok() && v.interim }
