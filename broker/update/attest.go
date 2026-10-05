package update

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Attestations (OSS-8): an installation that reproduced a release says
// what happened, on what hardware, with what versions, and signs it. The
// envelope is DSSE, the in-toto signing format, with the attestor's
// Ed25519 public key inside the signed statement.
//
// Attestations are evidence, not authority (OSS-9). Their one hard use
// here is UPD-8 with Mark's D6: a security fix auto-stages only with its
// threshold signatures plus at least one independent passing attestation
// from the fast channel. Independent means signed by a key that is not
// one of the repository's root-listed keys and not this box's own.

// AttestationType is the DSSE payload type.
const AttestationType = "application/vnd.agentos.attestation.v1+json"

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
}

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
func Attest(priv ed25519.PrivateKey, v *Checked, st Statement) ([]byte, error) {
	st.Release = v.manifest.Path
	st.ManifestSHA256 = v.manifest.SHA256
	st.Attestor = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if st.Result != ResultPass && st.Result != ResultFail {
		return nil, fmt.Errorf("result %q is not pass or fail", st.Result)
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
// statement and the attestor key.
func ParseAttestation(b []byte) (Statement, ed25519.PublicKey, error) {
	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return Statement{}, nil, err
	}
	if env.PayloadType != AttestationType {
		return Statement{}, nil, fmt.Errorf("payload type %q", env.PayloadType)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, nil, err
	}
	var st Statement
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return Statement{}, nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(st.Attestor)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return Statement{}, nil, errors.New("attestor is not an Ed25519 key")
	}
	pub := ed25519.PublicKey(raw)
	for _, sig := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err == nil && ed25519.Verify(pub, pae(env.PayloadType, body), raw) {
			return st, pub, nil
		}
	}
	return Statement{}, nil, errors.New("attestation signature does not verify")
}

// IndependentPasses counts distinct attestors with a valid, passing,
// fast-channel attestation for exactly this release, excluding
// root-listed keys and own (this box's key; may be nil). Malformed or
// unrelated attestations are skipped, not fatal: they arrive from anyone.
func (v *Checked) IndependentPasses(atts [][]byte, own ed25519.PublicKey) int {
	seen := map[string]bool{}
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
		if v.maintainers[fp] {
			continue
		}
		seen[fp] = true
	}
	return len(seen)
}

// SecurityAutoStage reports whether a security fix may stage without the
// owner: threshold signatures (already checked to make v) plus at least
// one independent fast-channel attestation (UPD-8, D6). Other releases
// follow UPD-5's soak, which is not decided here.
func (v *Checked) SecurityAutoStage(atts [][]byte, own ed25519.PublicKey) error {
	if !v.release.Security {
		return errors.New("not a security fix")
	}
	if v.IndependentPasses(atts, own) < 1 {
		return ErrNeedsAttestation
	}
	return nil
}

// Verified hands a checked release to the change pipeline as the Verified
// value it consumes (CHG-3, #34): the signed version and image digests,
// with Security set only for a security fix that also has an independent
// fast-channel attestation (UPD-8, D6).
func (v *Checked) Verified(atts [][]byte, own ed25519.PublicKey) Verified {
	images := make(map[string]string, len(v.files))
	for p, f := range v.files {
		images[p] = f.SHA256
	}
	r := Release{Version: strconv.FormatInt(v.release.Version, 10), Security: v.release.Security, Images: images}
	return Verified{r: r, security: r.Security && v.IndependentPasses(atts, own) >= 1}
}
