// Package update checks release metadata before anything from upstream
// reaches the change pipeline (SPEC UPD-8, CHG-3).
//
// This is the narrow seam the pipeline needs: a Verified value can only be
// built by Verify, after a threshold of distinct root keys has signed the
// exact metadata bytes. Full TUF (timestamp freshness, key rotation,
// rollback protection across versions) is the update package's own work
// (P4) and will build on a maintained implementation; it will construct
// Verified the same way, so the pipeline does not change.
package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Root is the installed set of maintainer keys and how many must sign.
type Root struct {
	Keys      map[string]ed25519.PublicKey // key ID -> public key
	Threshold int
}

// Signature is one maintainer key's signature over the metadata bytes.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// Release is the signed metadata: a version and the image files it
// installs, each a path under guest-image/ or host-image/ with the SHA-256
// of its content.
type Release struct {
	Version  string            `json:"version"`
	Security bool              `json:"security,omitempty"`
	Images   map[string]string `json:"images"`
}

// Verified is a release whose metadata passed Verify. Its fields are
// unexported, so no other package can make one.
type Verified struct {
	r        Release
	security bool
}

// Version is the signed version string.
func (v Verified) Version() string { return v.r.Version }

// Security reports a security release that also carries the independent
// attestation UPD-8 requires before it may auto-stage. A release marked
// security without one is still a release, but it is asked like any other.
func (v Verified) Security() bool { return v.security }

// Images returns the signed image paths and their SHA-256 digests (hex).
func (v Verified) Images() map[string]string {
	out := make(map[string]string, len(v.r.Images))
	for k, d := range v.r.Images {
		out[k] = d
	}
	return out
}

// OK reports whether v came from Verify (the zero value did not).
func (v Verified) OK() bool { return v.r.Version != "" }

// Digest is the form Images uses for content.
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Verify checks that at least root.Threshold distinct root keys signed
// meta, then decodes it strictly. attestations is the number of
// independent attestations the fast channel holds for this release
// (OSS-8); a security release needs at least one to count as one.
func Verify(root Root, meta []byte, sigs []Signature, attestations int) (Verified, error) {
	if root.Threshold < 1 || len(root.Keys) < root.Threshold {
		return Verified{}, errors.New("update: root threshold is not satisfiable")
	}
	// The threshold counts keys, not key IDs: a root listing one key
	// under two IDs is refused.
	seenKey := map[string]bool{}
	for _, k := range root.Keys {
		if len(k) != ed25519.PublicKeySize || seenKey[string(k)] {
			return Verified{}, errors.New("update: root has a malformed or repeated key")
		}
		seenKey[string(k)] = true
	}
	good := map[string]bool{}
	for _, s := range sigs {
		k, ok := root.Keys[s.KeyID]
		if ok && ed25519.Verify(k, meta, s.Sig) {
			good[string(k)] = true
		}
	}
	if len(good) < root.Threshold {
		return Verified{}, fmt.Errorf("update: %d of %d required signatures", len(good), root.Threshold)
	}
	if err := noDuplicateKeys(meta, releaseFields); err != nil {
		return Verified{}, fmt.Errorf("update: metadata does not parse: %v", err)
	}
	var r Release
	d := json.NewDecoder(bytes.NewReader(meta))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return Verified{}, fmt.Errorf("update: metadata does not parse: %v", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return Verified{}, errors.New("update: metadata has trailing data")
	}
	if r.Version == "" || len(r.Images) == 0 {
		return Verified{}, errors.New("update: metadata needs a version and images")
	}
	for p, dg := range r.Images {
		ns, _, _ := strings.Cut(p, "/")
		if (ns != "guest-image" && ns != "host-image") || path.Clean(p) != p || strings.Contains(p, "..") {
			return Verified{}, fmt.Errorf("update: %s is not an image path", p)
		}
		if b, err := hex.DecodeString(dg); err != nil || len(b) != sha256.Size {
			return Verified{}, fmt.Errorf("update: %s has a bad digest", p)
		}
	}
	return Verified{r: r, security: r.Security && attestations >= 1}, nil
}

// releaseFields are the exact top-level keys a release may carry.
var releaseFields = map[string]bool{"version": true, "security": true, "images": true}

// noDuplicateKeys rejects JSON with a repeated key in any object, which
// encoding/json would otherwise resolve silently (last one wins), and a
// top-level key not exactly in top: encoding/json matches struct fields
// case-insensitively, so "Version" would otherwise override "version".
func noDuplicateKeys(b []byte, top map[string]bool) error {
	d := json.NewDecoder(bytes.NewReader(b))
	depth := 0
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			depth++
			defer func() { depth-- }()
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				ks, _ := k.(string)
				if keys[ks] {
					return fmt.Errorf("duplicate key %q", ks)
				}
				if depth == 1 && !top[ks] {
					return fmt.Errorf("unknown key %q", ks)
				}
				keys[ks] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	return walk()
}
