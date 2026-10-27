package pageca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
)

// sealed is Marshal's form.
type sealed struct {
	Cert []byte `json:"cert"`
	Key  []byte `json:"key"` // PKCS#8
}

// MaxSealed bounds Marshal's form: a P-256 certificate and its PKCS#8 key,
// base64 in JSON, are under 2 KiB.
const MaxSealed = 4 << 10

// Marshal is the authority's sealed form, the plaintext the sealed
// store's handoff.PageCAEntry holds: its certificate and its
// PKCS#8 key. The caller wipes it.
func Marshal(a *Authority) ([]byte, error) {
	k, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return json.Marshal(sealed{Cert: a.cert.Raw, Key: k})
}

// Unmarshal reads Marshal's form, at most MaxSealed bytes, into the
// authority for the one name its certificate admits. It refuses a key and
// certificate that are not one pair made by New, a certificate that is not
// self-signed, and any form but Marshal's own.
func Unmarshal(b []byte) (*Authority, error) {
	if len(b) > MaxSealed {
		return nil, errors.New("pageca: the sealed authority is too large")
	}
	var v sealed
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, errors.New("pageca: the sealed authority does not read")
	}
	defer clear(v.Key)
	pk, err := x509.ParsePKCS8PrivateKey(v.Key)
	if err != nil {
		return nil, err
	}
	key, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pageca: not an ECDSA key")
	}
	cert, err := x509.ParseCertificate(v.Cert)
	if err != nil {
		return nil, err
	}
	if len(cert.PermittedDNSDomains) != 1 || !ValidName(cert.PermittedDNSDomains[0]) {
		return nil, errors.New("pageca: not a page authority")
	}
	if cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("pageca: the authority's certificate is not self-signed")
	}
	au, err := fromParts(cert.PermittedDNSDomains[0], v.Cert, key)
	if err != nil {
		return nil, err
	}
	// One encoding only: what reads is exactly what Marshal writes.
	again, err := Marshal(au)
	defer clear(again)
	if err != nil || !bytes.Equal(again, b) {
		return nil, errors.New("pageca: the sealed authority is not in its one form")
	}
	return au, nil
}
