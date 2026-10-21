package run

import (
	"crypto/ed25519"
	"crypto/x509"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// OpenExit builds the exit clerk a clerk process serves: its Secrets from
// dir, the process's own directory, durable there, and the declaration
// checked as clerk.NewExit checks it. The sealer is the software AESSealer
// until STO-2 releases the real store key; until then only tests run one.
func OpenExit(dir string, s clerk.Sealer, d clerk.Declaration, anchors []ed25519.PublicKey, roots *x509.CertPool) (*clerk.Exit, error) {
	sec, err := OpenSecrets(dir, s)
	if err != nil {
		return nil, err
	}
	return clerk.NewExit(d, anchors, sec, roots)
}
