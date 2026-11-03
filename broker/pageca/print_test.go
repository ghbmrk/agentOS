package pageca

// REQ: CLK-1

import (
	"crypto/x509"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// The authority's sealed form prints no key, in sixteen verbs, bare and in
// holders with unexported pointer, value and interface fields (CLK-1,
// DECOY-b-8, #4833), and the authority itself holds its key by pointer,
// which prints as an address.
func TestSealedPrintsNoKey(t *testing.T) {
	a := newAuthority(t)
	k := get(x509.MarshalPKCS8PrivateKey(a.key))
	v := sealed{Cert: a.cert.Raw, Key: new(&k)}
	d, dec := a.key.D.Bytes(), []byte(a.key.D.String())
	secrettest.NoKey(t, [][]byte{d, dec}, append(secrettest.Holders(v), secrettest.Holders(a)...)...)
}
