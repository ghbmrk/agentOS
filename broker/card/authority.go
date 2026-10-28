package card

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrNoAuthority is NewDisplay's refusal of a card without the page
// authority's certificate, or with one that is not the page's authority
// (HW-1): a card printed without the fingerprint can never get it.
var ErrNoAuthority = errors.New("card: no page authority to print on the card")

// AddressBarLine and TrustLine are the card's two lines beside the page
// authority's fingerprint (CH-9).
const (
	AddressBarLine = "agentOS asks for a code or secret only on a page whose address bar shows " + PageName + "."
	TrustLine      = "If your phone ever asks you to install or trust a certificate for this page, check that it shows this fingerprint; if it does not, stop and install nothing."
)

// CheckAuthority is the card's own reading of the authority certificate
// it is handed (DER): a CA that issues only leaves (pageca's
// MaxPathLenZero) under a critical name constraint permitting exactly
// PageName. It does not replace the phone's check or pageca's; it keeps
// the card from printing the fingerprint of a stranger's certificate.
func CheckAuthority(der []byte) error {
	if len(der) == 0 {
		return ErrNoAuthority
	}
	c, err := x509.ParseCertificate(der)
	switch {
	case err != nil,
		!c.BasicConstraintsValid || !c.IsCA || !c.MaxPathLenZero,
		!c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains) != 1 || c.PermittedDNSDomains[0] != PageName:
		return ErrNoAuthority
	}
	return nil
}

// Fingerprint renders SHA-256 of the authority's certificate (DER) as the
// card prints it: upper-case hex in groups of four, byte for byte
// pageca.Fingerprint (a test holds them equal; card links no pageca).
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(h[i : i+4])
	}
	return b.String()
}

// fingerprintLines splits a fingerprint's 16 groups into the card's two
// lines of eight.
func fingerprintLines(fp string) []string {
	g := strings.Fields(fp)
	if len(g) <= 8 {
		return []string{fp}
	}
	return []string{strings.Join(g[:8], " "), strings.Join(g[8:], " ")}
}
