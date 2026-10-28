package card

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"html/template"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/pageca"
)

var (
	authOnce sync.Once
	authDER  []byte
	authErr  error
)

// testAuthority is one page authority's certificate, made by pageca as the
// box makes it, shared by this package's tests (card links no pageca).
func testAuthority(t testing.TB) []byte {
	t.Helper()
	authOnce.Do(func() {
		var a *pageca.Authority
		if a, authErr = pageca.New(pageca.DefaultName, time.Now(), nil); authErr == nil {
			authDER = a.Certificate()
		}
	})
	if authErr != nil {
		t.Fatal(authErr)
	}
	return bytes.Clone(authDER)
}

// testFingerprint is testAuthority's fingerprint.
func testFingerprint(t testing.TB) string { return Fingerprint(testAuthority(t)) }

// printedFingerprint is fp as the card prints it: two lines of eight
// groups, HTML-escaped.
func printedFingerprint(fp string) []string {
	var out []string
	for _, l := range fingerprintLines(fp) {
		out = append(out, template.HTMLEscapeString(l))
	}
	return out
}

// REQ: CH-9
//
// One rendering: the card's fingerprint is pageca's, so the card and a
// phone-side page showing the authority never differ.
func TestFingerprintMatchesPageca(t *testing.T) {
	for i := 0; i < 3; i++ {
		a, err := pageca.New(pageca.DefaultName, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := Fingerprint(a.Certificate()), a.Fingerprint(); got != want {
			t.Fatalf("card prints %q, pageca %q", got, want)
		}
	}
	if l := fingerprintLines(testFingerprint(t)); len(l) != 2 || len(strings.Fields(l[0])) != 8 || len(strings.Fields(l[1])) != 8 {
		t.Fatalf("fingerprint lines = %q, want two lines of eight groups", l)
	}
}

// REQ: HW-1, CH-9
//
// The full card's HTML holds the given authority's fingerprint, the
// page's name and the address-bar and trust lines; it catches a card
// missing any of them.
func TestCardPrintsTheAuthoritysFingerprintAndName(t *testing.T) {
	x := newRig(t)
	page, err := x.d.Page()
	if err != nil {
		t.Fatal(err)
	}
	full, err := HTML(mustGen(t, 11), testFingerprint(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"display page": string(page), "card": string(full)} {
		want := append(printedFingerprint(testFingerprint(t)), `<span class="mono">`+PageName+`</span>`,
			template.HTMLEscapeString(AddressBarLine), template.HTMLEscapeString(TrustLine))
		for _, w := range want {
			if !strings.Contains(p, w) {
				t.Fatalf("%s lacks %q", name, w)
			}
		}
	}
	// Another authority prints another fingerprint: the card prints the
	// one it was given, not a fixed string.
	other, err := pageca.New(pageca.DefaultName, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(full), printedFingerprint(other.Fingerprint())[0]) {
		t.Fatal("card printed another authority's fingerprint")
	}
}

// countingRand counts the bytes read from it.
type countingRand struct{ n int }

func (c *countingRand) Read(p []byte) (int, error) {
	c.n += len(p)
	return rand.Read(p)
}

// caCert makes a self-signed CA for name (empty: no name constraint),
// with the name constraint critical or not.
func caCert(t *testing.T, name string, critical, maxPathZero bool) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: maxPathZero}
	if name != "" {
		tmpl.PermittedDNSDomains, tmpl.PermittedDNSDomainsCritical = []string{name}, critical
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// REQ: HW-1
//
// Fail closed: with no authority, garbage, a CA without a name
// constraint, one whose constraint is not critical, one that may issue
// sub-CAs, or one constrained to another name, NewDisplay refuses with
// ErrNoAuthority and reads no randomness; it catches a fingerprint-less
// card or one printing a stranger's certificate. The rig's control is a
// good authority, which the same rand serves.
func TestNoAuthorityNoCard(t *testing.T) {
	cases := map[string][]byte{
		"nil":               nil,
		"empty":             {},
		"garbage":           []byte("not a certificate"),
		"no constraint":     caCert(t, "", false, true),
		"not critical":      caCert(t, PageName, false, true),
		"another name":      caCert(t, "agentos.example", true, true),
		"may issue sub-CAs": caCert(t, PageName, true, false),
		"a truncated der":   testAuthority(t)[:100],
	}
	for name, der := range cases {
		for _, rot := range []*Parts{nil, {Recovery: true}} {
			r := &countingRand{}
			gen := 0
			d, err := NewDisplay(DisplayConfig{Rand: r, Authority: der, Rotate: rot,
				Generate:  func(r io.Reader) (*Card, error) { gen++; return Generate(r) },
				Provision: func(*Card) error { return nil }})
			if !errors.Is(err, ErrNoAuthority) || d != nil {
				t.Fatalf("%s (rotation %v): err %v, display %v", name, rot != nil, err, d)
			}
			if r.n != 0 || gen != 0 {
				t.Fatalf("%s: read %d random bytes, generated %d cards before refusing", name, r.n, gen)
			}
		}
	}
	if err := CheckAuthority(caCert(t, PageName, true, true)); err != nil {
		t.Fatalf("a page authority's shape refused: %v", err)
	}
	r := &countingRand{}
	if _, err := NewDisplay(DisplayConfig{Rand: r, Authority: testAuthority(t), Provision: func(*Card) error { return nil }}); err != nil || r.n == 0 {
		t.Fatalf("a good authority: err %v, %d bytes read", err, r.n)
	}
}
