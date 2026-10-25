package pageca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

// REQ: CH-9

var built = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func newAuthority(t *testing.T) *Authority {
	t.Helper()
	a, err := New(DefaultName, built, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func p256(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, der
}

// forge signs a leaf with the authority's own key outside Issue, as a key
// thief would, so only the name constraint can refuse it.
func forge(t *testing.T, a *Authority, dns []string, ips []net.IP) *x509.Certificate {
	t.Helper()
	k, _ := p256(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "x"}, DNSNames: dns, IPAddresses: ips,
		NotBefore: built, NotAfter: built.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &k.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verify(a *Authority, leaf *x509.Certificate, name string) error {
	roots := x509.NewCertPool()
	roots.AddCert(a.cert)
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: built.Add(time.Hour),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

type subtree struct {
	Base asn1.RawValue
}

type constraints struct {
	Permitted []subtree `asn1:"optional,tag:0"`
	Excluded  []subtree `asn1:"optional,tag:1"`
}

func TestAuthorityVerifiesOnlyThePageName(t *testing.T) {
	a := newAuthority(t)
	if err := verify(a, forge(t, a, []string{DefaultName}, nil), DefaultName); err != nil {
		t.Fatalf("the page name: %v", err)
	}
	for _, c := range []struct {
		why  string
		dns  []string
		ips  []net.IP
		host string
	}{
		{"a subdomain", []string{"x." + DefaultName}, nil, "x." + DefaultName},
		{"another name", []string{"example.com"}, nil, "example.com"},
		{"another .internal name", []string{"other.internal"}, nil, "other.internal"},
		{"an IPv4 address", nil, []net.IP{net.ParseIP("10.42.0.1")}, "10.42.0.1"},
		{"an IPv6 address", nil, []net.IP{net.ParseIP("fe80::1")}, "fe80::1"},
		{"the name plus another", []string{DefaultName, "example.com"}, nil, DefaultName},
		{"the name plus an IP", []string{DefaultName}, []net.IP{net.ParseIP("10.42.0.1")}, DefaultName},
	} {
		if err := verify(a, forge(t, a, c.dns, c.ips), c.host); err == nil {
			t.Errorf("%s verified", c.why)
		}
	}
	// The encoded extension, so the test does not pass on Go's reading
	// alone: critical, permitted the name only, excluded its subtree and
	// every address.
	var ext *pkix.Extension
	for i, e := range a.cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 30}) {
			ext = &a.cert.Extensions[i]
		}
	}
	if ext == nil || !ext.Critical {
		t.Fatalf("name constraints %+v: missing or not critical", ext)
	}
	var nc constraints
	if rest, err := asn1.Unmarshal(ext.Value, &nc); err != nil || len(rest) != 0 {
		t.Fatalf("name constraints: %v", err)
	}
	if len(nc.Permitted) != 1 || nc.Permitted[0].Base.Tag != 2 || string(nc.Permitted[0].Base.Bytes) != DefaultName {
		t.Errorf("permitted %+v", nc.Permitted)
	}
	var dns []string
	var ips [][]byte
	for _, s := range nc.Excluded {
		switch s.Base.Tag {
		case 2:
			dns = append(dns, string(s.Base.Bytes))
		case 7:
			ips = append(ips, s.Base.Bytes)
		default:
			t.Errorf("excluded tag %d", s.Base.Tag)
		}
	}
	if len(dns) != 1 || dns[0] != "."+DefaultName {
		t.Errorf("excluded names %q", dns)
	}
	if len(ips) != 2 || !bytes.Equal(ips[0], make([]byte, 8)) || !bytes.Equal(ips[1], make([]byte, 32)) {
		t.Errorf("excluded addresses %x", ips)
	}
}

func TestAuthorityShape(t *testing.T) {
	a := newAuthority(t)
	c := a.cert
	if want := built.Add(-24 * time.Hour); !c.NotBefore.Equal(want) {
		t.Errorf("NotBefore %v, want %v (the build time, not the clock)", c.NotBefore, want)
	}
	if want := built.Add(-24*time.Hour).AddDate(30, 0, 0); !c.NotAfter.Equal(want) {
		t.Errorf("NotAfter %v, want %v", c.NotAfter, want)
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Errorf("CA %v path %d zero %v", c.IsCA, c.MaxPathLen, c.MaxPathLenZero)
	}
	if c.KeyUsage != x509.KeyUsageCertSign {
		t.Errorf("key usage %v", c.KeyUsage)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnknownExtKeyUsage) != 0 {
		t.Errorf("extended key usage %v", c.ExtKeyUsage)
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("key %T", c.PublicKey)
	}
	if len(c.EmailAddresses)+len(c.URIs)+len(c.PermittedEmailAddresses)+len(c.PermittedURIDomains) != 0 {
		t.Error("email or URI names")
	}
	// Made twice at different clocks, the window is the same.
	b, err := New(DefaultName, built, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !b.cert.NotBefore.Equal(c.NotBefore) {
		t.Error("NotBefore moved")
	}
	if fp := a.Fingerprint(); len(fp) != 64+15 || fp == b.Fingerprint() {
		t.Errorf("fingerprint %q", fp)
	}
	for _, bad := range []string{"", "internal", "Agentos.internal", "10.42.0.1", "a..internal", "-a.internal", "a.internal.", "a_b.internal"} {
		if _, err := New(bad, built, nil); err == nil {
			t.Errorf("name %q made an authority", bad)
		}
	}
	if _, err := New(DefaultName, time.Time{}, nil); err == nil {
		t.Error("no build time made an authority")
	}
}

func TestIssueCapsAndRefuses(t *testing.T) {
	a := newAuthority(t)
	_, pub := p256(t)
	for _, now := range []time.Time{built.Add(-48 * time.Hour), built.Add(time.Hour), built.AddDate(5, 0, 0)} {
		der, err := a.Issue(pub, now, nil)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.NotAfter.Sub(leaf.NotBefore) > MaxLeaf || leaf.NotBefore.Before(built) {
			t.Errorf("at %v: %v to %v", now, leaf.NotBefore, leaf.NotAfter)
		}
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != DefaultName || len(leaf.IPAddresses) != 0 || leaf.IsCA {
			t.Errorf("names %v %v CA %v", leaf.DNSNames, leaf.IPAddresses, leaf.IsCA)
		}
		if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
			t.Errorf("usage %v", leaf.ExtKeyUsage)
		}
		roots := x509.NewCertPool()
		roots.AddCert(a.cert)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: DefaultName, Roots: roots, CurrentTime: leaf.NotBefore.Add(time.Minute)}); err != nil {
			t.Errorf("at %v: %v", now, err)
		}
	}
	// Near the authority's end, never past it.
	der, err := a.Issue(pub, a.cert.NotAfter.Add(-30*24*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	if leaf, _ := x509.ParseCertificate(der); !leaf.NotAfter.Equal(a.cert.NotAfter) {
		t.Errorf("NotAfter %v past %v", leaf.NotAfter, a.cert.NotAfter)
	}
	if _, err := a.Issue(pub, a.cert.NotAfter.Add(48*time.Hour), nil); err != ErrExpired {
		t.Errorf("past the end: %v", err)
	}
	// Other keys.
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, k := range []any{&p384.PublicKey, &rk.PublicKey, ek} {
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Issue(der, built, nil); err != ErrKey {
			t.Errorf("%T: %v", k, err)
		}
	}
	if _, err := a.Issue([]byte("junk"), built, nil); err != ErrKey {
		t.Errorf("junk: %v", err)
	}
	// It has no way to name anything else: its only input is the key.
	if _, err := New("other.internal", built, nil); err != nil {
		t.Fatal(err)
	}
}
