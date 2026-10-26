package localsrv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-9, HW-1

var pageBuilt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func testSealer(t *testing.T) pageca.Sealer {
	t.Helper()
	s, err := clerk.NewAESSealer(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func certifyCall(t *testing.T, s *Server, pub []byte) (localapi.Certified, error) {
	t.Helper()
	args, _ := json.Marshal(localapi.CertifyArgs{Pub: pub})
	out, err := s.Ops()[localapi.OpCertify](context.Background(), sockets.Peer{}, args)
	if err != nil {
		return localapi.Certified{}, err
	}
	b, _ := json.Marshal(out)
	var c localapi.Certified
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c, nil
}

func servingKey(t *testing.T) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return der
}

func TestCertifyReturnsLeafNeverKey(t *testing.T) {
	dir := t.TempDir()
	var logged []string
	p := OpenPage(PageConfig{Dir: dir, Sealer: testSealer(t), Built: pageBuilt, Log: func(s string) { logged = append(logged, s) }})
	if len(logged) != 1 || logged[0] != LogPageOpen {
		t.Fatalf("logged %q", logged)
	}
	now := pageBuilt.Add(48 * time.Hour)
	s := New(Config{Page: p, Now: func() time.Time { return now }})
	pub := servingKey(t)
	c, err := certifyCall(t, s, pub)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(c.Authority)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: pageca.DefaultName, Roots: roots, CurrentTime: now}); err != nil {
		t.Fatal(err)
	}
	if got, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey); !bytes.Equal(got, pub) {
		t.Error("the leaf is not for the page's key")
	}
	// The answer carries exactly the two certificates: no key field, and
	// no PKCS#8 or sealed bytes.
	out, _ := s.Ops()[localapi.OpCertify](context.Background(), sockets.Peer{}, mustJSON(localapi.CertifyArgs{Pub: pub}))
	raw, _ := json.Marshal(out)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	if len(fields) != 2 || fields["leaf"] == nil || fields["authority"] == nil {
		t.Errorf("answer fields %v", fields)
	}
	sealed, _ := os.ReadFile(filepath.Join(dir, pageca.File))
	if bytes.Contains(raw, sealed[:32]) || strings.Contains(strings.ToLower(string(raw)), "private") {
		t.Error("the answer carries key material")
	}
	// A key that is not P-256, junk, an oversized or an extra field: bad args.
	for _, args := range []json.RawMessage{mustJSON(localapi.CertifyArgs{Pub: []byte("junk")}), mustJSON(localapi.CertifyArgs{}),
		mustJSON(localapi.CertifyArgs{Pub: make([]byte, localapi.MaxPub+1)}), json.RawMessage(`{"pub":"","name":"x.agentos.internal"}`)} {
		if _, err := s.Ops()[localapi.OpCertify](context.Background(), sockets.Peer{}, args); !isCode(err, localapi.ErrBadArgs) {
			t.Errorf("%s: %v", args, err)
		}
	}
	// Reopened, the same authority.
	p2 := OpenPage(PageConfig{Dir: dir, Sealer: testSealer(t), Built: pageBuilt, Claimed: true, Log: func(string) {}})
	c2, err := certifyCall(t, New(Config{Page: p2, Now: func() time.Time { return now }}), pub)
	if err != nil || !bytes.Equal(c2.Authority, c.Authority) {
		t.Errorf("reopened: %v", err)
	}
}

func TestNoSealerNoAuthority(t *testing.T) {
	var logged []string
	logf := func(s string) { logged = append(logged, s) }
	// No sealer at all, as every shipped agentosd until STO-2.
	p := OpenPage(PageConfig{Dir: t.TempDir(), Built: pageBuilt, Log: logf})
	if _, err := certifyCall(t, New(Config{Page: p}), servingKey(t)); !isCode(err, localapi.ErrNoAuthority) {
		t.Errorf("no sealer: %v", err)
	}
	// No page passed in, as agentosd today.
	if _, err := certifyCall(t, New(Config{}), servingKey(t)); !isCode(err, localapi.ErrNoAuthority) {
		t.Errorf("no page: %v", err)
	}
	// A claimed box with no authority is owed a restore and gets no new one.
	dir := t.TempDir()
	p = OpenPage(PageConfig{Dir: dir, Sealer: testSealer(t), Built: pageBuilt, Claimed: true, Log: logf})
	if _, err := certifyCall(t, New(Config{Page: p}), servingKey(t)); !isCode(err, localapi.ErrRestore) {
		t.Errorf("claimed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, pageca.File)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a claimed box made an authority")
	}
	// A planted link on a fresh box: none, and the link stays.
	dir = t.TempDir()
	os.Symlink("/dev/null", filepath.Join(dir, pageca.File))
	p = OpenPage(PageConfig{Dir: dir, Sealer: testSealer(t), Built: pageBuilt, Log: logf})
	if _, err := certifyCall(t, New(Config{Page: p}), servingKey(t)); !isCode(err, localapi.ErrNoAuthority) {
		t.Errorf("linked: %v", err)
	}
	want := []string{LogPageNoSealer, LogPageRestore, LogPageNotOpen}
	if strings.Join(logged, "\n") != strings.Join(want, "\n") {
		t.Errorf("logged %q, want fixed lines %q", logged, want)
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func isCode(err error, code string) bool {
	return err != nil && err.Error() == code
}
