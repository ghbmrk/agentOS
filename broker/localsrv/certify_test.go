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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-9, HW-1

var pageBuilt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// fakeKernel is the kernel's certify: it holds the authority, as the
// kernel process does after f1, and answers as kernelsock's wrapper does.
type fakeKernel struct {
	a     *pageca.Authority
	now   time.Time
	err   error
	calls int
	got   []byte
}

func (k *fakeKernel) Certify(_ context.Context, pub []byte) ([]byte, []byte, error) {
	k.calls++
	k.got = pub
	if k.err != nil {
		return nil, nil, k.err
	}
	leaf, err := k.a.Issue(pub, k.now, nil)
	if errors.Is(err, pageca.ErrKey) {
		return nil, nil, errBadArgs
	}
	if err != nil {
		return nil, nil, err
	}
	return leaf, k.a.Certificate(), nil
}

func newFakeKernel(t *testing.T) *fakeKernel {
	t.Helper()
	a, err := pageca.New(pageca.DefaultName, pageBuilt, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKernel{a: a, now: pageBuilt.Add(48 * time.Hour)}
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

func TestCertifyForwardsToTheKernel(t *testing.T) {
	k := newFakeKernel(t)
	s := New(Config{Certify: k})
	pub := servingKey(t)
	c, err := certifyCall(t, s, pub)
	if err != nil {
		t.Fatal(err)
	}
	if k.calls != 1 || !bytes.Equal(k.got, pub) {
		t.Fatalf("the kernel got %d calls, key forwarded %v", k.calls, bytes.Equal(k.got, pub))
	}
	leaf, err := x509.ParseCertificate(c.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Authority, k.a.Certificate()) {
		t.Fatal("the authority is not the kernel's")
	}
	roots := x509.NewCertPool()
	roots.AddCert(get(x509.ParseCertificate(c.Authority)))
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: pageca.DefaultName, Roots: roots, CurrentTime: k.now}); err != nil {
		t.Fatal(err)
	}
	if got, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey); !bytes.Equal(got, pub) {
		t.Error("the leaf is not for the page's key")
	}
	// The answer carries exactly the two certificates.
	out, _ := s.Ops()[localapi.OpCertify](context.Background(), sockets.Peer{}, mustJSON(localapi.CertifyArgs{Pub: pub}))
	raw, _ := json.Marshal(out)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	if len(fields) != 2 || fields["leaf"] == nil || fields["authority"] == nil {
		t.Errorf("answer fields %v", fields)
	}
	// Empty, oversized or extra-field args refuse here, never reaching the
	// kernel; junk the kernel refuses as a bad key is bad args too.
	k.calls = 0
	for _, args := range []json.RawMessage{mustJSON(localapi.CertifyArgs{}),
		mustJSON(localapi.CertifyArgs{Pub: make([]byte, localapi.MaxPub+1)}), json.RawMessage(`{"pub":"","name":"x.agentos.internal"}`)} {
		if _, err := s.Ops()[localapi.OpCertify](context.Background(), sockets.Peer{}, args); !isCode(err, localapi.ErrBadArgs) {
			t.Errorf("%s: %v", args, err)
		}
	}
	if k.calls != 0 {
		t.Errorf("%d malformed calls reached the kernel", k.calls)
	}
	if _, err := certifyCall(t, s, []byte("junk")); !isCode(err, localapi.ErrBadArgs) {
		t.Errorf("junk key: %v", err)
	}
	// The kernel's no authority and restore reach the page as today's
	// codes; anything else, its text included, is failed.
	for _, c := range []struct {
		err  error
		want string
	}{
		{errNoAuthority, localapi.ErrNoAuthority},
		{errRestore, localapi.ErrRestore},
		{sockets.Code(localapi.ErrUnauthorized), localapi.ErrFailed},
		{errors.New("kernelsock: the kernel refused: /var/lib/secret"), localapi.ErrFailed},
	} {
		k.err = c.err
		_, err := certifyCall(t, s, pub)
		if !isCode(err, c.want) {
			t.Errorf("kernel %v: page got %v, want %s", c.err, err, c.want)
		}
	}
	// No kernel at all: no authority, and the page serves HTTP only.
	if _, err := certifyCall(t, New(Config{}), pub); !isCode(err, localapi.ErrNoAuthority) {
		t.Errorf("no kernel: %v", err)
	}
	// A kernel answering empty certificates is a failure, not a leaf.
	if _, err := certifyCall(t, New(Config{Certify: emptyKernel{}}), pub); !isCode(err, localapi.ErrFailed) {
		t.Errorf("empty answer: %v", err)
	}
}

type emptyKernel struct{}

func (emptyKernel) Certify(context.Context, []byte) ([]byte, []byte, error) { return nil, nil, nil }

func TestAgentosdHoldsNoAuthority(t *testing.T) {
	// agentosd's working directory stands in for its state directory: a
	// certify round never writes there, and the old sealed file never
	// appears.
	dir := t.TempDir()
	t.Chdir(dir)
	s := New(Config{Certify: newFakeKernel(t)})
	if _, err := certifyCall(t, s, servingKey(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := certifyCall(t, New(Config{}), servingKey(t)); !isCode(err, localapi.ErrNoAuthority) {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("the state directory gained %v", ents)
	}
	if _, err := os.Lstat("page-authority.sealed"); !errors.Is(err, os.ErrNotExist) {
		t.Error("agentosd wrote the sealed authority")
	}
	// Nothing in the page socket's config can carry an authority, a
	// directory for one or a sealer: its only certify path is the kernel.
	sealer := reflect.TypeOf((*interface {
		Seal(plain, aad []byte) ([]byte, error)
	})(nil)).Elem()
	cfg := reflect.TypeOf(Config{})
	for i := 0; i < cfg.NumField(); i++ {
		f := cfg.Field(i)
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if strings.HasSuffix(ft.PkgPath(), "/pageca") || f.Type.Implements(sealer) || f.Name == "Dir" || f.Name == "Page" {
			t.Errorf("Config.%s (%s) could hold the page authority", f.Name, f.Type)
		}
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func isCode(err error, code string) bool {
	return err != nil && err.Error() == code
}

func get[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
