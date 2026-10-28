package localui

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// The owner page over HTTPS (OWN-page-https, #3153; CH-9). This process
// never holds the page authority's key: it makes its own serving key in
// memory, never writes it, and asks agentosd to certify it (OpCertify) at
// start and every RenewEvery, with a fresh key each time.

// RenewEvery is how often the serving certificate is renewed; RetryEvery
// how soon a failed renewal is tried again, the current one serving
// meanwhile.
const (
	RenewEvery = 24 * time.Hour
	RetryEvery = time.Hour
)

// Fixed log lines: never an error's text.
const (
	LogRenewFailed = "owner page: renewing the serving certificate failed; the current one still serves"
	LogNoHTTPS     = "owner page: no page authority; serving HTTP only"
	LogRestore     = "owner page: my page authority is missing; serving HTTP only until I am restored"
)

// PageTLS is the HTTPS listener's certificate: one serving key and leaf,
// swapped whole on renewal.
type PageTLS struct {
	name  string
	owner Owner
	rand  io.Reader
	log   func(string)
	// after waits between renewals; time.After unless a test sets it.
	after func(time.Duration) <-chan time.Time

	mu   sync.Mutex
	cert *tls.Certificate
	// authority is the authority's certificate (DER) from the last
	// verified Renew; a failed renewal never clears it.
	authority []byte
}

// ErrNoAuthority and ErrRestore are agentosd's answers that the page has
// no authority to serve under: HTTPS stays off (the lifecycle matrix's
// "No sealer" and "authority missing" rows).
var (
	ErrNoAuthority = errors.New("localui: no page authority")
	ErrRestore     = errors.New("localui: the page authority must be restored")
)

// NewPageTLS asks agentosd for the first serving certificate for name. On
// ErrNoAuthority or ErrRestore, or any other failure, there is no HTTPS.
func NewPageTLS(ctx context.Context, name string, o Owner, r io.Reader, logf func(string)) (*PageTLS, error) {
	if r == nil {
		r = rand.Reader
	}
	if logf == nil {
		logf = func(s string) { log.Print(s) }
	}
	p := &PageTLS{name: name, owner: o, rand: r, log: logf, after: time.After}
	if err := p.Renew(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Renew makes a fresh serving key, has agentosd certify it, checks the
// answer and swaps it in. On any error the current certificate stays.
func (p *PageTLS) Renew(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), p.rand)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	var c localapi.Certified
	err = p.owner.Call(ctx, localapi.OpCertify, localapi.CertifyArgs{Pub: pub}, &c)
	switch {
	case refused(err, localapi.ErrNoAuthority):
		return ErrNoAuthority
	case refused(err, localapi.ErrRestore):
		return ErrRestore
	case err != nil:
		return err
	}
	leaf, err := x509.ParseCertificate(c.Leaf)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(c.Authority)
	if err != nil {
		return err
	}
	// Not checked against the clock, which may be wrong at first boot:
	// only that it is for this key and name, under this authority.
	lp, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !lp.Equal(&key.PublicKey) || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != p.name ||
		len(leaf.IPAddresses) != 0 || leaf.CheckSignatureFrom(ca) != nil {
		return errors.New("localui: agentosd's certificate is not for this key and name")
	}
	p.mu.Lock()
	p.cert = &tls.Certificate{Certificate: [][]byte{c.Leaf}, PrivateKey: key, Leaf: leaf}
	p.authority = bytes.Clone(c.Authority)
	p.mu.Unlock()
	return nil
}

// Run renews every RenewEvery until ctx ends; a failed renewal is logged
// with a fixed line and retried every RetryEvery.
func (p *PageTLS) Run(ctx context.Context) {
	wait := RenewEvery
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.after(wait):
		}
		if err := p.Renew(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log(LogRenewFailed)
			wait = RetryEvery
			continue
		}
		wait = RenewEvery
	}
}

// Leaf is the serving certificate now served.
func (p *PageTLS) Leaf() *x509.Certificate {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cert.Leaf
}

// Authority is a copy of the page authority's certificate (DER) from the
// last verified renewal: the one the served leaf chains to, which the
// Owner Card and every rotation sheet print the fingerprint of (HW-1,
// REC-4). It is nil on a nil PageTLS (no HTTPS) and before any success.
func (p *PageTLS) Authority() []byte {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.authority)
}

var errSNI = errors.New("localui: not the page's name")

// Config is the HTTPS listener's TLS: 1.3 only, and no handshake unless
// the client names the page (SNI), so a DNS-rebound name never gets one.
func (p *PageTLS) Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName != p.name {
				return nil, errSNI
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.cert, nil
		},
	}
}
