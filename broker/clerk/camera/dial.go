package camera

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// homeAddr admits only a literal ip:port on the home network: a private
// or link-local IPv4 address that is not a /24's broadcast, or a
// unique-local or link-local IPv6 address. Never a name to resolve, a
// global address, the box itself or a group, so the clerk reaches no
// internet host (DEV-1, DEV-2). The guard checks the same address again
// against the host's pins.
func homeAddr(ap netip.AddrPort) bool {
	a := ap.Addr().Unmap()
	if !ap.IsValid() || ap.Port() == 0 || a.Zone() != "" {
		return false
	}
	if a.Is4() && a.As4()[3] == 255 {
		return false
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}

// dial opens pin's stream: the guard's dial, then TLS 1.3 with the node's
// leaf key checked against the pin by SPKI hash (no chain, no name) and the
// core's client key presented. The key check runs on the node's
// certificate, before the client's certificate is sent, so a node with
// another key never sees a signature by the client key. A mismatch is
// errMismatch.
func (c *Clerk) dial(ctx context.Context, pin Node) (net.Conn, error) {
	if !homeAddr(pin.Addr) {
		return nil, ErrAddress
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	raw, err := c.cfg.Guard.DialContext(netguard.WithPurpose(ctx, netguard.PurposeDevice), "tcp", pin.Addr.String())
	if err != nil {
		c.log(pin.ID, "dial refused or failed")
		return nil, ErrDial
	}
	mismatch := false
	tc := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // VerifyConnection below is the check
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || netguard.KeyHash(cs.PeerCertificates[0]) != pin.Key {
				mismatch = true
				return errMismatch
			}
			return nil
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return c.cfg.Key.certificate(), nil
		},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		if mismatch {
			return nil, errMismatch
		}
		c.log(pin.ID, "handshake failed")
		return nil, errors.Join(ErrDial, ErrHandshake)
	}
	return tc, nil
}
