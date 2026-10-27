package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Certifier is the kernel's certify (kernelsock.Owner.Certify, wrapped by
// cmd/agentosd): the kernel holds the page authority and signs the page's
// serving key, PKIX DER, for the page name (CH-9, MIG-4-recovery-f2). It
// returns the leaf and the authority's certificate, both DER. Every
// refusal is a sockets.Code: ErrNoAuthority, ErrRestore or ErrBadArgs;
// any other error reaches the page as ErrFailed, so no kernel text does.
type Certifier interface {
	Certify(ctx context.Context, pub []byte) (leaf, authority []byte, err error)
}

// LogPageNoKernel is the one line a page socket with no kernel to certify
// logs: the owner page serves HTTP only.
const LogPageNoKernel = "page authority: no kernel to certify; the owner page serves HTTP only"

var (
	errNoAuthority = sockets.Code(localapi.ErrNoAuthority)
	errRestore     = sockets.Code(localapi.ErrRestore)
)

// certify forwards the page's serving key to the kernel (OpCertify). It
// returns the leaf and the authority's certificate only; agentosd never
// holds the authority.
func (s *Server) certify(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	k := s.cfg.Certify
	if k == nil {
		s.noPage.Do(func() { log.Print(LogPageNoKernel) })
		return nil, errNoAuthority
	}
	var a localapi.CertifyArgs
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if len(a.Pub) == 0 || len(a.Pub) > localapi.MaxPub {
		return nil, errBadArgs
	}
	leaf, ca, err := k.Certify(ctx, a.Pub)
	if err != nil {
		var c sockets.Code
		if errors.As(err, &c) && (c == errNoAuthority || c == errRestore || c == errBadArgs) {
			return nil, c
		}
		return nil, errFailed
	}
	if len(leaf) == 0 || len(ca) == 0 {
		return nil, errFailed
	}
	return localapi.Certified{Leaf: leaf, Authority: ca}, nil
}
