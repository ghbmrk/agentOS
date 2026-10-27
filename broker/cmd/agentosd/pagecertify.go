package main

import (
	"context"
	"errors"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// pageKernel is the owner seam the page's certify calls
// (kernelsock.Owner.Certify).
type pageKernel interface {
	Certify(ctx context.Context, pub []byte) (leaf, authority []byte, err error)
}

// pageCertify forwards the page's certify to the kernel, which holds the
// page authority (CH-9, MIG-4-recovery-f2; localsrv.Certifier). agentosd
// holds no authority and keeps nothing.
type pageCertify struct{ K pageKernel }

// keyRefusedText is pageca.ErrKey's text, the kernel's refusal of a key
// that is not P-256; TestPageCertifyMapsTheKernel keeps the two the same.
const keyRefusedText = "pageca: the serving key is not ECDSA P-256"

// Certify maps the kernel's answer to the page's fixed codes; no kernel
// text passes.
func (p pageCertify) Certify(ctx context.Context, pub []byte) ([]byte, []byte, error) {
	leaf, ca, err := p.K.Certify(ctx, pub)
	var r kernelsock.Refused
	switch {
	case err == nil:
		return leaf, ca, nil
	case errors.Is(err, kernelsock.ErrNoAuthority):
		return nil, nil, sockets.Code(localapi.ErrNoAuthority)
	case errors.Is(err, kernelsock.ErrPageRestore):
		return nil, nil, sockets.Code(localapi.ErrRestore)
	case errors.As(err, &r) && r.Text == keyRefusedText:
		return nil, nil, sockets.Code(localapi.ErrBadArgs)
	}
	return nil, nil, sockets.Code(localapi.ErrFailed)
}
