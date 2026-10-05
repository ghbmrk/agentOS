package localui

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Owner is agentosd's localui.sock (localapi, P2-2w): the owner channel
// as the page reaches it. agentosd mints and checks the session tokens
// and counts wrong codes; the page holds no authority of its own
// (Security L1 on the P2-2w plan).
type Owner interface {
	Call(ctx context.Context, op string, args, out any) error
}

// Refused is a fixed code agentosd answered (localapi.Err*, Refused*).
type Refused string

func (r Refused) Error() string { return string(r) }

func refused(err error, code string) bool {
	var r Refused
	return errors.As(err, &r) && string(r) == code
}

// Socket calls agentosd's localui.sock at Path.
type Socket struct{ Path string }

// Call sends op with args and decodes the result into out.
func (s Socket) Call(ctx context.Context, op string, args, out any) error {
	err := bridgeclient.Client{Path: s.Path}.Call(ctx, op, args, out)
	if errors.Is(err, bridgeclient.ErrRefused) {
		return Refused(strings.TrimPrefix(err.Error(), "bridgeclient: "))
	}
	return err
}

// InProcess serves ops in this process, as agentosd's socket would: for
// tests and the simulator. Arguments and results go through JSON, and a
// refusal comes back as its fixed code.
type InProcess map[string]sockets.Handler

// Call runs op's handler.
func (p InProcess) Call(ctx context.Context, op string, args, out any) error {
	h := p[op]
	if h == nil {
		return Refused(sockets.ErrUnknownOp)
	}
	b, err := json.Marshal(args)
	if err != nil {
		return err
	}
	res, err := h(ctx, sockets.Peer{Kind: "localui"}, b)
	if err != nil {
		var c sockets.Code
		if errors.As(err, &c) {
			return Refused(c)
		}
		return Refused(sockets.ErrFailed)
	}
	if out == nil {
		return nil
	}
	b, err = json.Marshal(res)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// callTimeout bounds one call to agentosd from a page.
const callTimeout = 10 * time.Second

func (s *Server) call(ctx context.Context, op string, args, out any) error {
	o := s.getOwner()
	if o == nil {
		return errNoOwner
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return o.Call(ctx, op, args, out)
}

var errNoOwner = errors.New("localui: no owner channel")

// ownerStatus is the box's state before sign-in, ok false when agentosd
// does not answer.
func (s *Server) ownerStatus(ctx context.Context) (st localapi.Status, ok bool) {
	return st, s.call(ctx, localapi.OpStatus, struct{}{}, &st) == nil
}
