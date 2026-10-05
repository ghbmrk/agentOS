// Package bridgeclient is the modem bridge's side of owner.sock
// (bridgeproto; P2-3w). It lives apart from bridgeproto so agentosd,
// which links bridgeproto, links no network client (ARC-2).
package bridgeclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
)

// Client is the bridge's side of owner.sock: one request per connection,
// the way agentosd's owner socket expects (B11).
type Client struct {
	Path string
}

// MaxAnswer bounds one answer from agentosd.
const MaxAnswer = 64 << 10

// ErrRefused is a call agentosd answered with an error code; the code is
// in the error's text.
var ErrRefused = errors.New("bridgeclient: refused")

type refused string

func (r refused) Error() string        { return "bridgeclient: " + string(r) }
func (r refused) Is(target error) bool { return target == ErrRefused }

// Call sends op with args and decodes the result into out (nil: none).
func (c Client) Call(ctx context.Context, op string, args, out any) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(bridgeproto.OutboxWait + 10*time.Second))
	b, err := json.Marshal(map[string]any{"op": op, "args": args})
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err
	}
	// An answer is one line, bounded: an item's text is at most
	// bridgeproto.MaxText bytes.
	line, err := bufio.NewReader(io.LimitReader(conn, MaxAnswer)).ReadBytes('\n')
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	var resp struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return refused(resp.Error)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, out)
}
