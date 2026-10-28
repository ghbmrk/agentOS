package kernelsock

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// Keeper is the keeper's recovery-key rotation one-shot on its socket
// (agentos-keeper-rotate.socket, REC-4 route A, brief MIG-4-recovery-r
// decision 7): one JSON request, the write half closed, one word back.
// agentosd runs as root and dials as root, which the socket
// (root:agentos-owner, 0660) admits; only a socket whose peer is UID (root
// in production) is spoken to. It carries the Owner Card factor and the
// new recovery key, so it sits with the owner seam's other root-side
// client and writes the request in one slice it clears.
type Keeper struct {
	Socket string
	UID    int
}

// keeperFor bounds one rotation: the keeper stretches a passphrase.
const keeperFor = time.Minute

// maxKeeperWord bounds the keeper's answer.
const maxKeeperWord = 64

// ErrNotKeeper: the socket's peer is not the keeper's uid; nothing was
// sent.
var ErrNotKeeper = errors.New("kernelsock: the rotation socket is not the keeper's; nothing was sent")

// Rotate sends one rotation request, the agentos-enroll -rotate-recovery
// rotateRequest: factor ("passphrase" or "recovery"), secret, the new key
// next and the kernel's approval. It returns the keeper's word ("ok",
// "factor", "approval", "stale", "busy", "request" or "store"). An error is
// a request not sent, or one whose answer was lost after it was sent.
func (k Keeper) Rotate(ctx context.Context, factor string, secret, next, approval []byte) (string, error) {
	req := keeperRequest(factor, secret, next, approval)
	defer clear(req)
	ctx, cancel := context.WithTimeout(ctx, keeperFor)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", k.Socket)
	if err != nil {
		return "", ErrUnreachable
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != k.UID {
		return "", ErrNotKeeper
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(req); err != nil {
		return "", ErrLost
	}
	if c, ok := conn.(interface{ CloseWrite() error }); !ok || c.CloseWrite() != nil {
		return "", ErrLost
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxKeeperWord)).ReadString('\n')
	if err != nil {
		return "", ErrLost
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// keeperRequest builds the request in one slice: the secret goes in as
// base64 and the new key as hex, appended straight in, so no string copy
// of either is made. factor is one of two fixed words (the caller checks).
func keeperRequest(factor string, secret, next, approval []byte) []byte {
	b := make([]byte, 0, 128+base64.StdEncoding.EncodedLen(len(secret))+hex.EncodedLen(len(next))+base64.StdEncoding.EncodedLen(len(approval)))
	b = append(b, `{"factor":"`...)
	b = append(b, factor...)
	b = append(b, `","secret":"`...)
	b = base64.StdEncoding.AppendEncode(b, secret)
	b = append(b, `","next":"`...)
	b = hex.AppendEncode(b, next)
	b = append(b, `","approval":"`...)
	b = base64.StdEncoding.AppendEncode(b, approval)
	return append(b, `"}`...)
}
