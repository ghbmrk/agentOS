package sipline

import (
	"context"

	"github.com/ghbmrk/agentos/broker/sipsign"
)

// Challenge is one digest challenge (RFC 3261 22.4) for one request.
type Challenge = sipsign.Challenge

// Signer answers a digest challenge with the Authorization (or
// Proxy-Authorization) value. The vault process holds the account password
// and answers (sipsign.Account behind sign.sock, reached with
// sipsign.Client), so the password never enters the process that runs the
// line (CRED-1).
type Signer interface {
	Sign(ctx context.Context, c Challenge) (string, error)
}
