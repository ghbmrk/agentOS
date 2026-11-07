// Package checker holds the key holders' side of the CH-4 checker's
// approvals (SIM-split): Act, the digest that binds an approval to the
// exact request a holder sends, and Redeemer, the holder's client for the
// checker's redeem socket. A key holder serves an irreversible act only
// once it redeems that act's approval there, so a compromised holder
// cannot approve a high-risk act alone.
//
// The checker process itself is cmd/agentos-checker, which serves the
// verify socket through clerk/codecheck; the hand socket's protocol is
// holder.Keeper's, and the verify client is package checkersock.
package checker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ghbmrk/agentos/broker/checker/checkersock"
)

// HandSocket is the hand socket's name inside the checker's run
// directory: the unlock step's (GET /state, PUT and DELETE /secret, and
// POST /verify for the unlock's own code).
const HandSocket = "hand.sock"

// PausedError refuses a verify until the oldest wrong code in its bucket
// leaves the window.
type PausedError = checkersock.PausedError

// Act names one request a holder sends upstream: the digest of the account
// whose login sends it (its credential name), and the request's host,
// method, path and body, each length-prefixed so no split of one field
// into the next gives the same act. Every holder shares one redeem socket,
// so the account is what keeps one account's approval from being spent by
// another's holder for the same bytes.
func Act(account, host, method, path string, body []byte) string {
	h := sha256.New()
	for _, f := range [][]byte{[]byte(account), []byte(host), []byte(method), []byte(path), body} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RedeemRequest is POST /redeem's body: the act whose approval is spent,
// and Secret when the request reveals a secret.
type RedeemRequest struct {
	Act    string `json:"act"`
	Secret bool   `json:"secret,omitempty"`
}

// Redeemer returns a key holder's client for the redeem socket: true means
// the act's approval was spent for this request; secret marks a request
// that reveals a secret, which no allowed approval serves. Only 204 is a
// yes and only 403 a no; any other answer is an error, which the holder
// refuses.
func Redeemer(socket string) func(ctx context.Context, act string, secret bool) (bool, error) {
	hc := checkersock.UnixClient(socket)
	return func(ctx context.Context, act string, secret bool) (bool, error) {
		b, _ := json.Marshal(RedeemRequest{Act: act, Secret: secret})
		req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/redeem", bytes.NewReader(b))
		if err != nil {
			return false, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return false, fmt.Errorf("checker: %w", err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, checkersock.MaxBody))
		switch resp.StatusCode {
		case http.StatusNoContent:
			return true, nil
		case http.StatusForbidden:
			return false, nil
		default:
			return false, fmt.Errorf("checker: redeem: %s", resp.Status)
		}
	}
}
