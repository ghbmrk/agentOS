// Package checkersock is the checker's verify-socket contract and its
// client (SIM-split-wire). agentosd asks the checker to verify owner codes
// through it, so agentosd links this dial-only client and none of the
// checker that holds the seed; every dial is to a unix socket.
package checkersock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// ErrNoSeed means the unlock step has not handed the seed yet.
var ErrNoSeed = errors.New("checker: no seed held")

// ErrDown means the checker's socket could not be dialled.
var ErrDown = errors.New("checker: not running")

// PausedError refuses a verify until the oldest wrong code in its bucket
// leaves the window.
type PausedError struct{ Until time.Time }

func (e *PausedError) Error() string { return "checker: too many wrong codes; checks are paused" }

// Act is one act a code approves: its digest (checker.Act), and Held when
// its item waits out an undo window (REV-3): a held approval cannot be
// spent until the broker releases it (POST /release), which it does only
// once the owner's UNDO can no longer reach the item.
type Act struct {
	Act  string `json:"act"`
	Held bool   `json:"held,omitempty"`
}

// VerifyRequest and VerifyResponse are POST /verify's bodies.
type VerifyRequest struct {
	Code    string `json:"code"`
	After   int64  `json:"after"`
	Counted bool   `json:"counted"`
	Acts    []Act  `json:"acts"`
}

// ActsRequest is POST /revoke's body, the acts whose approvals are
// withdrawn, as an UNDO does, and POST /release's, the held acts whose
// approvals may now be spent.
type ActsRequest struct {
	Acts []string `json:"acts"`
}

// AllowRequest is POST /allow's body, the acts the broker lets through
// with no code (checker.Allow), and Before, the Unix millisecond after
// which the checker records none of them (AllowWithin).
type AllowRequest struct {
	Acts   []Act `json:"acts"`
	Before int64 `json:"before"`
}

// AllowWithin is how long after it is sent an allow may still be
// recorded: under the verify client's 2 s timeout, so an allow whose
// answer was lost is settled once Allow returns (Client.Allow).
const AllowWithin = time.Second

type VerifyResponse struct {
	Step int64 `json:"step"`
	OK   bool  `json:"ok"`
}

// MaxBody bounds a request or response body.
const MaxBody = 16 << 10

// PausedHeader carries a paused bucket's end, in Unix seconds.
const PausedHeader = "Agentos-Paused-Until"

// UnixClient returns an HTTP client whose every dial is to socket.
func UnixClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
			DisableCompression: true,
			IdleConnTimeout:    90 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
}

// Client is the broker's client for the verify socket, and the unlock
// step's for the hand socket's POST /verify.
type Client struct{ hc *http.Client }

// VerifyClient returns a client for POST /verify at socket. Its callers
// wait on it holding a lock (the owner channel's, the unlock step's), so
// a hung checker delays them by at most 2 s.
func VerifyClient(socket string) *Client {
	hc := UnixClient(socket)
	hc.Timeout = 2 * time.Second
	return &Client{hc: hc}
}

// VerifyTOTP asks the checker to verify code after step after and, on a
// match, approve acts. Errors are ErrNoSeed, *PausedError, ErrDown when
// the socket cannot be dialled, or another transport or status error.
func (c *Client) VerifyTOTP(code string, after int64, counted bool, acts ...Act) (int64, bool, error) {
	b, _ := json.Marshal(VerifyRequest{Code: code, After: after, Counted: counted, Acts: acts})
	resp, err := c.hc.Post("http://localhost/verify", "application/json", bytes.NewReader(b))
	if err != nil {
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Op == "dial" {
			return 0, false, fmt.Errorf("%w: %v", ErrDown, err)
		}
		return 0, false, fmt.Errorf("checker: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var vr VerifyResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, MaxBody)).Decode(&vr); err != nil {
			return 0, false, fmt.Errorf("checker: %w", err)
		}
		return vr.Step, vr.OK, nil
	case http.StatusTooManyRequests:
		until, _ := strconv.ParseInt(resp.Header.Get(PausedHeader), 10, 64)
		return 0, false, &PausedError{Until: time.Unix(until, 0)}
	case http.StatusServiceUnavailable:
		return 0, false, ErrNoSeed
	default:
		return 0, false, fmt.Errorf("checker: verify: %s", resp.Status)
	}
}

// Revoke withdraws acts' approvals, spent or not: only 204 means the
// checker holds none of them now.
func (c *Client) Revoke(acts ...string) error { return c.acts("revoke", acts) }

// Release lets held acts' approvals be spent, each within ApprovalTTL:
// only 204 means the checker released them.
func (c *Client) Release(acts ...string) error { return c.acts("release", acts) }

// Allow records allowed approvals for acts, which serve an irreversible
// act but never a secret one: only 204 means the checker recorded them.
// The checker records none after AllowWithin, and an Allow that got no
// answer returns no sooner, so the checker has settled it by then: a
// Revoke sent after the error withdraws whatever it recorded.
func (c *Client) Allow(acts ...Act) error {
	before := time.Now().Add(AllowWithin)
	err := c.post("allow", AllowRequest{Acts: acts, Before: before.UnixMilli()})
	var se statusError
	if err != nil && !errors.As(err, &se) {
		time.Sleep(time.Until(before))
	}
	return err
}

// statusError is a checker answer other than 204: the request was settled.
type statusError struct {
	op     string
	status string
}

func (e statusError) Error() string { return "checker: " + e.op + ": " + e.status }

func (c *Client) acts(op string, acts []string) error {
	return c.post(op, ActsRequest{Acts: acts})
}

func (c *Client) post(op string, body any) error {
	b, _ := json.Marshal(body)
	resp, err := c.hc.Post("http://localhost/"+op, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("checker: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBody))
	if resp.StatusCode != http.StatusNoContent {
		return statusError{op, resp.Status}
	}
	return nil
}
