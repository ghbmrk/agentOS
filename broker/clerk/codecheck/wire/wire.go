// Package wire is the checker's verify socket contract and its dial-only
// client (MIG-4-exit-c2): the owner channel links this and none of the
// checker that holds the seed.
package wire

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

	"github.com/ghbmrk/agentos/broker/kernel"
)

var (
	// ErrNoSeed: the checker holds no seed, so it verifies nothing.
	ErrNoSeed = errors.New("checker: no seed held")
	// ErrDown: the checker's socket could not be dialled.
	ErrDown = errors.New("checker: not running")
)

// PausedError refuses a check until the oldest wrong code in its bucket
// leaves the window.
type PausedError struct{ Until time.Time }

func (e *PausedError) Error() string { return "checker: too many wrong codes; checks are paused" }

// Request is POST /verify's body: the code, the last step the caller saw
// spent, the bucket (Counted), and the held steps a match approves.
type Request struct {
	Code    string            `json:"code"`
	After   int64             `json:"after"`
	Counted bool              `json:"counted"`
	Steps   []kernel.CodeStep `json:"steps,omitempty"`
}

// Result is POST /verify's answer: the step a matching code spent, and the
// approval of the request's steps, which the owner channel submits to the
// kernel (owner call approvecode).
type Result struct {
	Step     int64                `json:"step"`
	OK       bool                 `json:"ok"`
	Approval *kernel.CodeApproval `json:"approval,omitempty"`
}

// MaxBody bounds a request or an answer.
const MaxBody = 32 << 10

// PausedHeader carries a paused bucket's end, in Unix seconds.
const PausedHeader = "Agentos-Paused-Until"

// Client calls the verify socket.
type Client struct{ hc *http.Client }

// NewClient dials socket for every call. Its callers wait on it holding
// the owner channel's lock, so a hung checker delays them by at most 2 s.
func NewClient(socket string) *Client {
	return &Client{hc: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
			DisableCompression: true,
		},
		Timeout: 2 * time.Second,
	}}
}

// Verify asks the checker to check r. Errors are ErrNoSeed, *PausedError,
// ErrDown, or another transport or status error; a wrong code is a Result
// with OK false.
func (c *Client) Verify(r Request) (Result, error) {
	b, _ := json.Marshal(r)
	resp, err := c.hc.Post("http://localhost/verify", "application/json", bytes.NewReader(b))
	if err != nil {
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Op == "dial" {
			return Result{}, fmt.Errorf("%w: %v", ErrDown, err)
		}
		return Result{}, fmt.Errorf("checker: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var res Result
		if err := json.NewDecoder(io.LimitReader(resp.Body, MaxBody)).Decode(&res); err != nil {
			return Result{}, fmt.Errorf("checker: %w", err)
		}
		return res, nil
	case http.StatusTooManyRequests:
		until, _ := strconv.ParseInt(resp.Header.Get(PausedHeader), 10, 64)
		return Result{}, &PausedError{Until: time.Unix(until, 0)}
	case http.StatusServiceUnavailable:
		return Result{}, ErrNoSeed
	default:
		return Result{}, fmt.Errorf("checker: verify: %s", resp.Status)
	}
}
