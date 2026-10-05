package modelroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// VerifyRequest asks the vault process to check a code-generator code for
// the owner channel (egress K7). After is the channel's last accepted step.
// Counted is false for the channel's silent checks of codes in chat (O5),
// which the vault process bounds apart from the rest.
type VerifyRequest struct {
	Code    string `json:"code"`
	After   int64  `json:"after"`
	Counted bool   `json:"counted"`
}

// HeaderPausedUntil carries, on a 429 from the verify socket, when checks
// of that kind resume (RFC 3339).
const HeaderPausedUntil = "Agentos-Paused-Until"

// VerifyFailure says why the vault process did not check a code.
type VerifyFailure int

const (
	VerifyDown   VerifyFailure = iota // not reached, or it failed; nothing was checked
	VerifyLocked                      // the vault is not open
	VerifyPaused                      // too many wrong codes until Until
	VerifyLost                        // sent, but no answer: the code may have been spent
)

// VerifyError is returned when no answer says whether the code matched.
type VerifyError struct {
	Kind  VerifyFailure
	Until time.Time
}

func (e *VerifyError) Error() string {
	return [...]string{"vault process down", "vault locked", "verify paused", "verify answer lost"}[e.Kind]
}

// VerifyResult is the vault process's answer: whether the code matched and
// the step it matched. It never carries the seed.
type VerifyResult struct {
	OK   bool  `json:"ok"`
	Step int64 `json:"step"`
}

// Verifier is the owner channel's high-tier check over the
// vault process's verify socket, so the code-generator seed stays in the
// vault process and agentosd holds none (egress K7).
type Verifier struct{ c *http.Client }

// NewVerifier returns a Verifier for the verify socket at path. The channel
// waits on it while holding its lock, so the timeout is short: a hung vault
// process delays STOP by at most that much.
func NewVerifier(path string) *Verifier {
	return &Verifier{c: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		Proxy: nil,
	}}}
}

// VerifyTOTP checks code for the owner channel; agentosd adapts it to
// owner.Verifier. Anything but a well-formed answer is a *VerifyError.
func (v *Verifier) VerifyTOTP(code string, after int64, counted bool) (int64, bool, error) {
	body, _ := json.Marshal(VerifyRequest{Code: code, After: after, Counted: counted})
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/verify"} // over the Unix socket
	resp, err := v.c.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return 0, false, &VerifyError{Kind: VerifyDown}
		}
		return 0, false, &VerifyError{Kind: VerifyLost}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return 0, false, &VerifyError{Kind: VerifyLocked}
	case http.StatusTooManyRequests:
		until, err := time.Parse(time.RFC3339, resp.Header.Get(HeaderPausedUntil))
		if err != nil {
			until = time.Now().Add(10 * time.Minute)
		}
		return 0, false, &VerifyError{Kind: VerifyPaused, Until: until}
	default:
		return 0, false, &VerifyError{Kind: VerifyDown}
	}
	var res VerifyResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&res); err != nil {
		return 0, false, &VerifyError{Kind: VerifyLost}
	}
	return res.Step, res.OK, nil
}
