package modelroute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// VerifyRequest asks the vault process to check a code-generator code for
// the owner channel (egress K7). After is the channel's last accepted step.
type VerifyRequest struct {
	Code  string `json:"code"`
	After int64  `json:"after"`
}

// VerifyResult is the vault process's answer: whether the code matched and
// the step it matched. It never carries the seed.
type VerifyResult struct {
	OK   bool  `json:"ok"`
	Step int64 `json:"step"`
}

// Verifier is the owner channel's high-tier check (owner.Verifier) over the
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

// VerifyTOTP implements owner.Verifier. Anything but a well-formed answer
// is an error: the vault is locked, the process is down, or it refuses
// after too many wrong codes.
func (v *Verifier) VerifyTOTP(code string, after int64) (int64, bool, error) {
	body, _ := json.Marshal(VerifyRequest{Code: code, After: after})
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/verify"} // over the Unix socket
	resp, err := v.c.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("vault process: %s", resp.Status)
	}
	var res VerifyResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&res); err != nil {
		return 0, false, err
	}
	return res.Step, res.OK, nil
}
