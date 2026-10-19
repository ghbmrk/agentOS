// Package noticesock reads the vault process's notice socket, so the one
// HTTP client agentosd needs for owner notices (P2-2w c4e4 s2b, #1421)
// lives here and cmd/agentosd links no net/http itself (ARC-2).
//
// The vault process serves GET /notices?boot=B&after=N as a long poll on a
// unix socket (notice.Socket). Every dial here is to that one socket, and
// the reply is decoded into notice.Batch; nothing it carries is returned
// as free text.
package noticesock

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/notice"
)

// maxGet bounds one poll; the vault's own wait is 25 s.
const maxGet = 40 * time.Second

// maxReply bounds what one reply may carry.
const maxReply = 1 << 16

// Client asks the vault process's notice socket for notices.
type Client struct {
	Socket string
	// Timeout overrides maxGet when positive (tests).
	Timeout time.Duration

	hc *http.Client
}

// New returns a client for the notice socket at path.
func New(path string) *Client {
	c := &Client{Socket: path}
	c.hc = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true,
	}}
	return c
}

// Get asks once for the notices after seq `after` of boot `boot`.
func (c *Client) Get(ctx context.Context, boot string, after uint64) (notice.Batch, error) {
	var b notice.Batch
	d := maxGet
	if c.Timeout > 0 {
		d = c.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	q := url.Values{"boot": {boot}, "after": {fmt.Sprint(after)}}
	// localhost: the host is never resolved (the dial ignores it) and is the
	// one the endpoint scan (DEP-2) accepts for a unix-socket client.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/notices?"+q.Encode(), nil)
	if err != nil {
		return b, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return b, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return b, fmt.Errorf("notice socket: %s", resp.Status)
	}
	err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxReply)).Decode(&b)
	return b, err
}
