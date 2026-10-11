package modelroute

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HeaderState marks the broker's state request on the model socket (OP-9
// C2). A guest cannot send it: Forward drops every Agentos- header the
// guest sent, so only agentosd's probe reaches the vault process with it.
const HeaderState = "Agentos-State"

// ModelState is what agentosd learns about the model route for STATUS
// (OP-9 C2): three yes-or-no facts, never a grant's machine or provider,
// a key, or anything else from the vault. The zero value is the stale or
// failed state: not reachable, nothing granted, nothing open.
type ModelState struct {
	// Reachable: the vault process answered on its model socket. It is
	// the probe's own finding, never the vault process's word.
	Reachable bool `json:"-"`
	// Granted: some machine has a model provider granted (-grant).
	Granted bool `json:"granted"`
	// Open: the vault is open, so the model route serves.
	Open bool `json:"open"`
}

// maxState bounds the vault process's state answer.
const maxState = 1 << 10

// NewStateProbe returns a probe of the vault process's model socket at
// path. Each call asks once and waits at most 2 seconds or ctx. Anything
// but a 200 with a well-formed answer is the zero ModelState, so a socket
// file with nothing answering, a hung process or a malformed answer never
// reads as granted or open.
func NewStateProbe(path string) func(context.Context) ModelState {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true,
		Proxy:             nil,
	}}
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/"} // over the Unix socket
	return func(ctx context.Context) ModelState {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return ModelState{}
		}
		req.Header.Set(HeaderState, "1")
		resp, err := c.Do(req)
		if err != nil {
			return ModelState{}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ModelState{}
		}
		var st ModelState
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxState)).Decode(&st); err != nil {
			return ModelState{}
		}
		st.Reachable = true
		return st
	}
}
