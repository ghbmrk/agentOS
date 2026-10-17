// Package anchorsock is update.Store.Anchor over the vault process's verify
// socket. It is apart from package update so agentosd links net/http only
// once W5b wires it (daemon TestAgentosdLinksNoInference).
package anchorsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
)

// SocketAnchor is update.Store.Anchor over the vault process's verify socket
// (SR3-6f-2c): the TPM counter agentos-egress keeps for the store's
// outside-attestor record. There is no request that lowers it.
type SocketAnchor struct {
	c *http.Client
}

// Paths on the verify socket; agentos-egress serves them.
const (
	AnchorPath      = "/update-anchor"
	AnchorRaisePath = "/update-anchor/raise"
)

// AnswerHeader names which conflict a 409 is (SR3-6-f5b): AnswerMissing,
// a counter that was defined and is gone (update.ErrAnchorMissing), or
// AnswerElsewhere, a counter on a chip this PC lacks
// (update.ErrAnchorElsewhere). A 409 without it is a plain error.
const (
	AnswerHeader    = "Anchor-Answer"
	AnswerMissing   = "missing"
	AnswerElsewhere = "elsewhere"
)

// AnchorState is the answer to both requests. Anchored false means this
// PC has no TPM (update.ErrNoAnchor); a counter that was defined and is gone is
// an error status, never this.
type AnchorState struct {
	Anchored bool   `json:"anchored"`
	Count    uint64 `json:"count,omitempty"`
}

// NewSocketAnchor talks to the vault process at the socket path.
func NewSocketAnchor(path string) *SocketAnchor {
	return NewAnchorClient(&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		Proxy: nil,
	}})
}

// NewAnchorClient uses c, whose transport reaches the vault process.
func NewAnchorClient(c *http.Client) *SocketAnchor { return &SocketAnchor{c: c} }

func (a *SocketAnchor) Read() (uint64, error) {
	st, err := a.do(http.MethodGet, AnchorPath)
	if err != nil {
		return 0, err
	}
	return st.Count, nil
}

func (a *SocketAnchor) Raise() error {
	_, err := a.do(http.MethodPost, AnchorRaisePath)
	return err
}

func (a *SocketAnchor) do(method, path string) (AnchorState, error) {
	req, err := http.NewRequest(method, "http://localhost"+path, nil) // over the Unix socket
	if err != nil {
		return AnchorState{}, err
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return AnchorState{}, fmt.Errorf("update: anchor: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return AnchorState{}, fmt.Errorf("update: anchor: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("update: anchor: %s: %s", resp.Status, bytesTrim(body))
		var typed error
		switch {
		case resp.StatusCode == http.StatusServiceUnavailable:
			typed = update.ErrAnchorLocked
		case resp.StatusCode == http.StatusConflict && resp.Header.Get(AnswerHeader) == AnswerMissing:
			typed = update.ErrAnchorMissing
		case resp.StatusCode == http.StatusConflict && resp.Header.Get(AnswerHeader) == AnswerElsewhere:
			typed = update.ErrAnchorElsewhere
		}
		if typed != nil {
			return AnchorState{}, fmt.Errorf("%w (%w)", err, typed)
		}
		return AnchorState{}, err
	}
	var st AnchorState
	if err := json.Unmarshal(body, &st); err != nil {
		return AnchorState{}, fmt.Errorf("update: anchor: malformed answer: %w", err)
	}
	if !st.Anchored {
		if st.Count != 0 {
			return AnchorState{}, errors.New("update: anchor: malformed answer: a count without an anchor")
		}
		return AnchorState{}, update.ErrNoAnchor
	}
	return st, nil
}

func bytesTrim(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return string(b)
}
