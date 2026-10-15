package modelroute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// RouteControl is agentosd's client of the vault process's provider control
// socket (agentos-egress, egress K28). It is a vm.Services: opening a
// provider worker's services opens its route socket and returns the
// directory that holds only that socket, which the machine mounts at
// /run/agentos; closing removes it. An open that is refused (vault locked,
// not a provider worker) is an error, so the worker does not start without
// its route; a locked vault is ErrVaultLocked. Like the other clients here
// it dials only the configured unix socket and holds no credential.
type RouteControl struct{ c *http.Client }

// NewRouteControl returns a RouteControl for the provider control socket at
// path.
func NewRouteControl(path string) *RouteControl {
	return &RouteControl{c: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		Proxy: nil,
	}}}
}

func (c *RouteControl) do(verb, id string) (*http.Response, error) {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/" + verb, RawQuery: url.Values{"machine": {id}}.Encode()} // over the Unix socket
	return c.c.Post(u.String(), "text/plain", nil)
}

// call posts verb for id and returns the reply body, mapping any 503 to
// ErrVaultLocked (and one that is not the locked vault's to ErrRouteBusy
// too: stalled or contended) and a missing plan login to ErrNoPlanLogin.
func (c *RouteControl) call(verb, id string, max int64) ([]byte, error) {
	resp, err := c.do(verb, id)
	if err != nil {
		return nil, fmt.Errorf("worker route for %s: %w", id, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusServiceUnavailable:
		if !isLocked(string(body)) {
			return nil, fmt.Errorf("worker route for %s: %w (%w)", id, ErrRouteBusy, ErrVaultLocked)
		}
		return nil, fmt.Errorf("worker route for %s: %w", id, ErrVaultLocked)
	}
	if isNoLogin(string(body)) {
		return nil, fmt.Errorf("worker route for %s: %w", id, ErrNoPlanLogin)
	}
	return nil, fmt.Errorf("worker route for %s: %s", id, strings.TrimSpace(string(body)))
}

// Open opens id's route and returns its directory. The directory must be
// absolute, clean and named for id, whatever the reply says (egress K28).
func (c *RouteControl) Open(id string) (string, error) {
	body, err := c.call("open", id, 4<<10)
	if err != nil {
		return "", err
	}
	var out struct{ Dir string }
	if err := json.Unmarshal(body, &out); err != nil || out.Dir == "" {
		return "", fmt.Errorf("worker route for %s: unreadable reply", id)
	}
	if !filepath.IsAbs(out.Dir) || filepath.Clean(out.Dir) != out.Dir || filepath.Base(out.Dir) != id {
		return "", fmt.Errorf("worker route for %s: reply names %q, not this worker's directory", id, out.Dir)
	}
	return out.Dir, nil
}

// Seed returns the vm seed the vault process minted for provider worker id
// (egress PlanLogins.Seed: its placeholder auth.json), for the broker to put
// in the machine before it starts and opens its route (egress K28, #1015).
func (c *RouteControl) Seed(id string) (map[string][]byte, error) {
	body, err := c.call("seed", id, 64<<10)
	if err != nil {
		return nil, err
	}
	var out map[string][]byte
	if err := json.Unmarshal(body, &out); err != nil || len(out) == 0 {
		return nil, fmt.Errorf("worker route for %s: unreadable seed", id)
	}
	return out, nil
}

// PoolReading is one plan pool as the vault process last read it from the
// provider's response headers on the broker's own connection (egress
// QuotaReading): ResetAt is unix seconds, zero when the provider gave none.
type PoolReading struct {
	At          time.Time
	Pool        string
	UsedPercent float64
	ResetAt     int64
	Exhausted   bool
}

// PlanUsage is a provider's plan usage across every worker route (egress
// UsageSnapshot): its pools, and the last refused login (zero when none).
type PlanUsage struct {
	Pools        []PoolReading
	LoginRefused time.Time
}

// Usage reads provider's plan usage (RES-5). An unreadable reply is an
// error, never an empty pool list.
func (c *RouteControl) Usage(provider string) (PlanUsage, error) {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/usage", RawQuery: url.Values{"provider": {provider}}.Encode()}
	resp, err := c.c.Post(u.String(), "text/plain", nil)
	if err != nil {
		return PlanUsage{}, fmt.Errorf("plan usage for %s: %w", provider, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return PlanUsage{}, fmt.Errorf("plan usage for %s: %s", provider, strings.TrimSpace(string(body)))
	}
	var out PlanUsage
	if err := json.Unmarshal(body, &out); err != nil {
		return PlanUsage{}, fmt.Errorf("plan usage for %s: unreadable reply", provider)
	}
	for _, p := range out.Pools {
		if p.Pool == "" || p.At.IsZero() {
			return PlanUsage{}, fmt.Errorf("plan usage for %s: unreadable reply", provider)
		}
	}
	return out, nil
}

// Close closes id's route; a failure leaves the route to the vault
// process's own shutdown.
func (c *RouteControl) Close(id string) {
	if resp, err := c.do("close", id); err == nil {
		resp.Body.Close()
	}
}
