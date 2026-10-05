package modelroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/routerule"
)

// RoutingPath is the routing socket's one path.
const RoutingPath = "/routing"

// ErrRoutingRefused is a rule the vault process will not take: not a
// reordering of the owner's -rule. Retrying it cannot succeed. Any other
// error (unreachable, a failed save) may pass.
var ErrRoutingRefused = errors.New("routing: vault process refused the rule")

// RoutingState is the vault process's active routing rule, its router's
// measured proposal (route.Router.Candidate), and the owner's configured
// rule (-rule), of which every adopted rule is a reordering.
type RoutingState struct {
	Rule      routerule.Rule `json:"rule"`
	Candidate routerule.Rule `json:"candidate"`
	Owner     routerule.Rule `json:"owner"`
}

// Routing reads and sets the vault process's active routing rule over its
// routing socket (W3, potency PW4 on #90), for the change pipeline's
// routing target in agentosd. The vault process accepts only a reordering
// of the owner's configured routes.
type Routing struct{ c *http.Client }

// NewRouting returns a Routing for the routing socket at path.
func NewRouting(path string) *Routing {
	return &Routing{c: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		Proxy: nil,
	}}}
}

func routingURL() string {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: RoutingPath} // over the Unix socket
	return u.String()
}

// State returns the active rule and the router's proposal.
func (r *Routing) State(ctx context.Context) (RoutingState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, routingURL(), nil)
	if err != nil {
		return RoutingState{}, err
	}
	resp, err := r.c.Do(req)
	if err != nil {
		return RoutingState{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return RoutingState{}, fmt.Errorf("routing: vault process answered %d", resp.StatusCode)
	}
	var st RoutingState
	if err := json.NewDecoder(io.LimitReader(resp.Body, 3*MaxRule+64)).Decode(&st); err != nil {
		return RoutingState{}, err
	}
	if len(st.Rule) == 0 {
		return RoutingState{}, fmt.Errorf("routing: vault process has no rule")
	}
	return st, nil
}

// Set adopts rule in the vault process; an empty rule is the owner's
// -rule. A refusal is ErrRoutingRefused, with its reason.
func (r *Routing) Set(ctx context.Context, rule routerule.Rule) error {
	b, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	if len(b) > MaxRule {
		return fmt.Errorf("routing: rule over %d bytes", MaxRule)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, routingURL(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrRoutingRefused, strings.TrimSpace(string(msg)))
	}
	return fmt.Errorf("routing: vault process answered %d", resp.StatusCode)
}
