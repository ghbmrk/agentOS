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
	"sync/atomic"
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

// Spare is the most attempts past the first a call can spend under the
// owner's rule (SR3-7-f2): the router fails over at most len(routes)-1
// times in a class, and the class is not known before the vault process
// reads the call, so it is the largest of those over the owner's classes.
// An adoption only reorders the owner's routes, so the owner's rule alone
// sets it. Run keeps it current off the request path; Retries is
// Config.Retries. The zero Spare is unknown.
type Spare struct{ n atomic.Int64 } // the count plus one; 0 is unknown

// Retries is the count, or -1 if unknown: nothing read yet, the last read
// failed, or the owner's rule has no class.
func (s *Spare) Retries() int { return int(s.n.Load()) - 1 }

// Observe sets the count from the owner's rule.
func (s *Spare) Observe(owner routerule.Rule) {
	n := -1
	for _, rs := range owner {
		n = max(n, len(rs)-1)
	}
	s.n.Store(int64(n) + 1)
}

func (s *Spare) refresh(ctx context.Context, state func(context.Context) (RoutingState, error)) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := state(ctx)
	if err != nil {
		s.n.Store(0)
		return
	}
	s.Observe(st.Owner)
}

// Run reads the owner's rule from state (Routing.State) now and then every
// period until ctx ends. A read that fails or times out leaves the count
// unknown until the next one succeeds.
func (s *Spare) Run(ctx context.Context, state func(context.Context) (RoutingState, error), every time.Duration) {
	for {
		s.refresh(ctx, state)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
