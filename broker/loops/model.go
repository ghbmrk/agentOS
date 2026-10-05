package loops

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/route"
)

// EvalModel builds the model access a counterfactual replay gets for one
// tree (replay.Config.Model; LOOP-5, replay ASSUMPTIONS R2 K1 and K3).
//
// Only the tree's routing rule, the order among routes, comes from the tree
// under test: that is the candidate being measured. Which providers exist,
// which are granted, and which may see private data are broker
// configuration, and every replay is private (it replays the owner's
// tasks), so a rule naming an ungranted provider, or a private case sent to
// a provider not marked PrivateOK, is refused by the router as for a guest.
// Calls go to Upstream, the egress the broker set aside for evaluation, and
// are metered by the replay plane against the spare budget meter
// (replay.Config.Meter = the scheduler's Spare).
//
// Routing decisions go only to Calls, which keeps counts; no builder or
// candidate can read them (K3).
type EvalModel struct {
	Providers []route.Provider
	// Granted reports whether the owner granted a provider for the guest's
	// model calls; replay uses the same grants and never more (ADP-4).
	Granted   func(provider string) bool
	PrivateOK map[string]bool
	// Upstream is the egress handler for evaluation calls.
	Upstream http.Handler
	// Active returns the active rule, used when a tree has none.
	Active func() route.Rule
	// MaxOutputTokens is the per-call output ceiling (route Config).
	MaxOutputTokens int
	// Calls counts evaluation decisions for the digest and the
	// scheduler's cost; nil discards them.
	Calls *CallCount
}

// EvalMachine is the machine name evaluation calls are made under in the
// router's decisions.
const EvalMachine = "eval"

// Handler returns the model handler for a replay of tree t. A tree whose
// rule cannot be read or names an undeclared provider gets a handler that
// refuses every call, so the candidate fails rather than falling back to
// another rule.
func (e EvalModel) Handler(t change.Tree) http.Handler {
	rule, err := e.rule(t)
	if err == nil {
		var r *route.Router
		r, err = route.New(route.Config{
			Providers: e.Providers,
			Rule:      rule,
			Granted: func(_, provider string) bool {
				return e.Granted != nil && e.Granted(provider)
			},
			PrivateOK:       e.PrivateOK,
			Label:           func(string) string { return "private" },
			Upstream:        func(string) http.Handler { return e.Upstream },
			Audit:           e.Calls.add,
			MaxOutputTokens: e.MaxOutputTokens,
		})
		if err == nil {
			return r.Handler(EvalMachine)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
			"message": "the routing rule under evaluation is not usable", "type": "invalid_request_error"}})
	})
}

func (e EvalModel) rule(t change.Tree) (route.Rule, error) {
	if b, ok := t[change.RoutingPath]; ok {
		var r route.Rule
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		return r, nil
	}
	if e.Active == nil {
		return nil, errors.New("loops: no routing rule")
	}
	return e.Active(), nil
}

// CallCount keeps counts of evaluation model calls: no content, routes,
// or reasons, so nothing a builder could learn the hidden suite from (K3).
type CallCount struct {
	mu                    sync.Mutex
	served, denied, other int64
}

func (c *CallCount) add(d route.Decision) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch d.Outcome {
	case route.Served:
		c.served++
	case route.Denied:
		c.denied++
	default:
		c.other++
	}
}

// Counts returns how many evaluation calls were served and refused.
func (c *CallCount) Counts() (served, denied int64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.served, c.denied
}
