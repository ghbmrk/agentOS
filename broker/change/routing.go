package change

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ghbmrk/agentos/broker/routerule"
)

// Router is the part of *route.Router the pipeline drives (ADP-4).
type Router interface {
	Rule() routerule.Rule
	SetRule(routerule.Rule) error
	Candidate() routerule.Rule
}

// RoutingTarget applies routing/rule.json to the model router. The router
// itself only proposes (Candidate); SetRule is called only here, when the
// pipeline adopts or reverts.
type RoutingTarget struct{ Router Router }

func (t RoutingTarget) Current() (Tree, error) {
	return Tree{RoutingPath: canonicalJSON(t.Router.Rule())}, nil
}

func (t RoutingTarget) Apply(files Tree) error {
	b, ok := files[RoutingPath]
	if !ok || len(files) != 1 {
		return errors.New("change: routing needs exactly " + RoutingPath)
	}
	var r routerule.Rule
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	return t.Router.SetRule(r)
}

// ProposeRouting turns the router's measured proposal into a candidate and
// runs it through the pipeline (ADP-4, CAP-9). It returns ok=false when the
// proposal equals the active rule.
func (p *Pipeline) ProposeRouting(ctx context.Context, r Router) (Report, bool, error) {
	next := canonicalJSON(r.Candidate())
	p.mu.Lock()
	same := string(p.st.Active[RoutingPath]) == string(next)
	p.mu.Unlock()
	if same {
		return Report{}, false, nil
	}
	rep, err := p.Propose(ctx, Candidate{Source: Local, Origin: "router", Files: Tree{RoutingPath: next}})
	return rep, true, err
}
