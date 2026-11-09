package sim

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// stopsHold judges a log against the narrowings in it (KRN-5, KRN-7, KEY-8,
// LOG-4): once a STOP, a task's end, a revoke or an erase folds, no step of
// a plan it reached that was not yet sent is dispatched afterwards, whatever
// folds next (a RESUME before any tick included); and no dispatch goes out
// for a task that is not live. A step the owner retried is exempt, since
// RETRY outlives the task (KRN-5). Which plans a STOP, an end or a revoke
// reaches is worked out here from the entries, not taken from the fold; an
// erase's are those its fold cancelled (LOG-4's lineage rule is the erase
// sim's to judge).
func stopsHold(anchors []key.PublicKey, es []kernel.Entry) error {
	s := kernel.NewState(anchors)
	stopped := map[string]string{} // plan -> the narrowing that reached it
	retried := map[[2]any]bool{}
	open := func(p *kernel.PlanState) bool { return p.Status == kernel.SPending || p.Status == kernel.SActive }
	reach := func(why string, hit func(*kernel.PlanState) bool) {
		for _, id := range s.Order {
			if p := s.Plans[id]; open(p) && stopped[id] == "" && hit(p) {
				stopped[id] = why
			}
		}
	}
	for _, e := range es {
		var b struct {
			Plan  string `json:"plan"`
			Index int    `json:"index"`
			Task  string `json:"task"`
			ID    key.ID `json:"id"`
		}
		_ = json.Unmarshal(e.Body, &b)
		var was map[string]bool // open plans, before an erase folds
		switch e.Type {
		case kernel.TStop:
			reach("a STOP", func(*kernel.PlanState) bool { return true })
		case kernel.TTaskEnded:
			reach("its task's end", func(p *kernel.PlanState) bool { return p.Plan.Task() == b.Task })
		case kernel.TKeyRevoked:
			reach("a revoke", func(p *kernel.PlanState) bool {
				v, err := kernel.VerifyPlan(p.Plan, kernel.PlanOwners(s, anchors, p.Plan.Key))
				return err == nil && slices.Contains(v.IDs, b.ID)
			})
		case kernel.TSubjectErased:
			was = map[string]bool{}
			for _, id := range s.Order {
				was[id] = open(s.Plans[id])
			}
		case kernel.TStepRetried:
			retried[[2]any{b.Plan, b.Index}] = true
		case kernel.TStepDispatch:
			p := s.Plans[b.Plan]
			if p == nil || retried[[2]any{b.Plan, b.Index}] {
				break
			}
			if why := stopped[b.Plan]; why != "" {
				return fmt.Errorf("invariant: entry %d dispatched step %d of %s after %s reached it", e.Seq, b.Index, b.Plan, why)
			}
			if t := key.TaskOf(p.Plan.Key); t != "" {
				if _, live := s.Task(t, e.At); !live {
					return fmt.Errorf("invariant: entry %d dispatched step %d of %s for task %s, not live", e.Seq, b.Index, b.Plan, t)
				}
			}
		}
		if err := s.Apply(e); err != nil {
			return err
		}
		for id, o := range was {
			if p := s.Plans[id]; o && p.Status == kernel.SCancelled && p.Cancel == kernel.CErased {
				stopped[id] = "an erase"
			}
		}
	}
	return nil
}
