package sim

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Clock is the simulation's only time source. It moves only when the
// scheduler advances it.
type Clock struct{ t time.Time }

func (c *Clock) Now() time.Time          { return c.t }
func (c *Clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// policy is the broker's grant table as a projection of the journal: an
// account may be acted on while its latest settled grant change allows it.
// Grant changes are intents on the broker account (OP-5), applied by
// brokerExec when they run and rebuilt from the journal at every boot.
type policy struct {
	s      *sim
	grants map[string]bool
	// stale holds, per intent, the decision a dispatch check made before
	// its nested operation ran; only MutantStaleRecheck reads it.
	stale map[string]error
}

var errNoGrant = errors.New("no grant for this account")

func (p *policy) Check(_ context.Context, phase journal.Phase, in journal.Intent) error {
	if in.Account == journal.BrokerAccount {
		return nil
	}
	// Read the grant first, so a revoke nested below lands between this
	// read and the dispatched record: the window the engine's recheck
	// closes (OP-3).
	var err error
	if !p.grants[in.Account] {
		err = errNoGrant
	}
	if phase != journal.PhaseDispatch {
		return err
	}
	if prev, ok := p.stale[in.ID]; ok && p.s.cfg.Mutant == MutantStaleRecheck {
		// The engine checks again because something was journaled during
		// the first check; the mutant answers from before that change.
		delete(p.stale, in.ID)
		return prev
	}
	p.s.interleave("check " + in.ID)
	if p.s.cfg.Mutant == MutantNoRecheck {
		return nil
	}
	p.stale[in.ID] = err
	return err
}

// rebuild replays every grant change the journal shows as succeeded.
func (p *policy) rebuild(trail []journal.Record, intents map[string]journal.Intent) {
	p.grants = map[string]bool{}
	for _, r := range trail {
		if r.Type != journal.RecObserved || r.Result != journal.ResultSucceeded {
			continue
		}
		if in, ok := intents[r.ID]; ok && in.Account == journal.BrokerAccount {
			p.apply(in)
		}
	}
}

func (p *policy) apply(in journal.Intent) {
	target := fmt.Sprint(in.Params["target"])
	p.grants[target] = in.Action == journal.ActionGrantChange
}

// brokerExec runs grant changes. Its state lives only in the journal, so a
// change whose outcome was not journaled before a crash did not happen.
type brokerExec struct{ p *policy }

func (b brokerExec) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	b.p.apply(in)
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "applied"}
}

func (b brokerExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not in the rebuilt grant table"}
}

// service is a fake external service. It is the ground truth the journal is
// checked against: what it applied survives every broker crash. Its replies
// can be lost, and it can time out before or after applying.
type service struct {
	s       *sim
	applied map[string]int  // intent ID to effects applied
	keys    map[string]bool // attempt keys executed
	took    map[string]bool // attempt keys that took effect
}

func (v *service) Execute(_ context.Context, in journal.Intent, n int) journal.Outcome {
	s := v.s
	key := journal.AttemptKey(in.ID, n)
	// OP-4: the dispatched record is durable before the executor runs, so
	// the journal can over-report but never under-report an effect.
	if !s.durablyDispatched(in.ID, n) {
		s.violate("OP-4", "%s ran before its dispatched record was durable", key)
	}
	// OP-3: authority is rechecked at dispatch, so nothing runs on a grant
	// that is no longer held.
	if !s.pol.grants[in.Account] {
		s.violate("OP-3", "%s ran on %s with no grant held", key, in.Account)
	}
	if v.keys[key] {
		s.violate("OP-2", "attempt %s executed twice", key)
	}
	v.keys[key] = true
	s.interleave("exec " + in.ID)
	switch r := s.rng.Intn(20); {
	case r < 12:
		v.apply(in.ID, key)
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "ok " + key}
	case r < 14:
		v.apply(in.ID, key)
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "reply lost"}
	case r < 17:
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "rejected"}
	default:
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "timeout"}
	}
}

func (v *service) apply(id, key string) {
	v.took[key] = true
	v.applied[id]++
	if v.applied[id] > 1 {
		v.s.violate("OP-2", "%s took effect %d times", id, v.applied[id])
	}
}

// truth is what really happened to one attempt.
func (v *service) truth(id string, n int) journal.Result {
	if v.took[journal.AttemptKey(id, n)] {
		return journal.ResultSucceeded
	}
	return journal.ResultNotApplied
}

func (v *service) Reconcile(_ context.Context, in journal.Intent, n int) journal.Outcome {
	if v.s.rng.Intn(4) == 0 {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "service cannot tell"}
	}
	return journal.Outcome{Result: v.truth(in.ID, n), Evidence: "service record"}
}

func (v *service) Cancel(context.Context, journal.Intent, int) (bool, string) {
	return v.s.rng.Intn(2) == 0, "cancel requested"
}
