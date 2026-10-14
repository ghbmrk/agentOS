package check

// A seeded world for generated journals: a real engine over an in-memory
// medium that crashes (sometimes tearing a line), plain effects that name
// grants, owner revocations of those grants, STOP, erasure and quality notes.
//
// REQ: OP-3, OP-4, OP-5, CAP-3

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

var ctx = context.Background()

var errCrash = errors.New("crash")

// crashing fails every append after budget; the failing one may be torn.
type crashing struct {
	*journal.MemStore
	budget  int
	torn    bool
	crashed bool
}

func (s *crashing) Append(line []byte) error {
	if s.crashed {
		return errCrash
	}
	if s.budget == 0 {
		s.crashed = true
		if s.torn {
			s.MemStore.Append(line[:len(line)/2])
		}
		return errCrash
	}
	s.budget--
	return s.MemStore.Append(line)
}

// policy refuses effects whose grant is revoked: at authorization always,
// and again at dispatch unless it is lax (the OP-3 defect to catch).
type policy struct {
	revoked map[string]bool
	lax     bool
}

const (
	honest = false
	lax    = true
)

func (p *policy) Check(_ context.Context, phase journal.Phase, in journal.Intent) error {
	if p.lax && phase == journal.PhaseDispatch {
		return nil
	}
	if in.GrantRef != "" && !journal.Narrowing(in) && p.revoked[in.GrantRef] {
		return fmt.Errorf("grant %s revoked", in.GrantRef)
	}
	return nil
}

// grants executes revocations.
type grants struct{ revoked map[string]bool }

func (g grants) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	g.revoked[in.GrantRef] = true
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "revoked"}
}

func (g grants) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	if g.revoked[in.GrantRef] {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "revoked"}
	}
	return journal.Outcome{Result: journal.ResultNotApplied}
}

// service applies effects, reporting some outcomes as unknown.
type service struct {
	rng  *rand.Rand
	real map[string]journal.Result
}

func (s *service) Execute(_ context.Context, in journal.Intent, n int) journal.Outcome {
	r := []journal.Result{journal.ResultSucceeded, journal.ResultNotApplied}[s.rng.Intn(2)]
	s.real[journal.AttemptKey(in.ID, n)] = r
	if s.rng.Intn(4) == 0 {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "timeout canary"}
	}
	return journal.Outcome{Result: r, Evidence: "receipt canary"}
}

func (s *service) Reconcile(_ context.Context, in journal.Intent, n int) journal.Outcome {
	if r, ok := s.real[journal.AttemptKey(in.ID, n)]; ok && s.rng.Intn(3) > 0 {
		return journal.Outcome{Result: r, Evidence: "reconciled canary"}
	}
	return journal.Outcome{Result: journal.ResultUnknown}
}

type world struct {
	t     *testing.T
	rng   *rand.Rand
	mem   *journal.MemStore
	store *crashing
	pol   *policy
	execs map[string]journal.Executor
	eng   *journal.Engine
}

func newWorld(t *testing.T, seed int64, laxPolicy bool) *world {
	rng := rand.New(rand.NewSource(seed))
	revoked := map[string]bool{}
	w := &world{t: t, rng: rng, mem: &journal.MemStore{}, pol: &policy{revoked: revoked, lax: laxPolicy},
		execs: map[string]journal.Executor{
			"svc":    &service{rng: rng, real: map[string]journal.Result{}},
			"grants": grants{revoked},
		}}
	w.restart()
	return w
}

func (w *world) restart() {
	w.t.Helper()
	for {
		w.store = &crashing{MemStore: w.mem, budget: w.rng.Intn(60) + 1, torn: w.rng.Intn(2) == 0}
		e, err := journal.Open(w.store, w.pol, w.execs, func(s string) string { return s })
		if errors.Is(err, errCrash) || (err != nil && errors.Is(err, journal.ErrBroken)) {
			continue
		}
		if err != nil {
			w.t.Fatalf("open: %v", err)
		}
		w.eng = e
		return
	}
}

var (
	effectIDs = []string{"e0", "e1", "e2", "e3", "e4", "e5"}
	grantIDs  = []string{"g0", "g1", "g2"}
)

func (w *world) intentFor(id string) journal.Intent {
	if id[0] == 'r' {
		return journal.Intent{ID: id, Origin: "owner", Account: journal.BrokerAccount,
			Action: journal.ActionGrantRevoke, GrantRef: "g" + id[1:], Executor: "grants"}
	}
	in := effect(id)
	if g := int(id[1]-'0') % 4; g < len(grantIDs) {
		in.GrantRef = grantIDs[g]
	}
	return in
}

func (w *world) id() string {
	if w.rng.Intn(4) == 0 {
		return "r" + grantIDs[w.rng.Intn(len(grantIDs))][1:]
	}
	return effectIDs[w.rng.Intn(len(effectIDs))]
}

// step does one random thing; a crash restarts the engine on the medium.
func (w *world) step() {
	e, id := w.eng, w.id()
	switch op := w.rng.Intn(100); {
	case op < 20:
		e.Submit(w.intentFor(id))
	case op < 35:
		e.Authorize(ctx, id)
	case op < 65:
		e.Dispatch(ctx, id)
	case op < 75:
		e.Reconcile(ctx)
	case op < 79:
		e.Stop(ctx)
	case op < 85:
		e.Resume()
	case op < 90:
		e.Erase([]string{id})
	case op < 94:
		e.RecordQuality(id, journal.Quality{Verdict: journal.VerdictGood, Source: "owner"})
	default:
		w.restart()
	}
	if w.store.crashed {
		w.restart()
	}
}
