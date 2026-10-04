package journal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// policyCall is one call to a Policy, in order.
type policyCall struct {
	Phase Phase
	ID    string
}

// testPolicy allows every intent except those revoked; it logs every call.
type testPolicy struct {
	mu      sync.Mutex
	revoked map[string]bool
	calls   []policyCall
}

func newPolicy() *testPolicy { return &testPolicy{revoked: map[string]bool{}} }

func (p *testPolicy) Check(_ context.Context, phase Phase, in Intent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, policyCall{phase, in.ID})
	if p.revoked[in.ID] {
		return errors.New("grant revoked")
	}
	return nil
}

func (p *testPolicy) revoke(id string, v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked[id] = v
}

func (p *testPolicy) allowed(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.revoked[id]
}

func (p *testPolicy) lastCall() (policyCall, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return policyCall{}, false
	}
	return p.calls[len(p.calls)-1], true
}

// execMode is how the fake service handles one Execute call.
type execMode int

const (
	modeOK      execMode = iota // apply, acknowledge
	modeRefuse                  // do not apply, say so
	modeDropAck                 // apply, but the acknowledgment is lost
	modeTimeout                 // do not apply, and the broker cannot tell
)

// fakeService is the external world. It survives broker restarts.
type fakeService struct {
	mu        sync.Mutex
	applied   map[string]bool // attempt key → effect happened
	effects   map[string]int  // intent ID → number of effects
	executes  []string        // attempt keys, in call order
	cancels   []string
	mode      func(key string) execMode
	knows     func(key string) bool // can Reconcile tell what happened?
	onExecute func(in Intent, attempt int)
	cancelOK  bool
}

func newService() *fakeService {
	return &fakeService{
		applied: map[string]bool{},
		effects: map[string]int{},
		mode:    func(string) execMode { return modeOK },
		knows:   func(string) bool { return true },
	}
}

func (s *fakeService) Execute(_ context.Context, in Intent, attempt int) Outcome {
	if s.onExecute != nil {
		s.onExecute(in, attempt)
	}
	key := AttemptKey(in.ID, attempt)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executes = append(s.executes, key)
	switch s.mode(key) {
	case modeRefuse:
		return Outcome{Result: ResultNotApplied, Evidence: "refused " + key}
	case modeDropAck:
		s.apply(in.ID, key)
		return Outcome{Result: ResultUnknown, Evidence: "timeout"}
	case modeTimeout:
		return Outcome{Result: ResultUnknown, Evidence: "timeout"}
	default:
		s.apply(in.ID, key)
		return Outcome{Result: ResultSucceeded, Evidence: "receipt " + key}
	}
}

func (s *fakeService) apply(id, key string) {
	if !s.applied[key] {
		s.applied[key] = true
		s.effects[id]++
	}
}

func (s *fakeService) Reconcile(_ context.Context, in Intent, attempt int) Outcome {
	key := AttemptKey(in.ID, attempt)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.knows(key) {
		return Outcome{Result: ResultUnknown}
	}
	if s.applied[key] {
		return Outcome{Result: ResultSucceeded, Evidence: "found " + key}
	}
	return Outcome{Result: ResultNotApplied, Evidence: "no record of " + key}
}

func (s *fakeService) Cancel(_ context.Context, in Intent, attempt int) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancels = append(s.cancels, AttemptKey(in.ID, attempt))
	return s.cancelOK, "cancel requested"
}

func (s *fakeService) effectCount(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effects[id]
}

func (s *fakeService) wasApplied(id string, attempt int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied[AttemptKey(id, attempt)]
}

func (s *fakeService) executeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.executes)
}

// plainExec is an executor without cancellation support.
type plainExec struct{ svc *fakeService }

func (p plainExec) Execute(ctx context.Context, in Intent, a int) Outcome {
	return p.svc.Execute(ctx, in, a)
}
func (p plainExec) Reconcile(ctx context.Context, in Intent, a int) Outcome {
	return p.svc.Reconcile(ctx, in, a)
}

// crashStore wraps a MemStore. After `budget` successful appends, the next
// append fails; if torn is set, half of that line reaches the medium first.
type crashStore struct {
	*MemStore
	budget  int
	torn    bool
	crashed bool
}

var errCrash = errors.New("simulated crash")

func (c *crashStore) Append(line []byte) error {
	if c.crashed {
		return errCrash
	}
	if c.budget == 0 {
		c.crashed = true
		if c.torn {
			_ = c.MemStore.Append(line[:len(line)/2])
		}
		return errCrash
	}
	c.budget--
	return c.MemStore.Append(line)
}

func intent(id, account string) Intent {
	return Intent{
		ID:         id,
		GoalID:     "goal-1",
		Origin:     "owner-sms",
		Account:    account,
		Action:     "send",
		Params:     map[string]any{"subject": "hello", "n": 1},
		Recipients: []string{"alice@example.test"},
		Visibility: "private",
		GrantRef:   "grant-1",
		Executor:   "svc",
	}
}

func mustOpen(t interface{ Fatalf(string, ...any) }, st Store, p Policy, svc Executor) *Engine {
	e, err := Open(st, p, map[string]Executor{"svc": svc}, testRedact)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return e
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}
	return v
}

// canary is a synthetic secret. testRedact removes it, as the broker's
// vault-value redactor would remove a real one.
const canary = "CANARY-7f3a91-SECRET"

func testRedact(s string) string { return strings.ReplaceAll(s, canary, "[redacted]") }
