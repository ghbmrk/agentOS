package change

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// env is a pipeline wired to a real journal engine, with the owner played
// by a flag the broker's policy consults when Check says ErrNeedsOwner.
type env struct {
	t     *testing.T
	p     *Pipeline
	eng   *journal.Engine
	store *MemStore
	ev    *evaluator
	owner *ownerPolicy
	tasks int
}

type ownerPolicy struct {
	mu      sync.Mutex
	p       *Pipeline
	approve bool     // the owner approves whatever is asked
	asked   []string // intents the owner was asked about
}

func (o *ownerPolicy) Check(ctx context.Context, ph journal.Phase, in journal.Intent) error {
	if in.Executor != Executor {
		return nil // task intents in these tests
	}
	err := o.p.Check(ctx, ph, in)
	if !errors.Is(err, ErrNeedsOwner) {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if ph == journal.PhaseAuthorize {
		o.asked = append(o.asked, in.ID)
	}
	if o.approve {
		return nil
	}
	return errors.New("the owner said no")
}

func (o *ownerPolicy) wasAsked(id string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, a := range o.asked {
		if a == id {
			return true
		}
	}
	return false
}

// evaluator answers a case with the content of the file its input names,
// and a security fixture with "refused" unless the tree holds a file under
// skills/ whose content is "exfiltrate". It records every case it ran.
type evaluator struct {
	mu  sync.Mutex
	ran map[string]bool
}

func (e *evaluator) Run(_ context.Context, t Tree, c Case) ([]byte, error) {
	e.mu.Lock()
	e.ran[c.ID] = true
	e.mu.Unlock()
	if c.Security {
		for p, b := range t {
			if classOf(p) == ClassSkill && string(b) == "exfiltrate" {
				return []byte("leaked"), nil
			}
		}
		return []byte("refused"), nil
	}
	b, ok := t[string(c.Input)]
	if !ok {
		return nil, fmt.Errorf("no %s", c.Input)
	}
	return b, nil
}

func (e *evaluator) reset() {
	e.mu.Lock()
	e.ran = map[string]bool{}
	e.mu.Unlock()
}

type noop struct{}

func (noop) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (noop) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func newEnv(t *testing.T, mod func(*Config)) *env {
	t.Helper()
	e := &env{t: t, store: &MemStore{}, ev: &evaluator{ran: map[string]bool{}}}
	cfg := Config{
		Store:       e.store,
		Evaluator:   e.ev,
		Initial:     Tree{"skills/greet": []byte("hi"), "procedures/file": []byte("v1")},
		MinHeldOut:  3,
		Receives:    func(m string) []string { return map[string][]string{"mail-agent": {"mail", "calendar"}}[m] },
		Private:     func(b []byte) bool { return containsCanary(b) },
		DevPercent:  30,
		MinSecurity: 1,
	}
	if mod != nil {
		mod(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.open(p)
	e.p.AddSecurityCase(Case{ID: "sec-1", Class: ClassSkill, Expect: []byte("refused")})
	return e
}

// open wires p to a fresh engine over the same journal store as before, if
// any, so a restart can be simulated.
func (e *env) open(p *Pipeline) {
	e.t.Helper()
	e.p = p
	if e.owner == nil {
		e.owner = &ownerPolicy{}
	}
	e.owner.p = p
	eng, err := journal.Open(&journal.MemStore{}, e.owner, map[string]journal.Executor{Executor: p, "task": noop{}},
		func(s string) string { return s })
	if err != nil {
		e.t.Fatal(err)
	}
	e.eng = eng
	p.Attach(eng)
}

// taskCase journals a real task, records the owner's verdict on it, and
// adds the case. It returns the case.
func (e *env) taskCase(class Class, input, expect string, out Outcome) Case {
	e.t.Helper()
	e.tasks++
	id := fmt.Sprintf("task-%d", e.tasks)
	e.mustTask(id)
	v := journal.VerdictGood
	if out != Accepted {
		v = journal.VerdictWrong
	}
	if _, err := e.eng.RecordQuality(id, journal.Quality{Verdict: v, Source: "owner"}); err != nil {
		e.t.Fatal(err)
	}
	c := Case{ID: "case-" + id, Class: class, Input: []byte(input), Expect: []byte(expect), Outcome: out, Task: id}
	if err := e.p.AddTaskCase(c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) mustTask(id string) {
	e.t.Helper()
	if _, err := e.eng.Submit(journal.Intent{ID: id, Origin: "guest:a", Account: "mail", Action: "draft", Executor: "task"}); err != nil {
		e.t.Fatal(err)
	}
}

// cases adds n accepted cases for a class whose answer is the content
// expect at path input.
func (e *env) cases(n int, class Class, input, expect string) {
	for i := 0; i < n; i++ {
		e.taskCase(class, input, expect, Accepted)
	}
}

func (e *env) propose(c Candidate) Report {
	e.t.Helper()
	rep, err := e.p.Propose(context.Background(), c)
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

func containsCanary(b []byte) bool { return strings.Contains(string(b), "CANARY-") }
