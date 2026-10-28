package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-4, OP-2

// guardNames are the executor names agentosd registers with the daemon
// besides the grants gate, whose Reconcile is a constant not_applied:
// broker executors (loops, change, update and FORGET, retired; mail)
// and the recall rollback executor.
var guardNames = []string{"loops", "change", "update", grants.ForgetExecutor, "mail", grants.RecallExecutor}

// guard stands in for an executor at restart. Reconcile answers unknown
// for its first few asks, then the evidence it was given; Execute must
// never run, since startup reconcile only gathers evidence (#1371).
type guard struct {
	t        *testing.T
	name     string
	mu       sync.Mutex
	down     int
	answer   journal.Result
	asked    int
	executed int
}

func (g *guard) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	g.mu.Lock()
	g.executed++
	g.mu.Unlock()
	g.t.Errorf("startup reconcile executed %s through %s", in.ID, g.name)
	return journal.Outcome{Result: journal.ResultNotApplied}
}

func (g *guard) Reconcile(_ context.Context, _ journal.Intent, _ int) journal.Outcome {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked++
	if g.down > 0 {
		g.down--
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "service unavailable"}
	}
	return journal.Outcome{Result: g.answer}
}

// stuck blocks Execute until release closes, as a broker that dies
// mid-dispatch would.
type stuck struct {
	entered chan string
	release chan struct{}
}

func (s stuck) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	s.entered <- in.ID
	<-s.release
	return journal.Outcome{Result: journal.ResultUnknown}
}

func (stuck) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}

// crashOnePerExecutor leaves a journal with one intent per guard name
// dispatched and never finished.
func crashOnePerExecutor(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.log")
	store, err := journal.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := stuck{entered: make(chan string), release: make(chan struct{})}
	execs := map[string]journal.Executor{}
	for _, n := range guardNames {
		execs[n] = s
	}
	eng, err := journal.Open(store, allowAll{}, execs, redactAll)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for _, n := range guardNames {
		in := journal.Intent{ID: "crash:" + n, Origin: "owner", Account: journal.BrokerAccount, Action: "act." + n, Executor: n}
		if _, err := eng.Submit(in); err != nil {
			t.Fatal(err)
		}
		if st, err := eng.Authorize(ctx, in.ID); err != nil || st.State != journal.Authorized {
			t.Fatalf("authorize %s: %s %v", in.ID, st.State, err)
		}
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = eng.Dispatch(ctx, in.ID) }()
		<-s.entered
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	crashed := filepath.Join(t.TempDir(), "journal.log")
	if err := os.WriteFile(crashed, data, 0o600); err != nil {
		t.Fatal(err)
	}
	close(s.release)
	wg.Wait()
	store.Close()
	return crashed
}

// Startup reconcile never calls an executor's Execute: one intent per
// registered executor crashes mid-dispatch, evidence is unavailable for a
// few rounds and then says succeeded or not_applied, and the fence lifts
// with nothing run again, not even the not_applied ones (#1371).
func TestOP4StartupReconcileNeverExecutes(t *testing.T) {
	fastSettle(t)
	crashed := crashOnePerExecutor(t)
	dir := t.TempDir()
	guards := map[string]*guard{}
	brokers := map[string]journal.Executor{}
	for i, n := range guardNames {
		g := &guard{t: t, name: n, down: i % 3, answer: journal.ResultSucceeded}
		if i%2 == 1 {
			g.answer = journal.ResultNotApplied
		}
		guards[n] = g
		if n != grants.RecallExecutor {
			brokers[n] = g
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, Config{
		JournalPath: crashed, SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Auth: unlocked{},
		Admission:       admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		BrokerExecutors: brokers,
		Recall:          guards[grants.RecallExecutor],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); d.Wait() }()
	waitUnfenced(t, d)
	time.Sleep(20 * time.Millisecond) // a dispatch after settling would land here
	for _, n := range guardNames {
		g := guards[n]
		g.mu.Lock()
		asked, executed, want := g.asked, g.executed, g.down
		g.mu.Unlock()
		if executed != 0 || asked == 0 || want != 0 {
			t.Errorf("%s: asked %d, executed %d, unknowns left %d", n, asked, executed, want)
		}
		st, err := d.Engine().Get("crash:" + n)
		if err != nil {
			t.Fatal(err)
		}
		if wantState := map[journal.Result]journal.State{journal.ResultSucceeded: journal.Succeeded,
			journal.ResultNotApplied: journal.NotApplied}[g.answer]; st.State != wantState || len(st.Attempts) != 1 {
			t.Errorf("%s: %s after %d attempts", n, st.State, len(st.Attempts))
		}
	}
}
