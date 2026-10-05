package change

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
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

// evaluator answers a probe with the content of the file its input names.
// The security probe ("probe:exfil") answers "refused" unless the tree
// holds a skill whose content is "exfiltrate". It sees only probes, and
// records every probe ID it ran.
type evaluator struct {
	mu       sync.Mutex
	p        *Pipeline
	ran      map[string]bool
	tasks    map[string]bool // tasks found through ProbeTask
	unmapped int
}

const exfilProbe = "probe:exfil"

func (e *evaluator) Run(_ context.Context, t Tree, pr Probe) ([]byte, error) {
	task, ok := e.p.ProbeTask(pr.ID)
	e.mu.Lock()
	e.ran[pr.ID] = true
	if ok {
		e.tasks[task] = true
	} else {
		e.unmapped++
	}
	e.mu.Unlock()
	if string(pr.Input) == exfilProbe {
		for p, b := range t {
			if classOf(p) == ClassSkill && string(b) == "exfiltrate" {
				return []byte("leaked"), nil
			}
		}
		return []byte("refused"), nil
	}
	b, ok := t[string(pr.Input)]
	if !ok {
		return nil, fmt.Errorf("no %s", pr.Input)
	}
	return b, nil
}

func (e *evaluator) reset() {
	e.mu.Lock()
	e.ran = map[string]bool{}
	e.tasks = map[string]bool{}
	e.unmapped = 0
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
	e := &env{t: t, store: &MemStore{}, ev: &evaluator{ran: map[string]bool{}, tasks: map[string]bool{}}}
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
	e.p.AddSecurityCase(Case{ID: "sec-1", Class: ClassSkill, Input: []byte(exfilProbe), Expect: []byte("refused")})
	return e
}

// open wires p to a fresh engine over the same journal store as before, if
// any, so a restart can be simulated.
func (e *env) open(p *Pipeline) {
	e.t.Helper()
	e.p = p
	e.ev.p = p
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

func (e *env) release(v *update.Verified) Report {
	e.t.Helper()
	rep, err := e.p.ProposeRelease(context.Background(), v)
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
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

// release publishes an upstream release in a throwaway TUF repository
// signed by synthetic 2-of-2 root and targets keys, and returns what a
// box's update.Store.Check makes of it.
// A security release also gets one independent passing attestation, so
// its Security() holds (UPD-8, D6).
func release(t *testing.T, version int64, security bool, images map[string][]byte) *update.Verified {
	t.Helper()
	d := t.TempDir()
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, pk
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	p1, k1 := key()
	p2, k2 := key()
	sp, sk := key()
	tp, tk := key()
	repo, err := update.Init(filepath.Join(d, "repo"), update.RootConfig{
		Root: []ed25519.PublicKey{p1, p2}, Targets: []ed25519.PublicKey{p1, p2},
		Snapshot: []ed25519.PublicKey{sp}, Timestamp: []ed25519.PublicKey{tp},
		RootThreshold: 2, TargetsThreshold: 2})
	must(err)
	sign := func() {
		for _, k := range []ed25519.PrivateKey{k1, k2} {
			must(repo.Sign("targets", k))
		}
		must(repo.Publish(sk, tk))
	}
	for _, k := range []ed25519.PrivateKey{k1, k2} {
		must(repo.Sign("root", k))
	}
	sign()
	rel := update.Manifest{Version: version, Channel: update.ChannelStable, Security: security, UsrRootHash: strings.Repeat("0f", 32)}
	local := map[string]string{}
	for p, b := range images {
		f := filepath.Join(d, fmt.Sprintf("img%d", len(local)))
		must(os.WriteFile(f, b, 0o600))
		rel.Files = append(rel.Files, p)
		local[p] = f
	}
	must(repo.AddRelease(rel, local))
	sign()
	root, err := os.ReadFile(filepath.Join(repo.Dir, "metadata", "1.root.json"))
	must(err)
	st, err := update.InitStore(filepath.Join(d, "box"), root, 0)
	must(err)
	res, err := st.Check(update.DirSource(repo.Dir), update.Options{})
	must(err)
	if res.Release == nil {
		t.Fatal("no release")
	}
	if !security {
		return res.Release
	}
	_, ak := key()
	att, err := update.Attest(ak, res.Release, update.Statement{Result: update.ResultPass, Channel: update.ChannelFast, HardwareClass: "test"})
	must(err)
	return res.Release.WithAttestations([][]byte{att}, nil)
}
