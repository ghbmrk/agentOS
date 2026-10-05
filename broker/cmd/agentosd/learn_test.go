package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/routerule"
)

// REQ: LOOP-0, LOOP-1, LOOP-2, LOOP-6, CHG-2, ADP-4

const ownerNum = "+15550000001"

// The learning plane runs in agentosd (W3): the owner's loop settings reach
// the scheduler through the owner channel, the gate, and the journal, a
// locked session's LOOPS OFF included; HELP carries the loops line; the
// spare meter is capped by the owner's setting; and until the replay
// evaluator opens, nothing is evaluated and no loop work runs.
func TestLearningPlaneRunsInAgentosd(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !lp.busy() || !lp.stopped() {
		t.Fatal("loop work could start before the daemon runs")
	}
	if _, err := lp.eval.Run(context.Background(), change.Tree{}, change.Probe{ID: "p"}); !errors.Is(err, change.ErrNotEvaluated) {
		t.Fatalf("evaluation with no evaluator: %v", err)
	}
	if _, limit := lp.spare.Overall(); limit != loops.SpareLimits(loops.DefaultSpareCalls) {
		t.Fatalf("spare cap %+v", limit)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	lp.attach(ctx, d)
	if lp.busy() || lp.stopped() {
		t.Fatal("an idle box reads busy or stopped")
	}
	if got := d.Owner().Handle(ctx, ownerNum, "LOOPS OFF"); len(got) != 1 || !strings.Contains(got[0], "LOOPS ON") {
		t.Fatalf("locked LOOPS OFF: %q", got)
	}
	if !lp.sched.Settings().Off {
		t.Fatalf("settings after LOOPS OFF: %+v", lp.sched.Settings())
	}
	if got := d.Owner().Handle(ctx, ownerNum, "SPARE BUDGET 900"); len(got) != 1 || !strings.HasPrefix(got[0], "Locked.") {
		t.Fatalf("locked raise: %q", got)
	}
	if got := d.Owner().Handle(ctx, ownerNum, "HELP"); len(got) != 1 || !strings.Contains(got[0], loops.HelpLine) {
		t.Fatalf("HELP: %q", got)
	}
	cancel()
	d.Wait()
}

// The vault process's refusals of replay machines' model calls are logged,
// never journaled: egress records feed the owner's alerts and digest. Only
// a fixed class is logged, never the reason text, which may quote a
// private replay's request.
func TestEvalDenialsStayOutOfTheJournal(t *testing.T) {
	var logged []string
	deny := evalDenied(func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	deny("eval-0a1b", modelroute.Denial{Reason: modelroute.ReasonEvalCeiling, Status: 403})
	deny("eval-0a1b", modelroute.Denial{Reason: "denied: CANARY-7f3e quoted request", Status: 403})
	deny("agent", modelroute.Denial{Reason: "denied"})
	if len(logged) != 2 || !strings.Contains(logged[0], "price ceiling") || strings.Contains(logged[1], "CANARY") {
		t.Fatalf("logged %q", logged)
	}
}

// Routing adoptions are held in agentosd until agentos-egress follows them
// (its -rule): adopting one here would leave the vault process routing,
// and pricing evaluations, by a rule the pipeline no longer holds.
func TestRoutingAdoptionsAreHeld(t *testing.T) {
	var h heldRouting
	if cur, err := h.Current(); err != nil || len(cur) != 0 {
		t.Fatalf("current %v %v", cur, err)
	}
	if err := h.Apply(change.Tree{}); err != nil {
		t.Fatalf("restoring an empty routing tree: %v", err)
	}
	if err := h.Apply(change.Tree{change.RoutingPath: []byte(`{}`)}); err == nil {
		t.Fatal("a routing adoption applied")
	}
}

// L3 S3 on #90: when the learning plane could not start, the owner's loop
// settings are answered by the box, locked or not, saying it is off, and
// never go to the agent as chat; HELP says so too.
func TestLearningOffIsSaid(t *testing.T) {
	var cfg daemon.Config
	learningOff(&cfg)
	for _, msg := range []string{"LOOPS OFF", "SPARE BUDGET 900", "HELP LOOPS"} {
		for _, unlocked := range []bool{true, false} {
			if got, ok := cfg.Settings(context.Background(), msg, unlocked); !ok || got != learningOffText {
				t.Fatalf("%s (unlocked %v): %q %v", msg, unlocked, got, ok)
			}
		}
		if !cfg.Narrows(msg) {
			t.Fatalf("%s is held for the unlock", msg)
		}
	}
	if _, ok := cfg.Settings(context.Background(), "book a table", true); ok || cfg.Narrows("book a table") {
		t.Fatal("task chat taken as a setting")
	}
	// W3-off (UX R1 on #92): STATUS says so too, without a loop text.
	if len(cfg.Notes) != 1 || cfg.Notes[0]() != learningOffNote {
		t.Fatalf("STATUS notes: %d", len(cfg.Notes))
	}
	if cfg.HelpExtra != learningOffText {
		t.Fatalf("HELP: %q", cfg.HelpExtra)
	}
	// One GSM-7 segment, no longer than the loops' own HELP line is allowed
	// to be, so HELP stays within three (UX-49-1, UX-92-1).
	if len(learningOffText) > 153 {
		t.Fatalf("learning-off line is %d characters", len(learningOffText))
	}
}

// fakeRouting is the vault process's routing socket over the owner's rule
// base; down refuses every call, and like the vault process it takes only
// reorderings of base, an empty rule meaning base.
type fakeRouting struct {
	mu   sync.Mutex
	down bool
	base routerule.Rule
	rule routerule.Rule
	sets int
}

func (f *fakeRouting) State(context.Context) (modelroute.RoutingState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return modelroute.RoutingState{}, errors.New("down")
	}
	return modelroute.RoutingState{Rule: f.rule, Candidate: f.rule}, nil
}

func (f *fakeRouting) Set(_ context.Context, r routerule.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("down")
	}
	if len(r) == 0 {
		r = f.base
	}
	for c, rs := range f.base {
		if len(r) != len(f.base) || len(r[c]) != len(rs) {
			return modelroute.ErrRoutingRefused
		}
		for _, x := range rs {
			if !slices.Contains(r[c], x) {
				return modelroute.ErrRoutingRefused
			}
		}
	}
	f.rule, f.sets = r, f.sets+1
	return nil
}

func (f *fakeRouting) setDown(d bool) { f.mu.Lock(); f.down = d; f.mu.Unlock() }

func (f *fakeRouting) now() (routerule.Rule, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rule, f.sets
}

// W3 (potency PW4 on #90): with a routing socket, the pipeline's routing
// namespace follows the vault process's rule, an empty tree standing for
// the owner's -rule. On first start it records the vault process's rule,
// or with the vault process down the owner's, pushed once it is up
// (potency PW6). On a restart the restored rule is pushed, later if the
// vault process is not up yet; one it refuses (the owner changed -rule)
// gives way to the owner's rule and stands for it from then on (security
// R1). After start an adoption the vault process cannot take fails, so the
// pipeline never records a rule the router does not route by. Loop 1's
// router reads the vault process's proposal, or with the vault process
// down the active rule, so nothing is proposed.
func TestRoutingFollowsTheVaultProcess(t *testing.T) {
	ra := routerule.Route{Provider: "openai", Model: "gpt-test"}
	rb := routerule.Route{Provider: "anthropic", Model: "claude-test"}
	rc := routerule.Route{Provider: "openai", Model: "gpt-dear"}
	owners := routerule.Rule{"chat": {ra, rb}}
	reordered := routerule.Rule{"chat": {rb, ra}}
	tree := func(r routerule.Rule) change.Tree {
		b, _ := json.Marshal(r)
		return change.Tree{change.RoutingPath: b}
	}
	open := func(store change.Store, f *fakeRouting) (*syncedRouting, *change.Pipeline) {
		t.Helper()
		s := &syncedRouting{r: f, restoring: true, logf: t.Logf}
		p, err := change.New(change.Config{Store: store, Evaluator: &lateEvaluator{}, Targets: map[string]change.Target{"routing": s}})
		if err != nil {
			t.Fatal(err)
		}
		s.doneRestoring()
		return s, p
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First start with the vault process up records its rule.
	store := change.FileStore{Path: filepath.Join(t.TempDir(), "change.json")}
	vault := &fakeRouting{base: owners, rule: reordered}
	s, p := open(store, vault)
	if r := (routerOf{s, p}).active(); !sameRule(r, reordered) {
		t.Fatalf("first start recorded %v", r)
	}
	if !s.push(ctx) {
		t.Fatal("something pending after a first start with the vault process up")
	}

	// First start with it down records the owner's rule (an empty tree),
	// proposes nothing, and pushes the owner's rule once it is up.
	down := &fakeRouting{base: owners, rule: reordered, down: true}
	s2, p2 := open(change.FileStore{Path: filepath.Join(t.TempDir(), "change.json")}, down)
	r2 := routerOf{s2, p2}
	if len(p2.Files("routing")) != 0 || len(r2.Candidate()) != 0 {
		t.Fatalf("first start with the vault process down: %v, proposing %v", p2.Files("routing"), r2.Candidate())
	}
	down.setDown(false)
	s2.run(ctx, time.Millisecond)
	if r, _ := down.now(); !sameRule(r, owners) {
		t.Fatalf("vault process routes by %v", r)
	}

	// A restart while it is down pushes the restored rule once it is up;
	// an adoption it cannot take after the restart fails.
	vault = &fakeRouting{base: owners, rule: owners, down: true}
	s, p = open(store, vault)
	if s.push(ctx) {
		t.Fatal("the restored rule counted as pushed with the vault process down")
	}
	if err := s.Apply(tree(owners)); err == nil {
		t.Fatal("an adoption was recorded that the vault process never took")
	}
	r := routerOf{s, p}
	if !sameRule(r.Rule(), reordered) || !sameRule(r.Candidate(), reordered) {
		t.Fatalf("router with the vault process down: rule %v, candidate %v", r.Rule(), r.Candidate())
	}
	vault.setDown(false)
	s.run(ctx, time.Millisecond)
	if rule, sets := vault.now(); !sameRule(rule, reordered) || sets != 1 {
		t.Fatalf("vault process routes by %v after %d sets", rule, sets)
	}

	// The owner changed -rule since: the restored rule is refused, the
	// owner's rule is pushed, and a revert to the refused rule is taken
	// as the owner's rule rather than refused.
	changed := routerule.Rule{"chat": {ra, rc}}
	vault = &fakeRouting{base: changed, rule: changed}
	s, _ = open(store, vault)
	s.run(ctx, time.Millisecond)
	if rule, _ := vault.now(); !sameRule(rule, changed) {
		t.Fatalf("after -rule changed the vault process routes by %v", rule)
	}
	if err := s.Apply(tree(reordered)); err != nil {
		t.Fatalf("revert to the refused rule: %v", err)
	}
	if err := s.Apply(tree(routerule.Rule{"chat": {rb, rc}})); !errors.Is(err, modelroute.ErrRoutingRefused) {
		t.Fatalf("a non-reordering adoption: %v", err)
	}
}
