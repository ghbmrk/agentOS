package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loopbuild"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: LOOP-9, ADP-9

// pauseRec is a gate that records Loop 2's pause intents.
type pauseRec struct {
	got   []journal.Intent
	state journal.State
}

func (g *pauseRec) Submit(in journal.Intent) (journal.Status, error) {
	g.got = append(g.got, in)
	return journal.Status{Intent: in, State: journal.Pending}, nil
}
func (g *pauseRec) Authorize(_ context.Context, id string) (journal.Status, error) {
	return journal.Status{State: journal.Authorized}, nil
}
func (g *pauseRec) Dispatch(_ context.Context, id string) (journal.Status, error) {
	return journal.Status{State: g.state}, nil
}

// W5a, loops K-S2: Loop 2's containment pauses a grant through the gate
// from the broker's own origin, and only a grant: executors have no pause
// intent yet, so that finding says it could not pause (loops S4).
func TestLoop2PausesThroughTheGate(t *testing.T) {
	g := &pauseRec{state: journal.Succeeded}
	c := &loop2Contain{}
	if err := c.Contain(context.Background(), loops.Target{Kind: "grant", Name: "G2"}, "f1"); err == nil {
		t.Fatal("paused with no gate attached")
	}
	c.gate.Store(&pauseGateBox{g})
	if err := c.Contain(context.Background(), loops.Target{Kind: "grant", Name: "G2"}, "hash:f1"); err != nil {
		t.Fatal(err)
	}
	in := g.got[0]
	if in.Origin != grants.OriginLoop2 || in.Action != journal.ActionGrantPause || in.GrantRef != "G2" ||
		in.Executor != grants.ExecutorName || in.Account != journal.BrokerAccount || in.Params["finding"] != "hash:f1" {
		t.Fatalf("pause intent: %+v", in)
	}
	if err := c.Contain(context.Background(), loops.Target{Kind: "executor", Name: "egress"}, "f2"); err == nil || len(g.got) != 1 {
		t.Fatalf("an executor pause: %v, %d intents", err, len(g.got))
	}
	g.state = journal.Denied
	if err := c.Contain(context.Background(), loops.Target{Kind: "grant", Name: "G3"}, "f3"); !errors.Is(err, errNotPaused) {
		t.Fatalf("a refused pause: %v", err)
	}
}

// The learning plane runs Loop 2 as a scheduler source. Until the box
// has a verified input for a check (a signed release, a signed advisory
// feed, vault metadata), STATUS and the digest name it as not run, with
// why, never as passed (loops S2; L5 and C2 on W5a).
func TestLearningRunsLoop2(t *testing.T) {
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
	if cfg.Grants.Unpaused == nil {
		t.Fatal("the gate does not tell Loop 2 when a pause ends")
	}
	if _, err := lp.guard.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "Loop 2: partial (not run: file hashes, needs the updater; known vulnerabilities, needs a signed advisory feed; " +
		"settings, needs a check of what the machines hold; credential expiry, needs the vault's expiry list)."
	if d := strings.Join(lp.sched.Digest(), "\n"); !strings.Contains(d, want) {
		t.Fatalf("digest %q lacks %q", d, want)
	}
	status := ""
	for _, n := range cfg.Notes {
		status += n()
	}
	if !strings.Contains(status, want) {
		t.Fatalf("STATUS %q lacks %q", status, want)
	}
}

// attachForTest attaches lp and, at cleanup, cancels ctx and waits for the
// scheduler, so a Loop 2 pass never writes into a removed test directory.
func attachForTest(t *testing.T, lp *learning, ctx context.Context, cancel context.CancelFunc, d *daemon.Daemon) {
	lp.attach(ctx, d)
	t.Cleanup(func() {
		cancel()
		lp.running.Wait()
	})
}

// L3 S1 on #169: at start, Loop 2 drops every pause the gate no longer
// holds (a crash between the gate's resume and Loop 2's save, or a grant
// revoked with its connection), so the digest does not list a grant that
// is gone and a new pause of it is texted.
func TestAttachReconcilesLoop2Pauses(t *testing.T) {
	dir := t.TempDir()
	// Loop 2 listed G9 as paused when the box went down; the gate has no G9.
	rec := `{"finding":{"id":"advisory-1","check":"advisory","subject":"a","detail":"ADV-1","severity":"low",` +
		`"contain":{"kind":"grant","name":"G9"}},"contained":"paused","texted":true}`
	if err := os.WriteFile(filepath.Join(dir, "loop2.json"), []byte(`{"paused":{"grant/G9":`+rec+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d := strings.Join(lp.guard.Digest(), " "); !strings.Contains(d, "Cleared: a.") {
		t.Fatalf("the seeded pause is not listed before attach: %q", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	attachForTest(t, lp, ctx, cancel, d)
	if dg := strings.Join(lp.guard.Digest(), " "); strings.Contains(dg, "Cleared: a.") {
		t.Fatalf("a pause the gate does not hold is still listed: %q", dg)
	}
}

// L3 on #173 (mutant R3): only a grant the gate holds paused stays
// listed. A grant whose resume was journaled but not heard by Loop 2 (the
// crash window) exists unpaused, and is dropped.
func TestLoop2HeldIsOnlyAPausedGrant(t *testing.T) {
	held := loop2Held([]grants.Grant{{ID: "G1", Paused: true}, {ID: "G2"}})
	for _, c := range []struct {
		t    loops.Target
		want bool
	}{
		{loops.Target{Kind: "grant", Name: "G1"}, true},
		{loops.Target{Kind: "grant", Name: "G2"}, false}, // resumed
		{loops.Target{Kind: "grant", Name: "G3"}, false}, // revoked
		{loops.Target{Kind: "executor", Name: "G1"}, false},
	} {
		if got := held(c.t); got != c.want {
			t.Errorf("%+v: held %v, want %v", c.t, got, c.want)
		}
	}
}

type pauseExec struct{ paused []string }

func (x *pauseExec) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	x.paused = append(x.paused, in.GrantRef)
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (x *pauseExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}

// P3-4b LOOP-9 (1): containment works even during STOP. A pause only
// narrows authority (journal A9), so a stopped engine still dispatches it,
// and a seeded finding reported after STOP pauses exactly its target.
func TestLoop2ContainsDuringStop(t *testing.T) {
	x := &pauseExec{}
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, map[string]journal.Executor{grants.ExecutorName: x},
		func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := &loop2Contain{}
	c.gate.Store(&pauseGateBox{eng})
	if err := c.Contain(context.Background(), loops.Target{Kind: "grant", Name: "G7"}, "seeded:f1"); err != nil {
		t.Fatalf("pause during STOP: %v", err)
	}
	if len(x.paused) != 1 || x.paused[0] != "G7" {
		t.Fatalf("paused %q", x.paused)
	}
}

// REQ: LOOP-2, CHG-2

// P3-4b-5: the daemon answers Loop 2's fix requests through Loop 1's
// builder. With no builder machines the request stays open and STATUS
// names the cause; with a builder that has no model route, it names that.
func TestLoop2AsksTheBuilderForItsFixes(t *testing.T) {
	lp := testLearning(t)
	rule := `{"tree_rule":[{"path":"config/privacy.json","pointer":"/private_routes","op":"subset","value":["local"]}]}`
	rec, err := lp.guard.Report(context.Background(), loops.Finding{Check: loops.CheckSeeded, Subject: "private-route",
		Detail: "private work may use a cloud route", Severity: loops.High, Rule: []byte(rule)})
	if err != nil || rec.Fix != loops.FixPending {
		t.Fatalf("report: %+v, %v", rec, err)
	}
	lp.guard.Trigger()
	if _, err := lp.guard.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := lp.guard.Status(); !strings.Contains(s, "waits for a fix: I cannot build one yet, because "+loop2NoBuilder+".") {
		t.Fatalf("STATUS %q", s)
	}
	if _, err := (lateFix{&lp.build}).Fix(context.Background(), rec.Finding); !errors.Is(err, errNoBuilder) {
		t.Fatalf("fix with no builder: %v", err)
	}
	var s lateServices
	lp.startBuilder(&fakeBuilderMachines{}, images{"builder": "/img/builder", "openclaw": "/img/openclaw"}, &s,
		buildConfig{Dir: filepath.Join(t.TempDir(), "build"), Image: "builder", AgentImage: "openclaw"})
	if s := lp.guard.Status(); !strings.Contains(s, "I cannot build one yet, because "+loopbuild.NoModel+".") {
		t.Fatalf("STATUS with no model route %q", s)
	}
}

// LOOP-2: fix jobs spend Loop 2's share of the spare meter, apart from
// Loop 1's builder share; the wiring sets both.
func TestFixJobsHaveTheirOwnShare(t *testing.T) {
	b, f := builderShare(), loop2FixShare()
	if b.Prefix != loopbuild.BuildPrefix || f.Prefix != loopbuild.FixPrefix || f.Max <= 0 || f.Max > b.Max {
		t.Fatalf("shares %+v %+v", b, f)
	}
	lp := testLearning(t)
	if err := lp.spare.SetShares([]meter.Share{lp.sched.EvalShare(), b, f}); err != nil {
		t.Fatal(err)
	}
}
