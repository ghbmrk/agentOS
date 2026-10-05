package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: LOOP-0, LOOP-1, LOOP-2, LOOP-6, CHG-2

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
