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
	"github.com/ghbmrk/agentos/broker/loops"
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
	if err := c.Contain(context.Background(), loops.Target{Kind: "grant", Name: "G2"}, "f1"); err != nil {
		t.Fatal(err)
	}
	in := g.got[0]
	if in.Origin != grants.OriginLoop2 || in.Action != journal.ActionGrantPause || in.GrantRef != "G2" ||
		in.Executor != grants.ExecutorName || in.Account != journal.BrokerAccount {
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
// feed, vault metadata), the digest names it as not run, never as passed
// (loops S2).
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
	want := "Security checks not run:"
	if d := strings.Join(lp.sched.Digest(), "\n"); !strings.Contains(d, want) {
		t.Fatalf("digest %q lacks %q", d, want)
	}
}
