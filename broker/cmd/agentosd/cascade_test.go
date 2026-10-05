package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CAP-3, CHG-1

// W3-tasks part 2 (security C1 on #120): the learning plane's forget runs
// the pipeline's cascade, so a candidate learned from the forgotten task
// is never adopted afterwards (its undo of past adoptions: change
// TestForgetGoalUndoesWhatWasLearnedFromIt), while another task's still
// goes to evaluation.
func TestLearningForgetRunsTheCascade(t *testing.T) {
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
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, map[string]journal.Executor{"task": succeeds{}, change.Executor: lp.pipe}, func(string) string { return daemon.Redacted })
	if err != nil {
		t.Fatal(err)
	}
	lp.pipe.Attach(eng)
	lp.eng.Store(eng)
	if err := lp.forgetTask("owner:f1"); err != nil {
		t.Fatal(err)
	}
	cand := func(goal string) change.Candidate {
		return change.Candidate{Source: change.Local, Goals: []string{goal}, Files: change.Tree{"skills/note": []byte("x")}}
	}
	if _, err := lp.pipe.Propose(context.Background(), cand("owner:f1")); !errors.Is(err, change.ErrForgotten) {
		t.Fatalf("a forgotten task's candidate: %v", err)
	}
	if _, err := lp.pipe.Propose(context.Background(), cand("owner:f2")); err != nil {
		t.Fatalf("another task's candidate: %v", err)
	}
}
