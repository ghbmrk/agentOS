package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	if !lp.learn.Forgot("owner:f1") {
		t.Fatal("Loop 1 was not told of the forget")
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

// L3 MUST-2 on #160: a forget tombstones the goal, then writes the live
// tree before it saves the pipeline. Here the box stopped between the two:
// the tombstone holds the goal, while the saved pipeline still has an
// adoption and a case from it. Opening the learning plane runs the cascade
// again, before the agent can get the tree.
func TestLearningOpenReplaysAnInterruptedForget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "change.json")
	if _, err := change.New(change.Config{Store: change.FileStore{Path: path}, Evaluator: noEval{},
		Initial: change.Tree{"skills/greet.json": []byte("hi")}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	must(t, json.Unmarshal(raw, &st))
	canary := []byte("CANARY-f1")
	st["active"].(map[string]any)["skills/note.json"] = canary
	st["adoptions"] = []any{map[string]any{"id": "a1", "short": "A1", "source": "local", "goals": []string{"owner:f1"},
		"edits": []any{map[string]any{"path": "skills/note.json", "after": canary}}}}
	st["cases"] = map[string]any{"c1": map[string]any{"id": "c1", "class": "skill", "goal": "owner:f1", "input": canary}}
	raw, err = json.Marshal(st)
	must(t, err)
	must(t, os.WriteFile(path, raw, 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "forgotten.json"), []byte(`{"owner:f1":"2026-10-05T09:00:00Z"}`), 0o600))
	// The forget had not reached the harvester or the task texts either.
	must(t, os.WriteFile(filepath.Join(dir, "harvest.json"), []byte(`{"tasks":{"c1":"CANARY-key"},"added":{"c1":true}}`), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "tasks.json"), []byte(`{"owner:f1":{"text":"CANARY-text","at":"2026-10-05T08:00:00Z"}}`), 0o600))

	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lt := newLiveTree(t.Logf)
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json"), Tree: lt}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !lp.learn.Forgot("owner:f1") {
		t.Fatal("the replay did not reach Loop 1")
	}
	if lt.files["skills/note.json"] != nil || string(lt.files["skills/greet.json"]) != "hi" || !lt.ready {
		t.Fatalf("live tree after the replay: %q, ready %v", lt.files, lt.ready)
	}
	if raw, _ := os.ReadFile(path); bytes.Contains(raw, []byte("Q0FOQVJZ")) { // base64 of "CANARY"
		t.Fatal("the saved pipeline still holds the forgotten goal's files or case")
	}
	for _, f := range []string{"harvest.json", "tasks.json"} {
		if raw, _ := os.ReadFile(filepath.Join(dir, f)); bytes.Contains(raw, []byte("CANARY")) {
			t.Fatalf("%s still holds the forgotten goal's records", f)
		}
	}
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, map[string]journal.Executor{"task": succeeds{}, change.Executor: lp.pipe}, func(string) string { return daemon.Redacted })
	must(t, err)
	lp.pipe.Attach(eng)
	cand := change.Candidate{Source: change.Local, Goals: []string{"owner:f1"}, Files: change.Tree{"skills/note.json": []byte("x")}}
	if _, err := lp.pipe.Propose(context.Background(), cand); !errors.Is(err, change.ErrForgotten) {
		t.Fatalf("a forgotten task's candidate after the restart: %v", err)
	}
}

// A replay that cannot save leaves learning off, and the agent never gets
// the tree with the forgotten files on it.
func TestLearningStaysOffWhenTheReplayFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "change.json")
	if _, err := change.New(change.Config{Store: change.FileStore{Path: path}, Evaluator: noEval{},
		Initial: change.Tree{"skills/greet.json": []byte("hi")}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	must(t, err)
	var st map[string]any
	must(t, json.Unmarshal(raw, &st))
	st["cases"] = map[string]any{"c1": map[string]any{"id": "c1", "class": "skill", "goal": "owner:f1"}}
	raw, err = json.Marshal(st)
	must(t, err)
	must(t, os.WriteFile(path, raw, 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "forgotten.json"), []byte(`{"owner:f1":"2026-10-05T09:00:00Z"}`), 0o600))
	real := pipelineStore
	t.Cleanup(func() { pipelineStore = real })
	pipelineStore = func(p string) change.Store { return unsaved{change.FileStore{Path: p}} } // the pipeline's save cannot write
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lt := newLiveTree(t.Logf)
	if _, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json"), Tree: lt}, false, &cfg); err == nil {
		t.Fatal("learning opened with the replay unsaved")
	}
	if lt.ready {
		t.Fatal("the tree was marked ready")
	}
}

// unsaved is a FileStore whose saves fail.
type unsaved struct{ change.FileStore }

func (unsaved) Save([]byte) error { return errors.New("synthetic save failure") }
