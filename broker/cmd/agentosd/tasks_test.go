package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
)

// REQ: OP-7, CHG-1, REV-5, CRED-8

type fakeHarvest struct{ got []loops.Outcome }

func (f *fakeHarvest) Harvest(o loops.Outcome) error {
	f.got = append(f.got, o)
	if strings.Contains(string(o.Input), "capped") {
		return loops.ErrImplicitCap
	}
	if strings.Contains(string(o.Input), "refuse") {
		return fmt.Errorf("case %s refused", o.Input)
	}
	return nil
}

// W3 (potency PW3 on #90): the owner's final verdict on an agent's effect
// becomes a Loop 1 case whose input is the owner's task text, kept by goal
// ID; the item is the effect's parameters, and the case is public only if
// the owner marked the task PUBLIC (the harvester narrows it further by
// the journal's label). Implicit acceptance is not harvested yet (PK2),
// nor a verdict whose task text is not kept. Logs never carry either text.
func TestOwnerVerdictsBecomeCases(t *testing.T) {
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	var logged []string
	logf := func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	tasks, err := openTaskTexts(change.FileStore{Path: filepath.Join(t.TempDir(), "tasks.json")}, func() time.Time { return now }, logf)
	if err != nil {
		t.Fatal(err)
	}
	tasks.put("owner:a1", "send Sam the invoice CANARY-task", true, viaSMS)
	tasks.put("owner:a2", "please refuse CANARY-task", false, viaSMS)
	h := &fakeHarvest{}
	effect := func(id, goal string) journal.Intent {
		return journal.Intent{ID: id, GoalID: goal, Origin: "guest:agent", Params: map[string]any{"record": "inv-1042"}}
	}
	harvestOutcome(h, tasks, grants.OwnerOutcome{Intent: effect("agent/1", "owner:a1"), Verdict: grants.OwnerAccepted}, logf)
	harvestOutcome(h, tasks, grants.OwnerOutcome{Intent: effect("agent/2", "owner:a1"), Verdict: grants.OwnerAcceptedImplicitly}, logf)
	harvestOutcome(h, tasks, grants.OwnerOutcome{Intent: effect("agent/3", "owner:gone"), Verdict: grants.OwnerDeclined}, logf)
	harvestOutcome(h, tasks, grants.OwnerOutcome{Intent: effect("agent/4", "owner:a2"), Verdict: grants.OwnerUndone}, logf)
	if len(h.got) != 3 {
		t.Fatalf("harvested %+v", h.got)
	}
	// An auto-reply let go on time is an implicit acceptance (PW3 part B).
	if o := h.got[1]; o.Intent != "agent/2" || o.Action != loops.Implicit {
		t.Fatalf("implicit: %+v", o)
	}
	h.got = append(h.got[:1], h.got[2:]...)
	tasks.put("owner:a3", "capped CANARY-task", false, viaSMS)
	harvestOutcome(&fakeHarvest{}, tasks, grants.OwnerOutcome{Intent: effect("agent/5", "owner:a3"), Verdict: grants.OwnerAcceptedImplicitly}, logf)
	if l := logged[len(logged)-1]; l != "learning: owner verdict not harvested: daily cap on implicit acceptances" {
		t.Fatalf("cap logged %q", l)
	}
	logged = logged[:len(logged)-1]
	if o := h.got[0]; o.Intent != "agent/1" || o.Action != loops.Approved || string(o.Input) != "send Sam the invoice CANARY-task" ||
		string(o.Output) != `{"record":"inv-1042"}` || !o.Public {
		t.Fatalf("accepted: %+v", o)
	}
	if o := h.got[1]; o.Action != loops.Undone || o.Public {
		t.Fatalf("undone: %+v", o)
	}
	if len(logged) != 2 || strings.Contains(strings.Join(logged, " "), "CANARY") {
		t.Fatalf("logged %q", logged)
	}
}

// Task texts are bounded: none older than keepTasks is used or kept, at
// most maxTasks are kept, and they survive a restart.
func TestTaskTextsAreBounded(t *testing.T) {
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := change.FileStore{Path: filepath.Join(t.TempDir(), "tasks.json")}
	tasks, err := openTaskTexts(store, clock, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	tasks.put("owner:old", "old task", false, viaSMS)
	now = now.Add(keepTasks + time.Minute)
	if _, ok := tasks.get("owner:old"); ok {
		t.Fatal("an expired task text was used")
	}
	for i := 0; i <= maxTasks; i++ {
		now = now.Add(time.Second)
		tasks.put(fmt.Sprintf("owner:%d", i), "task", false, viaSMS)
	}
	tasks, err = openTaskTexts(store, clock, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks.st) != maxTasks {
		t.Fatalf("kept %d", len(tasks.st))
	}
	if _, ok := tasks.get("owner:0"); ok {
		t.Fatal("the oldest task was kept over the cap")
	}
	if x, ok := tasks.get(fmt.Sprintf("owner:%d", maxTasks)); !ok || x.Text != "task" {
		t.Fatal("the newest task was lost across a restart")
	}
	if _, ok := tasks.st["owner:old"]; ok {
		t.Fatal("an expired task text was kept")
	}
	// Expired texts are swept at start, without waiting for a new task.
	now = now.Add(keepTasks + time.Hour)
	if tasks, err = openTaskTexts(store, clock, t.Logf); err != nil || len(tasks.st) != 0 {
		t.Fatalf("after a restart past the limit: %d kept, %v", len(tasks.st), err)
	}
	if tasks, err = openTaskTexts(store, clock, t.Logf); err != nil || len(tasks.st) != 0 {
		t.Fatalf("the sweep was not saved: %d kept, %v", len(tasks.st), err)
	}
	// Only the broker reads them (L3 N4 on #101).
	if fi, err := os.Stat(store.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("tasks.json: %v, %v", fi.Mode(), err)
	}
}

// REQ: CAP-3

// W3-tasks part 1 (security R1 on PW3): forgetting a task deletes its kept
// text from the learn directory, and a later verdict on it makes no case.
func TestForgetDeletesTheTaskText(t *testing.T) {
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	store := change.FileStore{Path: filepath.Join(t.TempDir(), "tasks.json")}
	tasks, err := openTaskTexts(store, func() time.Time { return now }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	tasks.put("owner:a1", "send Sam the invoice CANARY-forget", false, viaSMS)
	tasks.put("owner:a2", "book the dentist", false, viaSMS)
	if ok, err := tasks.forget("owner:a1"); !ok || err != nil {
		t.Fatal("forget reported the wrong result", err)
	}
	if ok, _ := tasks.forget("owner:a1"); ok {
		t.Fatal("forget reported the wrong result")
	}
	raw, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "CANARY-forget") || !strings.Contains(string(raw), "dentist") {
		t.Fatalf("saved texts: %s", raw)
	}
	h := &fakeHarvest{}
	harvestOutcome(h, tasks, grants.OwnerOutcome{Intent: journal.Intent{ID: "agent/1", GoalID: "owner:a1"}, Verdict: grants.OwnerAccepted}, t.Logf)
	if len(h.got) != 0 {
		t.Fatalf("a forgotten task made a case: %+v", h.got)
	}
}
