package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: OP-7

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
// text from the learn directory.
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
}
