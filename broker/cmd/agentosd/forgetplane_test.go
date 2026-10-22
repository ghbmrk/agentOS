package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
)

// REQ: CAP-3

const ownerNum = "+15550000001"

// attachForTest attaches lp to the running daemon d and ends d with the
// test.
func attachForTest(t *testing.T, lp *forgetPlane, ctx context.Context, cancel context.CancelFunc, d *daemon.Daemon) {
	lp.attach(ctx, d)
	t.Cleanup(func() {
		cancel()
		d.Wait()
	})
}

// The old loop settings texts (LOOPS, LEARNING, SPARE BUDGET, HELP LOOPS)
// are answered by the box, locked or not, saying there is no spare-time
// work, and never go to the agent as chat; FORGET is never task chat,
// forget plane or not (MIG-4-untrusted-learn, W3-forget).
func TestLoopSettingsAreAnsweredByTheBox(t *testing.T) {
	for _, plane := range []bool{false, true} {
		cfg := daemon.Config{}
		if plane {
			if _, err := openForgetPlane(t.TempDir(), &cfg); err != nil {
				t.Fatal(err)
			}
		} else {
			wireSettings(&cfg, nil)
		}
		for _, msg := range []string{"LOOPS OFF", "LOOP 1 ON", "LEARNING OFF", "SECURITY TESTS ON", "SPARE BUDGET 900", "HELP LOOPS", "STOP SHARING"} {
			for _, unlocked := range []bool{true, false} {
				if got, ok := cfg.Settings(context.Background(), msg, unlocked); !ok || got != loopsOffText {
					t.Fatalf("plane %v, %s (unlocked %v): %q %v", plane, msg, unlocked, got, ok)
				}
			}
			if !cfg.Narrows(msg) {
				t.Fatalf("%s is held for the unlock", msg)
			}
		}
		if _, ok := cfg.Settings(context.Background(), "book a table", true); ok || cfg.Narrows("book a table") {
			t.Fatal("task chat taken as a setting")
		}
		got, ok := cfg.Settings(context.Background(), "FORGET", true)
		if !ok || plane == (got == forgetOffText) {
			t.Fatalf("plane %v, FORGET: %q %v", plane, got, ok)
		}
		if cfg.HelpExtra != "" {
			t.Fatalf("HELP names a setting the box no longer has: %q", cfg.HelpExtra)
		}
	}
	// One GSM-7 segment each.
	for _, l := range []string{loopsOffText, forgetOffText} {
		if utf8.RuneCountInString(l) > 153 || len(l) != utf8.RuneCountInString(l) {
			t.Fatalf("%q is not one plain segment", l)
		}
	}
}

// The learning loop's state is removed when the forget plane opens, since
// FORGET can no longer reach a task in it (CAP-3); FORGET's own state and
// the values key mail's UNDO derives from stay.
func TestOpenRemovesTheLearningState(t *testing.T) {
	dir := t.TempDir()
	for _, name := range learnedFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bodies := filepath.Join(dir, "change.json.d")
	if err := os.Remove(bodies); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bodies, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	kept := []string{"values.key", "tasks.json", "forgotten.json"}
	for _, name := range kept {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := openForgetPlane(dir, &daemon.Config{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range learnedFiles {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", name, err)
		}
	}
	for _, name := range kept {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s removed: %v", name, err)
		}
	}
}

// The owner's task texts are kept for FORGET's list, but never for a goal
// the owner forgot (security F1 on #123), and forgetTask deletes the text
// after the tombstone.
func TestTaskTextsAreKeptForForget(t *testing.T) {
	lp, err := openForgetPlane(t.TempDir(), &daemon.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lp.delivered("g1", "book a table", false)
	if _, ok := lp.tasks.get("g1"); !ok {
		t.Fatal("task text not kept")
	}
	if err := lp.forgetTask("g1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := lp.tasks.get("g1"); ok || !lp.forgotten.has("g1") {
		t.Fatal("forget left the text or no tombstone")
	}
	lp.delivered("g1", "book it again", false)
	if _, ok := lp.tasks.get("g1"); ok {
		t.Fatal("a forgotten goal's text was kept again")
	}
	if c := lp.forgetOwner.learned("g1"); c != 0 {
		t.Fatalf("a forget undoes %d learned changes", c)
	}
}

// failSave is a store whose saves fail, as on a full or read-only disk.
type failSave struct{ change.Store }

func (failSave) Save([]byte) error { return errors.New("disk full") }

// W3-tasks part 1 (security F1 on #123): a forget whose deletion did not
// reach the disk says so, so the owner is never told a task is gone while
// its text is still at rest.
func TestForgetReportsAFailedSave(t *testing.T) {
	lp, err := openForgetPlane(t.TempDir(), &daemon.Config{})
	if err != nil {
		t.Fatal(err)
	}
	const goal = "owner:tasks"
	lp.tasks.put(goal, "pay the CANARY-forget invoice", false, viaSMS)
	tasks := lp.tasks.store
	lp.tasks.store = failSave{tasks}
	if _, err := lp.tasks.forget("none"); err != nil {
		t.Fatalf("nothing to forget still failed: %v", err)
	}
	if err := lp.forgetTask(goal); err == nil {
		t.Fatal("forget reported success with its save failing")
	}
	lp.tasks.store = tasks
	// Security R1: the entry is gone from memory, so a retried forget must
	// still save, or the file keeps the text.
	if err := lp.forgetTask(goal); err != nil {
		t.Fatalf("retried forget: %v", err)
	}
	if raw, _ := tasks.Load(); bytes.Contains(raw, []byte("CANARY-forget")) || bytes.Contains(raw, []byte(goal)) {
		t.Fatal("a retried forget left the task on disk")
	}
	if _, ok := lp.tasks.get(goal); ok {
		t.Fatal("task text kept in memory")
	}
}
