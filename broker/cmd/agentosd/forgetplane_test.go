package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/durable"
)

// REQ: CAP-3

const ownerNum = "+15550000001"

// learnTemp is spelled out so agentosd imports no more old core; this
// pins it to durable's, or the sweep would miss temps holding task text
// (Security release finding on #2808).
func TestLearnTempIsDurablesTempPrefix(t *testing.T) {
	if learnTemp != durable.TempPrefix {
		t.Fatalf("learnTemp = %q, durable.TempPrefix = %q", learnTemp, durable.TempPrefix)
	}
}

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
		for _, msg := range []string{"LOOPS OFF", "LOOP 1 ON", "LEARNING OFF", "SECURITY TESTS ON", "SPARE BUDGET 900", "HELP LOOPS", "STOP SHARING",
			"UPDATES FAST", "UPDATE SOAK 14", "HELP UPDATES"} {
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
	// Not gone for good (HLD-4), and an owner who had LEARNING OFF is told
	// task texts are kept for FORGET (NL-4; security 2 on #2801).
	if !strings.Contains(loopsOffText, "in this version") || !strings.Contains(loopsOffText, "30 days") || strings.Contains(loopsOffText, "no longer") {
		t.Fatalf("loopsOffText: %q", loopsOffText)
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

// statusNotes is every STATUS note cfg holds now.
func statusNotes(cfg *daemon.Config) []string {
	var out []string
	for _, n := range cfg.Notes {
		if l := n(); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// A temp a crash left from durable.WriteFile (a copy of harvest.json, say)
// is removed when the forget plane opens, with the learning state, since
// FORGET cannot reach a task in it (CAP-3; security 1 on #2801).
func TestOpenSweepsCrashLeftTemps(t *testing.T) {
	dir := t.TempDir()
	temp := filepath.Join(dir, learnTemp+"harvest.json-123")
	if err := os.WriteFile(temp, []byte(`{"goal":"CANARY-temp-task"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := daemon.Config{}
	lp, err := openForgetPlane(dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatalf("crash-left temp kept: %v", err)
	}
	if lp.notErased || len(statusNotes(&cfg)) != 0 {
		t.Fatalf("STATUS says not erased: %q", statusNotes(&cfg))
	}
}

// LOG-4 (erase fails closed, owner told; security 3 on #2801): old learning
// state or a temp that does not remove is named in STATUS, and the next
// start tries again.
func TestEraseFailureIsToldInStatus(t *testing.T) {
	for _, which := range []string{"learned", "temp"} {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "harvest.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			fail := errors.New("read-only disk")
			if which == "learned" {
				removeAll = func(string) error { return fail }
			} else {
				sweepTemp = func(string) error { return fail }
			}
			cfg := daemon.Config{}
			_, err := openForgetPlane(dir, &cfg)
			sweepTemp, removeAll = sweepLearnTemp, os.RemoveAll
			if err != nil {
				t.Fatal(err)
			}
			if got := statusNotes(&cfg); len(got) != 1 || got[0] != forgetNotErased {
				t.Fatalf("STATUS notes %q", got)
			}
			// The next start tries again, and the line goes.
			cfg = daemon.Config{}
			if _, err := openForgetPlane(dir, &cfg); err != nil {
				t.Fatal(err)
			}
			if got := statusNotes(&cfg); len(got) != 0 {
				t.Fatalf("STATUS notes after the retry %q", got)
			}
			if _, err := os.Lstat(filepath.Join(dir, "harvest.json")); !os.IsNotExist(err) {
				t.Fatalf("retry left the state: %v", err)
			}
		})
	}
}

// UX R1 on #92: when the forget plane does not open, STATUS says FORGET is
// not running and that a restart may fix it; when it opens, no such line.
func TestStatusSaysWhenForgetIsNotRunning(t *testing.T) {
	cfg := daemon.Config{}
	wireSettings(&cfg, nil)
	if got := statusNotes(&cfg); len(got) != 1 || got[0] != forgetNotRunning {
		t.Fatalf("STATUS notes %q", got)
	}
	cfg = daemon.Config{}
	if _, err := openForgetPlane(t.TempDir(), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, l := range statusNotes(&cfg) {
		if l == forgetNotRunning {
			t.Fatal("forget plane open, STATUS says it is not running")
		}
	}
}
