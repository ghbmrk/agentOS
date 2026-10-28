package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
)

// REQ: CAP-3

const ownerNum = "+15550000001"

// The old settings texts are answered by the box, locked or not, and
// never go to the agent as chat: the loop settings (LOOPS, LEARNING,
// SPARE BUDGET, HELP LOOPS) say there is no spare-time work, and FORGET
// and RENEW, deleted with recall (#2781), say they do not run in this
// version. Longer texts that start with those words stay task chat, as
// they were.
func TestOldSettingsAreAnsweredByTheBox(t *testing.T) {
	cfg := daemon.Config{}
	openLearnState(t.TempDir(), &cfg)
	for msg, want := range map[string]string{
		"LOOPS OFF": loopsOffText, "LOOP 1 ON": loopsOffText, "LEARNING OFF": loopsOffText, "SECURITY TESTS ON": loopsOffText,
		"SPARE BUDGET 900": loopsOffText, "HELP LOOPS": loopsOffText, "STOP SHARING": loopsOffText,
		"UPDATES FAST": loopsOffText, "UPDATE SOAK 14": loopsOffText, "HELP UPDATES": loopsOffText,
		"FORGET": forgetOffText, "forget 3": forgetOffText, "Forget last": forgetOffText,
		"RENEW": renewOffText, "renew 2": renewOffText, "RENEW x": renewOffText,
	} {
		for _, unlocked := range []bool{true, false} {
			if got, ok := cfg.Settings(context.Background(), msg, unlocked); !ok || got != want {
				t.Fatalf("%s (unlocked %v): %q %v", msg, unlocked, got, ok)
			}
		}
	}
	for _, msg := range []string{"book a table", "forget the draft and write it again", "forget it", "renew my passport today"} {
		if _, ok := cfg.Settings(context.Background(), msg, true); ok {
			t.Fatalf("task chat %q taken as a setting", msg)
		}
	}
	if !cfg.Narrows("LOOPS OFF") || cfg.Narrows("FORGET") || cfg.Narrows("book a table") {
		t.Fatal("Narrows")
	}
	if cfg.HelpExtra != "" {
		t.Fatalf("HELP names a setting the box no longer has: %q", cfg.HelpExtra)
	}
	// One GSM-7 segment each.
	for _, l := range []string{loopsOffText, forgetOffText, renewOffText} {
		if utf8.RuneCountInString(l) > 153 || len(l) != utf8.RuneCountInString(l) {
			t.Fatalf("%q is not one plain segment", l)
		}
	}
}

// The old learning plane's state, FORGET's task texts and tombstones
// among it, is removed at start, since nothing can reach a task in it any
// more (CAP-3); the values key mail's UNDO derives from and the restored
// forget log the restore hold reads stay.
func TestOpenRemovesTheLearningState(t *testing.T) {
	dir := t.TempDir()
	for _, name := range learnedFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"text":"CANARY-learn-task"}`), 0o600); err != nil {
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
	kept := []string{"values.key", forgetLogFile}
	for _, name := range kept {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	openLearnState(dir, &daemon.Config{})
	for _, name := range learnedFiles {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", name, err)
		}
	}
	for _, name := range []string{"tasks.json", "forgotten.json", "forget-owed.json", "forget-owed.json.bad"} {
		found := false
		for _, l := range learnedFiles {
			found = found || l == name
		}
		if !found {
			t.Errorf("FORGET's %s is not erased", name)
		}
	}
	for _, name := range kept {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s removed: %v", name, err)
		}
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
// is removed at start, with the learning state, since nothing can reach a
// task in it (CAP-3; security 1 on #2801).
func TestOpenSweepsCrashLeftTemps(t *testing.T) {
	dir := t.TempDir()
	temp := filepath.Join(dir, learnTemp+"harvest.json-123")
	if err := os.WriteFile(temp, []byte(`{"goal":"CANARY-temp-task"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := daemon.Config{}
	openLearnState(dir, &cfg)
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatalf("crash-left temp kept: %v", err)
	}
	if got := statusNotes(&cfg); len(got) != 0 {
		t.Fatalf("STATUS notes %q", got)
	}
}

// LOG-4 (erase fails closed, owner told; security 3 on #2801): old learning
// state or a temp that does not remove is named in STATUS, and the next
// start tries again.
func TestEraseFailureIsToldInStatus(t *testing.T) {
	for _, which := range []string{"learned", "temp"} {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "tasks.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			fail := errors.New("read-only disk")
			if which == "learned" {
				removeAll = func(string) error { return fail }
			} else {
				sweepTemp = func(string) error { return fail }
			}
			cfg := daemon.Config{}
			openLearnState(dir, &cfg)
			sweepTemp, removeAll = sweepLearnTemp, os.RemoveAll
			if got := statusNotes(&cfg); len(got) != 1 || got[0] != forgetNotErased {
				t.Fatalf("STATUS notes %q", got)
			}
			// The next start tries again, and the line goes.
			cfg = daemon.Config{}
			openLearnState(dir, &cfg)
			if got := statusNotes(&cfg); len(got) != 0 {
				t.Fatalf("STATUS notes after the retry %q", got)
			}
			if _, err := os.Lstat(filepath.Join(dir, "tasks.json")); !os.IsNotExist(err) {
				t.Fatalf("retry left the state: %v", err)
			}
		})
	}
}

// KRN-forget b: the erase by name brings forgetting back, so the learning
// state adds no "not running" line; STATUS's forget lines are forget.go's.
func TestStatusNoLongerSaysForgetIsNotRunning(t *testing.T) {
	cfg := daemon.Config{}
	openLearnState(t.TempDir(), &cfg)
	if got := statusNotes(&cfg); len(got) != 0 {
		t.Fatalf("STATUS notes %q", got)
	}
}

// NL-8: intents left open for the deleted executors (change, loops,
// FORGET, recall's rollbacks, RENEW among them, and the page's follows,
// #3430) settle as not applied instead of failing for want of an
// executor; a follow intent never reaches the update store.
func TestDeletedExecutorsSettleNotApplied(t *testing.T) {
	cfg := daemon.Config{}
	registerRetired(&cfg)
	execs := []journal.Executor{cfg.Recall}
	for _, name := range []string{change.Executor, loops.Executor, grants.ForgetExecutor, grants.FollowExecutor} {
		execs = append(execs, cfg.BrokerExecutors[name])
	}
	for i, ex := range execs {
		if ex == nil {
			t.Fatalf("executor %d not registered", i)
		}
		if o := ex.Execute(context.Background(), journal.Intent{}, 1); o.Result != journal.ResultNotApplied {
			t.Fatalf("executor %d: %+v", i, o)
		}
	}
}

// main wires what this file's tests pin: STATUS's always-off recall line
// (OP-9; FD-3) and the retired executors (NL-8; FD-4), both before the
// daemon runs, which copies the notes and the executors (potency on
// #2827).
func TestMainWiresTheDeletedCapabilities(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	run := strings.Index(s, "daemon.Run(ctx, cfg)")
	for _, call := range []string{"caps.recallWired(false)", "registerRetired(&cfg)", "openLearnState(learnDir, &cfg)"} {
		if i := strings.Index(s, call); i < 0 || run < 0 || i > run {
			t.Errorf("main.go does not call %s before daemon.Run (%d, %d)", call, i, run)
		}
	}
}
