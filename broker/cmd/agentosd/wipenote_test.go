package main

// REQ: HW-8, OWN-17

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/daemon"
)

// wipeUnit is the shipped unit whose stop writes wipeFailed.
const wipeUnit = "../../../image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-keeper-wipe.service"

// unitValue is key's one value in the unit's text.
func unitValue(t *testing.T, text, key string) string {
	t.Helper()
	var vals []string
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			vals = append(vals, v)
		}
	}
	if len(vals) != 1 {
		t.Fatalf("%s: %q, want one", key, vals)
	}
	return vals[0]
}

// MOR-wipe-owner (#6094): the unit's own stop step, run with the results
// systemd hands it, drives STATUS. A failed wipe adds the line, and only a
// later successful one removes it.
func TestFailedWipeIsToldInStatus(t *testing.T) {
	b, err := os.ReadFile(wipeUnit)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if got := "/var/lib/" + unitValue(t, text, "StateDirectory") + "/failed"; got != wipeFailed[0] {
		t.Fatalf("the unit writes %s; STATUS reads %s", got, wipeFailed[0])
	}
	// systemd turns $$ into $ and splits the line as sh does.
	stop := strings.ReplaceAll(unitValue(t, text, "ExecStopPost"), "$$", "$")
	dir := t.TempDir()
	path := filepath.Join(dir, "failed")
	cfg := daemon.Config{}
	cfg.Notes = append(cfg.Notes, wipeNote([]string{path}))
	run := func(result, code, status string) {
		t.Helper()
		c := exec.Command("/bin/sh", "-c", stop)
		c.Env = []string{"STATE_DIRECTORY=" + dir, "SERVICE_RESULT=" + result, "EXIT_CODE=" + code, "EXIT_STATUS=" + status}
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", result, err, out)
		}
	}
	if got := statusNotes(&cfg); len(got) != 0 {
		t.Fatalf("before any shutdown: %q", got)
	}
	for _, failed := range [][3]string{{"exit-code", "exited", "1"}, {"timeout", "killed", "TERM"}, {"signal", "killed", "KILL"}} {
		run(failed[0], failed[1], failed[2])
		if got := statusNotes(&cfg); len(got) != 1 || got[0] != wipeFailedLine {
			t.Fatalf("after a %s wipe: %q", failed[0], got)
		}
		if b, _ := os.ReadFile(path); string(b) != strings.Join(failed[:], " ")+"\n" {
			t.Fatalf("record %q", b)
		}
		run("success", "exited", "0")
		if got := statusNotes(&cfg); len(got) != 0 {
			t.Fatalf("after a good wipe: %q", got)
		}
	}
	// A good wipe with no record leaves none.
	run("success", "exited", "0")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("record after a good wipe: %v", err)
	}
}

// morUnit is the shipped unit whose stop writes wipeFailed[1].
const morUnit = "../../../image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-mor.service"

// MOR-clear-owner (#6111): a refused MOR clear, or one that could not run,
// is told by the wipe's line, and a later good clear removes it; the wipe's
// record and the clear's are told alike, and the line stays while either
// is there. broker/cmd/agentos-mor's TestRefusalIsRecorded drives each
// refusal through the same step to the record read here.
func TestRefusedClearIsToldInStatus(t *testing.T) {
	b, err := os.ReadFile(morUnit)
	if err != nil {
		t.Fatal(err)
	}
	stop := strings.ReplaceAll(unitValue(t, string(b), "ExecStopPost"), "$$", "$")
	shipped := filepath.Dir(wipeFailed[1])
	if n := strings.Count(stop, wipeFailed[1]); n != 3 {
		t.Fatalf("the unit names %s %d times, want 3: %s", wipeFailed[1], n, stop)
	}
	if n := strings.Count(stop, shipped); n != 4 {
		t.Fatalf("the unit names %s %d times, want 4: %s", shipped, n, stop)
	}
	// The record's directory is made at the stop, never at the start.
	dir := filepath.Join(t.TempDir(), "agentos-mor")
	stop = strings.ReplaceAll(stop, shipped, dir)
	wipe := filepath.Join(t.TempDir(), "failed")
	cfg := daemon.Config{}
	cfg.Notes = append(cfg.Notes, wipeNote([]string{wipe, filepath.Join(dir, "refused")}))
	run := func(result, code, status string) {
		t.Helper()
		c := exec.Command("/bin/sh", "-c", stop)
		c.Env = []string{"SERVICE_RESULT=" + result, "EXIT_CODE=" + code, "EXIT_STATUS=" + status}
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", result, err, out)
		}
	}
	told := func(want bool) {
		t.Helper()
		got := statusNotes(&cfg)
		if want != (len(got) == 1 && got[0] == wipeFailedLine) || len(got) > 1 {
			t.Fatalf("lines %q, want told %v", got, want)
		}
	}
	run("success", "exited", "0")
	told(false)
	for _, failed := range [][3]string{{"exit-code", "exited", "1"}, {"timeout", "killed", "TERM"}, {"signal", "killed", "ABRT"}} {
		run(failed[0], failed[1], failed[2])
		told(true)
		if b, _ := os.ReadFile(filepath.Join(dir, "refused")); string(b) != strings.Join(failed[:], " ")+"\n" {
			t.Fatalf("record %q", b)
		}
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("record directory: %v %v", fi, err)
		}
		run("success", "exited", "0")
		told(false)
	}
	// Either record alone keeps the line.
	if err := os.WriteFile(wipe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	told(true)
	run("exit-code", "exited", "1")
	told(true)
	if err := os.Remove(wipe); err != nil {
		t.Fatal(err)
	}
	told(true)
	run("success", "exited", "0")
	told(false)
	// Both shipped records are read in agentosd (main.go).
	if len(wipeFailed) != 2 || wipeFailed[0] == wipeFailed[1] {
		t.Fatalf("records %q", wipeFailed)
	}
}

// A record that cannot be checked is told, never hidden.
func TestUncheckableWipeRecordIsTold(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{{filepath.Join(f, "failed")}, {filepath.Join(f, "absent"), filepath.Join(f, "refused")}} {
		if got := wipeNote(paths)(); got != wipeFailedLine {
			t.Fatalf("under a file %q: %q", paths, got)
		}
	}
}

func TestWipeLineIsOwnerWorded(t *testing.T) {
	if err := ownerWorded(wipeFailedLine); err != nil {
		t.Fatal(err)
	}
	// Without its full stop the line is refused: the check reads the
	// whole sentence, not only its head and fix.
	if ownerWorded(strings.TrimSuffix(wipeFailedLine, ".")) == nil {
		t.Fatal("a line with no full stop passed")
	}
}
