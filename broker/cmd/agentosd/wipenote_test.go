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
	if got := "/var/lib/" + unitValue(t, text, "StateDirectory") + "/failed"; got != wipeFailed {
		t.Fatalf("the unit writes %s; STATUS reads %s", got, wipeFailed)
	}
	// systemd turns $$ into $ and splits the line as sh does.
	stop := strings.ReplaceAll(unitValue(t, text, "ExecStopPost"), "$$", "$")
	dir := t.TempDir()
	path := filepath.Join(dir, "failed")
	cfg := daemon.Config{}
	cfg.Notes = append(cfg.Notes, wipeNote(path))
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

// A record that cannot be checked is told, never hidden.
func TestUncheckableWipeRecordIsTold(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := wipeNote(filepath.Join(f, "failed"))(); got != wipeFailedLine {
		t.Fatalf("under a file: %q", got)
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
