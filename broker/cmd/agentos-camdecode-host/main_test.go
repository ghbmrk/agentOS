package main

// REQ: CLK-1, RES-2

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	good := []string{"-runsc", "/r", "-runsc-root", "/tmp/runsc", "-decode-root", "/dr"}
	c, err := parse(good, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rt := runtime(c); !rt.Rootless || rt.Bin != "/r" || rt.StateDir != "/tmp/runsc" || rt.Platform != "systrap" {
		t.Fatalf("runtime %+v", rt)
	}
	for i := 0; i < len(good); i += 2 {
		bad := append(append([]string{}, good[:i]...), good[i+2:]...)
		if _, err := parse(bad, &bytes.Buffer{}); err == nil {
			t.Fatalf("parse without %s succeeded", good[i])
		}
	}
	if _, err := parse(append(good, "extra"), &bytes.Buffer{}); err == nil {
		t.Fatal("an extra argument was taken")
	}
	if _, err := parse([]string{"-runsc", "r", "-runsc-root", "/t", "-decode-root", "/d"}, &bytes.Buffer{}); err == nil {
		t.Fatal("a relative runsc was taken")
	}
	// The flag set's own complaint goes to the stderr it is given.
	var stderr bytes.Buffer
	if _, err := parse([]string{"-bogus"}, &stderr); err == nil || !strings.Contains(stderr.String(), "-bogus") {
		t.Fatalf("an unknown flag: %v, stderr %q", err, stderr.String())
	}
}

// TestRunJoinsItsLeafBeforeItServes: the process joins its leaf of its
// own unit's group before it reads the session, so one whose group it
// cannot read or join serves nothing (decodehost's tests join a leaf).
func TestRunJoinsItsLeafBeforeItServes(t *testing.T) {
	self := filepath.Join(t.TempDir(), "cgroup")
	os.WriteFile(self, []byte("0::/agentos-camdecode-test-none/x\n"), 0o600)
	args := []string{"-runsc", "/r", "-runsc-root", "/tmp/runsc", "-decode-root", "/dr"}
	if err := run(args, &bytes.Buffer{}, os.Stdin, self); err == nil || !strings.Contains(err.Error(), "agentos-camdecode-test-none") {
		t.Fatalf("a group that does not exist was joined: %v", err)
	}
	os.WriteFile(self, []byte("12:pids:/x\n"), 0o600)
	if err := run(args, &bytes.Buffer{}, os.Stdin, self); err == nil || !strings.Contains(err.Error(), "no cgroup v2 group") {
		t.Fatalf("served with no cgroup v2 group: %v", err)
	}
	if err := run([]string{"-runsc", "r"}, &bytes.Buffer{}, os.Stdin, self); err == nil || !strings.Contains(err.Error(), "are required") {
		t.Fatalf("a bad command line served: %v", err)
	}
}

type record struct{ errs, logs []string }

func (r *record) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *record) Logf(f string, a ...any)   { r.logs = append(r.logs, fmt.Sprintf(f, a...)) }

// TestRunHoldsOnlyDirectories (#4392): the session's /run check passes
// directories only. A socket fails it, and so does one in a directory the
// session can search but not list; a directory it can neither list nor
// search hides whatever it holds. Root lists every directory, so only a
// run as another user (CI's broker-race) tests the unsearchable case.
func TestRunHoldsOnlyDirectories(t *testing.T) {
	run := t.TempDir()
	os.MkdirAll(filepath.Join(run, "user"), 0o755)
	os.Mkdir(filepath.Join(run, "systemd"), 0o000)
	defer os.Chmod(filepath.Join(run, "systemd"), 0o755)
	r := &record{}
	runHolds(r, run)
	if len(r.errs) != 0 {
		t.Fatalf("directories only: %q", r.errs)
	}
	if !strings.Contains(strings.Join(r.logs, "\n"), "user drwxr-xr-x") {
		t.Fatalf("modes not logged: %q", r.logs)
	}
	hidden := filepath.Join(run, "hidden")
	os.Mkdir(hidden, 0o755)
	ln, err := net.Listen("unix", filepath.Join(hidden, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	os.Chmod(hidden, 0o311)
	defer os.Chmod(hidden, 0o755)
	r = &record{}
	runHolds(r, run)
	if len(r.errs) == 0 {
		t.Fatalf("a socket in a searchable directory passed: %q", r.logs)
	}
}
