package main

// REQ: CLK-1, RES-2

import (
	"bytes"
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
	if err := run(args, &bytes.Buffer{}, os.Stdin, self); err == nil {
		t.Fatal("served with no cgroup v2 group")
	}
	if err := run([]string{"-runsc", "r"}, &bytes.Buffer{}, os.Stdin, self); err == nil {
		t.Fatal("a bad command line served")
	}
}
