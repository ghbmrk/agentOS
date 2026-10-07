package main

// REQ: UPD-2, UPD-8

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// UX-46-4 and PR1: `status` prints each role's version, signatures against
// threshold and expiry, lists staged roles still collecting signatures,
// and fails (for CI) while anything needs a maintainer.
func TestStatusCommand(t *testing.T) {
	d := t.TempDir()
	repo := filepath.Join(d, "repo")
	k := func(n string) string { return filepath.Join(d, n) }
	var out bytes.Buffer
	do := func(args ...string) error {
		out.Reset()
		return run(args, &out)
	}
	must := func(args ...string) {
		t.Helper()
		if err := do(args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out.String())
		}
	}
	for _, n := range []string{"r0", "r1", "t0", "t1", "snap", "ts"} {
		must("keygen", k(n))
	}
	must("init", "-repo", repo, "-root", k("r0.pub")+","+k("r1.pub"), "-targets", k("t0.pub")+","+k("t1.pub"),
		"-snapshot", k("snap.pub"), "-timestamp", k("ts.pub"))
	must("sign", "-repo", repo, "-role", "root", "-key", k("r0.key"))
	err := do("status", "-repo", repo)
	if err == nil || !strings.Contains(out.String(), "note: staged root v1: 1 of 2 signatures") ||
		!strings.Contains(out.String(), "WARNING: no published root") {
		t.Fatalf("unpublished repository: err %v\n%s", err, out.String())
	}
	must("sign", "-repo", repo, "-role", "root", "-key", k("r1.key"))
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t0.key"))
	must("sign", "-repo", repo, "-role", "targets", "-key", k("t1.key"))
	must("publish", "-repo", repo, "-snapshot-key", k("snap.key"), "-timestamp-key", k("ts.key"))
	must("status", "-repo", repo)
	for _, want := range []string{"root      v1  2 of 2 signatures  expires ", "targets   v1  2 of 2 signatures", "timestamp v1  1 of 1 signatures"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "WARNING") {
		t.Fatalf("fresh repository warned:\n%s", out.String())
	}
	if err := do("status"); err == nil {
		t.Fatal("status ran without -repo")
	}
}
